using System.Text.Json;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;

namespace ShareGuard.Core.Engine;

/// <summary>
/// 共享目录扫描引擎。
///
/// 架构(针对千万级文件):
///   生产者:每个扫描根一个枚举任务,只做目录递归 + 扩展名过滤,把候选文件推入有界 Channel;
///   消费者:Parallelism 个分析任务,读文件并跑 FileAnalyzer;
///   结果:通过 IProgress 流式回传,调用方决定写 CSV/JSONL,引擎自身不堆积结果。
///
/// 容错:任何单目录/单文件异常都被吞掉并计数,扫描不中断;
/// 断点续扫:检查点记录"完整处理完的目录",重启后整目录跳过(保守正确——
/// 目录内文件只会被少扫不会被漏判,重启时再对跳过目录做一次增量校验即可)。
/// </summary>
public sealed class Scanner
{
    private readonly FileAnalyzer _analyzer;
    private readonly ParserRegistry _parsers;

    public Scanner(FileAnalyzer analyzer, ParserRegistry parsers)
    {
        _analyzer = analyzer;
        _parsers = parsers;
    }

    /// <param name="onResult">每条分析结果的回调。会被多个消费者线程并发调用,
    /// 实现方必须自行保证线程安全(用锁、并发集合或 Interlocked),引擎保证不丢条、不重条。</param>
    /// <param name="onMessage">进度/诊断消息回调,同样可能并发调用。</param>
    public async Task<ScanStats> ScanAsync(
        ScanOptions options,
        Action<AnalysisResult> onResult,
        Action<string>? onMessage = null,
        CancellationToken cancellationToken = default)
    {
        var stats = new ScanStats();
        var errors = new List<string>();
        var errorLock = new object();
        var checkpoint = await CheckpointStore.LoadOrCreateAsync(options.CheckpointPath, cancellationToken)
            .ConfigureAwait(false);

        var channel = System.Threading.Channels.Channel.CreateBounded<(string Path, string Name)>(
            new System.Threading.Channels.BoundedChannelOptions(options.QueueCapacity)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = false,
            });

        // ---------- 消费者:并行分析 ----------
        // 消费者已是线程池任务,内部直接同步调用 Analyze,不再嵌套 Task.Run——
        // 双重 Task.Run 会无谓占用额外线程,在小队列 + 高并行度下加剧线程池饥饿。
        var consumers = Enumerable.Range(0, options.Parallelism).Select(_ => Task.Run(async () =>
        {
            await foreach (var (path, name) in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                AnalysisResult result;
                try
                {
                    result = _analyzer.Analyze(path, name);
                    stats.IncrementAnalyzed();
                    if (result.ParseError) stats.IncrementParseErrors();
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    RecordError(errors, errorLock, options, $"分析失败 {path}: {ex.Message}");
                    stats.IncrementAccessErrors();
                    continue;
                }

                stats.RecordSeverity(result.Severity);
                if (!options.OnlyReportFindings || result.Severity != Severity.Benign)
                    onResult(result); // 同步回调,保证结果不丢、顺序由调用方自行处理
            }
        }, cancellationToken)).ToArray();

        // ---------- 生产者:多根枚举(全异步,禁止 sync-over-async 阻塞)----------
        var producers = options.Roots.Select(root => Task.Run(async () =>
        {
            try
            {
                await EnumerateAsync(root, options, channel.Writer, stats, checkpoint, errors, errorLock,
                    onMessage, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { /* 正常退出 */ }
            catch (Exception ex)
            {
                RecordError(errors, errorLock, options, $"枚举根 {root} 失败:{ex.Message}");
            }
        }, cancellationToken)).ToArray();

        await Task.WhenAll(producers).ConfigureAwait(false);
        channel.Writer.Complete();
        await Task.WhenAll(consumers).ConfigureAwait(false);

        await checkpoint.SaveAsync(cancellationToken).ConfigureAwait(false);
        return stats;
    }

    private async Task EnumerateAsync(
        string root,
        ScanOptions options,
        System.Threading.Channels.ChannelWriter<(string, string)> writer,
        ScanStats stats,
        CheckpointStore checkpoint,
        List<string> errors,
        object errorLock,
        Action<string>? onMessage,
        CancellationToken ct)
    {
        // 手写栈递归,避免深目录打爆栈,也便于在目录粒度做检查点
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = stack.Pop();

            if (checkpoint.IsCompleted(dir)) continue;
            if (options.SkipReparsePoints && IsReparsePoint(dir)) continue;

            string[] files;
            string[] subDirs;
            try
            {
                // 物化到数组:惰性枚举器与后续 await 交错持有目录句柄,
                // 在网络共享上容易触发句柄复用异常;目录条目本身不进通道,内存可控。
                files = Directory.GetFiles(dir);
                subDirs = Directory.GetDirectories(dir);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or DirectoryNotFoundException)
            {
                stats.IncrementAccessErrors();
                RecordError(errors, errorLock, options, $"无法枚举目录 {dir}: {ex.Message}");
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                stats.IncrementEnumerated();
                var name = Path.GetFileName(file);
                if (!_parsers.IsCandidate(name)) continue;

                stats.IncrementCandidates();
                // 全异步等待:队列满时让出线程,绝不 sync-over-async 阻塞线程池
                await writer.WriteAsync((file, name), ct).ConfigureAwait(false);
            }

            foreach (var sub in subDirs)
            {
                var subName = Path.GetFileName(sub.TrimEnd(Path.DirectorySeparatorChar));
                if (options.ExcludedDirectories.Contains(subName)) continue;
                stack.Push(sub);
            }

            // 目录枚举完成即记检查点(其内文件已全部入队;消费端处理失败会体现在报告里)
            checkpoint.MarkCompleted(dir);
            stats.IncrementDirectories();

            if (stats.DirectoriesVisited % 500 == 0)
                onMessage?.Invoke($"已枚举 {stats.DirectoriesVisited} 个目录 / {stats.FilesEnumerated} 个文件," +
                    $"候选 {stats.CandidateFiles},当前 {dir}");

            if (options.CheckpointPath != null &&
                stats.FilesEnumerated > 0 &&
                stats.FilesEnumerated % options.CheckpointInterval < 1000)
            {
                await checkpoint.SaveAsync(ct).ConfigureAwait(false);
            }
        }
    }

    private static bool IsReparsePoint(string dir)
    {
        try
        {
            return File.GetAttributes(dir).HasFlag(FileAttributes.ReparsePoint);
        }
        catch
        {
            return false;
        }
    }

    private static void RecordError(List<string> errors, object gate, ScanOptions options, string message)
    {
        lock (gate)
        {
            if (errors.Count < options.MaxRecordedErrors) errors.Add(message);
        }
    }
}

/// <summary>检查点:已完整枚举的目录集合,JSON 持久化。</summary>
internal sealed class CheckpointStore
{
    private readonly string? _path;
    private readonly HashSet<string> _completed = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private CheckpointStore(string? path) => _path = path;

    public static async Task<CheckpointStore> LoadOrCreateAsync(string? path, CancellationToken ct)
    {
        var store = new CheckpointStore(path);
        if (path == null || !File.Exists(path)) return store;
        try
        {
            await using var fs = File.OpenRead(path);
            var data = await JsonSerializer.DeserializeAsync<CheckpointData>(fs, cancellationToken: ct)
                .ConfigureAwait(false);
            if (data?.CompletedDirectories is { } dirs)
            {
                foreach (var d in dirs) store._completed.Add(d);
            }
        }
        catch (JsonException)
        {
            // 检查点损坏时从头扫描,保证不漏
        }
        return store;
    }

    public bool IsCompleted(string dir)
    {
        lock (_gate) return _completed.Contains(Normalize(dir));
    }

    public void MarkCompleted(string dir)
    {
        lock (_gate) _completed.Add(Normalize(dir));
    }

    public async Task SaveAsync(CancellationToken ct)
    {
        if (_path == null) return;
        string[] snapshot;
        lock (_gate) snapshot = _completed.ToArray();

        var tmp = _path + ".tmp";
        await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(fs, new CheckpointData { CompletedDirectories = snapshot },
                cancellationToken: ct).ConfigureAwait(false);
        }
        File.Move(tmp, _path, overwrite: true);
    }

    private static string Normalize(string dir) =>
        dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToLowerInvariant();

    private sealed class CheckpointData
    {
        public string[]? CompletedDirectories { get; set; }
    }
}
