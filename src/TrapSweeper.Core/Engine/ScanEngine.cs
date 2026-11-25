using System.Threading.Channels;
using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Models;
using TrapSweeper.Core.Quarantine;

namespace TrapSweeper.Core.Engine;

public sealed class ScanOptions
{
    public List<string> Roots { get; set; } = new();
    public string? CheckpointPath { get; set; }
    public int MaxDegreeOfParallelism { get; set; } = Math.Max(2, Environment.ProcessorCount - 1);
    public int ChannelCapacity { get; set; } = 2000;
    /// <summary>对扩展名不在清单内的文件也读取头部按 CLSID 嗅探（更慢，默认关闭）。</summary>
    public bool SniffAllFiles { get; set; }
    /// <summary>默认跳过 reparse point（挂载点/符号链接），防止循环与越界扫描。</summary>
    public bool FollowReparsePoints { get; set; }
    public long MaxFileSizeBytes { get; set; } = 8 * 1024 * 1024;
    /// <summary>断点记录的目录深度（相对每个根）。</summary>
    public int CheckpointDepth { get; set; } = 2;
    public QuarantineStore? Quarantine { get; set; }
    /// <summary>显式 --apply 才会真正隔离；否则只审计。</summary>
    public bool ApplyQuarantine { get; set; }
    public Action<ScanCounters>? ProgressCallback { get; set; }
    public TimeSpan ProgressInterval { get; set; } = TimeSpan.FromSeconds(5);
    public CancellationToken CancellationToken { get; set; }
}

/// <summary>枚举到的待处理文件（先不读内容，避免句柄堆积）。</summary>
internal sealed record WorkItem(string Path, FileTypeRegistry.FileTypeSpec Spec, DateTime LastWriteUtc, bool HiddenOrSystem);

/// <summary>
/// 千万级文件扫描管道：
/// 单线程递归枚举（IO 密集，线程多了只会加剧寻道）→ 有界 Channel → 多消费者读取/解析/判定 → 结果汇聚。
/// 断点按"相对根目录深度 N 的已完成目录"记录，重扫时跳过整棵子树。
/// </summary>
public sealed class ScanEngine
{
    private readonly DecoyAnalyzer _analyzer;
    private readonly ScanOptions _opts;
    private readonly ScanCounters _counters = new();
    private readonly CheckpointStore _checkpoint;
    private readonly object _checkpointLock = new();

    public ScanEngine(DecoyAnalyzer analyzer, ScanOptions opts)
    {
        _analyzer = analyzer;
        _opts = opts;
        _checkpoint = new CheckpointStore(opts.CheckpointPath, opts.CheckpointDepth);
    }

    public ScanReport Run()
    {
        var report = new ScanReport { StartedUtc = DateTime.UtcNow, Roots = _opts.Roots };
        var channel = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(_opts.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true
        });

        var cts = CancellationTokenSource.CreateLinkedTokenSource(_opts.CancellationToken);
        var token = cts.Token;

        var producer = Task.Run(() =>
        {
            try
            {
                foreach (var root in _opts.Roots)
                {
                    token.ThrowIfCancellationRequested();
                    Enumerate(root, root, depth: 0, channel.Writer, token);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException) { throw; }
            finally { channel.Writer.Complete(); }
        }, token);

        var consumers = Enumerable.Range(0, _opts.MaxDegreeOfParallelism)
            .Select(_ => Task.Run(() => ConsumeLoop(channel.Reader, token), token))
            .ToArray();

        var progress = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try { await Task.Delay(_opts.ProgressInterval, token); }
                catch { break; }
                _opts.ProgressCallback?.Invoke(_counters);
            }
        }, token);

        try
        {
            producer.GetAwaiter().GetResult();
            Task.WaitAll(consumers);
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException))
        {
            // Ctrl+C：保留已产出的结果与断点
        }
        catch (OperationCanceledException) { }
        finally
        {
            cts.Cancel();
            _checkpoint.Flush();
        }

        report.Counters = _counters;
        report.FinishedUtc = DateTime.UtcNow;
        return report;
    }

    private void Enumerate(string root, string dir, int depth, ChannelWriter<WorkItem> writer, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        if (depth >= _opts.CheckpointDepth && _checkpoint.IsComplete(root, dir))
            return;

        IEnumerable<string> files;
        IEnumerable<string> subDirs;
        try
        {
            // 不预取属性、不递归：手动控制递归以便容错和断点
            files = Directory.EnumerateFiles(dir);
            subDirs = Directory.EnumerateDirectories(dir);
        }
        catch (UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _counters.AccessDenied);
            return;
        }
        catch (DirectoryNotFoundException) { return; }
        catch (IOException) { return; }

        Interlocked.Increment(ref _counters.DirectoriesVisited);

        foreach (var file in files)
        {
            token.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _counters.FilesEnumerated);

            var name = Path.GetFileName(file);
            var spec = FileTypeRegistry.ByExtensionFirst(file);
            if (spec != null || (_opts.SniffAllFiles && ShouldSniff(name)))
            {
                if (TryBuildWorkItem(file, spec, out var item) && item != null)
                {
                    Interlocked.Increment(ref _counters.CandidatesOpened);
                    writer.WriteAsync(item, token).AsTask().GetAwaiter().GetResult();
                }
            }
        }

        foreach (var sub in subDirs)
        {
            if (!_opts.FollowReparsePoints && IsReparsePoint(sub)) continue;
            Enumerate(root, sub, depth + 1, writer, token);
        }

        if (depth >= _opts.CheckpointDepth)
        {
            lock (_checkpointLock) _checkpoint.MarkComplete(root, dir);
        }
    }

    private bool TryBuildWorkItem(string file, FileTypeRegistry.FileTypeSpec? spec, out WorkItem? item)
    {
        item = null;
        try
        {
            var info = new FileInfo(file);
            if (!info.Exists || info.Length > _opts.MaxFileSizeBytes) return false;

            var hidden = info.Attributes.HasFlag(FileAttributes.Hidden) || info.Attributes.HasFlag(FileAttributes.System);
            var effectiveSpec = spec;
            if (effectiveSpec == null)
            {
                // 嗅探路径：读头部判断是否为改后缀的 lnk/url。
                // ShellLink 头为 76 字节、CLSID 位于偏移 4..19，需读满 76 字节才能通过 IsLnkByHeader 的完整性检查
                try
                {
                    var head = new byte[76];
                    using var fs = File.OpenRead(file);
                    var read = fs.Read(head);
                    if (read >= 76 && Parsers.LnkParser.IsLnkByHeader(head))
                        effectiveSpec = FileTypeRegistry.ByExtensionFirst("x.lnk");
                    else
                        return false;
                }
                catch (UnauthorizedAccessException) { Interlocked.Increment(ref _counters.AccessDenied); return false; }
                catch (IOException) { return false; }
            }

            if (effectiveSpec == null) return false;
            // desktop.ini 按文件名精确识别，避免把业务 ini 全部打开
            if (effectiveSpec.Kind == DecoyKind.DesktopIni && !FileTypeRegistry.IsDesktopIni(file))
                return false;

            item = new WorkItem(file, effectiveSpec, info.LastWriteTimeUtc, hidden);
            return true;
        }
        catch (UnauthorizedAccessException) { Interlocked.Increment(ref _counters.AccessDenied); return false; }
        catch (IOException) { return false; }
    }

    private void ConsumeLoop(ChannelReader<WorkItem> reader, CancellationToken token)
    {
        var localFindings = new List<Finding>();
        while (reader.WaitToReadAsync(token).AsTask().GetAwaiter().GetResult())
        {
            while (reader.TryRead(out var item))
            {
                token.ThrowIfCancellationRequested();
                var finding = ProcessItem(item, token);
                if (finding != null)
                {
                    localFindings.Add(finding);
                    Interlocked.Increment(ref _counters.FindingsTotal);
                    if (finding.IsActionable) Interlocked.Increment(ref _counters.FindingsActionable);
                }
            }
            Drain(localFindings);
        }
        Drain(localFindings);
    }

    private Finding? ProcessItem(WorkItem item, CancellationToken token)
    {
        try
        {
            var bytes = File.ReadAllBytes(item.Path);
            var finding = _analyzer.Analyze(item.Path, item.Spec.Kind, bytes, item.LastWriteUtc, item.HiddenOrSystem);

            if (finding.Error != null) Interlocked.Increment(ref _counters.ParseErrors);

            if (finding.IsActionable && _opts.Quarantine != null && _opts.ApplyQuarantine)
            {
                var outcome = _opts.Quarantine.Quarantine(finding, token);
                if (outcome) Interlocked.Increment(ref _counters.Quarantined);
                else Interlocked.Increment(ref _counters.QuarantineFailures);
            }
            return finding;
        }
        catch (UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _counters.AccessDenied);
            return null;
        }
        catch (IOException) { return null; }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _counters.ParseErrors);
            return new Finding
            {
                FilePath = item.Path,
                Kind = item.Spec.Kind,
                Verdict = Verdict.Suspicious,
                Severity = Severity.Medium,
                Error = $"读取/分析失败: {ex.GetType().Name}: {ex.Message}",
                Reasons = new List<string> { "处理异常，按可疑级别上报以避免漏报" }
            };
        }
    }

    /// <summary>结果汇聚点：报告累积在引擎内部，通过事件交给上层写 JSONL/控制台，避免大对象锁竞争。</summary>
    public event Action<Finding>? FindingEmitted;

    private void Drain(List<Finding> local)
    {
        if (local.Count == 0 || FindingEmitted == null) { local.Clear(); return; }
        foreach (var f in local) FindingEmitted(f);
        local.Clear();
    }

    private static bool ShouldSniff(string name)
    {
        var ext = Path.GetExtension(name);
        // 极小概率含 lnk 头的常见伪装后缀；排除明显的大体积媒体/压缩格式
        return ext is ".dat" or ".tmp" or ".txt" or ".bin" or "";
    }

    private static bool IsReparsePoint(string path)
    {
        try { return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint); }
        catch { return true; } // 拿不到属性时按 reparse 处理，保守跳过
    }
}
