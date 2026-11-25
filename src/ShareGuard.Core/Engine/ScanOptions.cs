namespace ShareGuard.Core.Engine;

/// <summary>扫描参数。面向几千万文件的共享目录做了性能与可恢复性设计。</summary>
public sealed class ScanOptions
{
    /// <summary>扫描根目录(本地路径或 UNC 根),可多个。</summary>
    public required IReadOnlyList<string> Roots { get; init; }

    /// <summary>文件解析并行度。默认 = CPU 核数,网络共享建议 2~4 倍核数。</summary>
    public int Parallelism { get; init; } = Math.Max(2, Environment.ProcessorCount * 2);

    /// <summary>枚举与解析之间的有界队列容量,防止内存被待处理文件撑爆。</summary>
    public int QueueCapacity { get; init; } = 4096;

    /// <summary>单文件大小上限(字节),超过只登记不解析。</summary>
    public long MaxFileSize { get; init; } = 16 * 1024 * 1024;

    /// <summary>要排除的目录名(精确匹配,大小写不敏感),例如 DfsrPrivate、~snapshot。</summary>
    public HashSet<string> ExcludedDirectories { get; init; } =
        new(StringComparer.OrdinalIgnoreCase) { "dfsrprivate", "~snapshot", ".snapshot", "$recycle.bin", "system volume information" };

    /// <summary>不跟随重解析点(DFS junction 等),避免循环与越权枚举。</summary>
    public bool SkipReparsePoints { get; init; } = true;

    /// <summary>出错文件最多记录条数(防日志爆炸),之后只累加计数。</summary>
    public int MaxRecordedErrors { get; init; } = 1000;

    /// <summary>检查点文件路径;非空时周期性写入已完成目录,重启可续扫。</summary>
    public string? CheckpointPath { get; init; }

    /// <summary>每处理多少个文件落一次检查点。</summary>
    public int CheckpointInterval { get; init; } = 50_000;

    /// <summary>是否只返回可疑/高危结果(Benign 不进输出),默认 true 控制报告体量。</summary>
    public bool OnlyReportFindings { get; init; } = true;
}

/// <summary>扫描运行期统计,线程安全计数。</summary>
public sealed class ScanStats
{
    private long _directoriesVisited;
    private long _filesEnumerated;
    private long _candidateFiles;
    private long _filesAnalyzed;
    private long _parseErrors;
    private long _accessErrors;
    private long _benign;
    private long _suspicious;
    private long _malicious;

    public long DirectoriesVisited => Interlocked.Read(ref _directoriesVisited);
    public long FilesEnumerated => Interlocked.Read(ref _filesEnumerated);
    public long CandidateFiles => Interlocked.Read(ref _candidateFiles);
    public long FilesAnalyzed => Interlocked.Read(ref _filesAnalyzed);
    public long ParseErrors => Interlocked.Read(ref _parseErrors);
    public long AccessErrors => Interlocked.Read(ref _accessErrors);
    public long Benign => Interlocked.Read(ref _benign);
    public long Suspicious => Interlocked.Read(ref _suspicious);
    public long Malicious => Interlocked.Read(ref _malicious);

    internal void IncrementDirectories() => Interlocked.Increment(ref _directoriesVisited);
    internal void IncrementEnumerated() => Interlocked.Increment(ref _filesEnumerated);
    internal void IncrementCandidates() => Interlocked.Increment(ref _candidateFiles);
    internal void IncrementAnalyzed() => Interlocked.Increment(ref _filesAnalyzed);
    internal void IncrementParseErrors() => Interlocked.Increment(ref _parseErrors);
    internal void IncrementAccessErrors() => Interlocked.Increment(ref _accessErrors);
    internal void RecordSeverity(Models.Severity severity)
    {
        switch (severity)
        {
            case Models.Severity.Benign: Interlocked.Increment(ref _benign); break;
            case Models.Severity.Suspicious: Interlocked.Increment(ref _suspicious); break;
            case Models.Severity.Malicious: Interlocked.Increment(ref _malicious); break;
        }
    }
}
