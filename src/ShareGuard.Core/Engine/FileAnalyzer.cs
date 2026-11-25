using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;

namespace ShareGuard.Core.Engine;

/// <summary>
/// 单文件分析管线:解析引用 → 逐引用主机分级 → 汇总文件级结论。
/// 无状态、线程安全,可被扫描引擎并行调用。
/// </summary>
public sealed class FileAnalyzer
{
    private readonly ParserRegistry _parsers;
    private readonly HostClassifier _classifier;
    private readonly long _maxFileSize;

    public FileAnalyzer(ParserRegistry parsers, HostClassifier classifier, long maxFileSize = 16 * 1024 * 1024)
    {
        _parsers = parsers;
        _classifier = classifier;
        _maxFileSize = maxFileSize;
    }

    public AnalysisResult Analyze(string filePath, string? overrideFileName = null)
    {
        var fileName = overrideFileName ?? Path.GetFileName(filePath);
        var parser = _parsers.Resolve(fileName)
            ?? throw new InvalidOperationException($"无解析器可处理 {fileName}");

        var info = new FileInfo(filePath);
        IReadOnlyList<EmbeddedReference> references = Array.Empty<EmbeddedReference>();
        var parseError = false;
        var reasons = new List<string>();

        byte[] content;
        try
        {
            if (info.Length > _maxFileSize)
            {
                // 诱饵文件都很小;超限按可疑处理而非整块读入,保护扫描内存
                return new AnalysisResult
                {
                    FilePath = filePath,
                    FileType = parser.FileType,
                    References = references,
                    Verdicts = Array.Empty<HostVerdict>(),
                    Severity = Severity.Suspicious,
                    Reasons = [$"文件大小 {info.Length} 字节超过上限 {_maxFileSize},跳过内容解析"],
                    ParseError = true,
                    FileSize = info.Length,
                    LastWriteTimeUtc = info.LastWriteTimeUtc,
                };
            }
            content = ReadAllBytesShared(filePath);
        }
        catch (IOException ex)
        {
            return new AnalysisResult
            {
                FilePath = filePath,
                FileType = parser.FileType,
                References = references,
                Verdicts = Array.Empty<HostVerdict>(),
                Severity = Severity.Suspicious,
                Reasons = [$"读取失败(文件被占用或权限不足):{ex.Message}"],
                ParseError = true,
                FileSize = SafeSize(info),
                LastWriteTimeUtc = SafeTime(info),
            };
        }

        try
        {
            references = parser.Parse(filePath, content);
        }
        catch (BaitParseException ex)
        {
            parseError = true;
            reasons.Add($"结构解析失败:{ex.Message}(已尝试字符串兜底)");
            // LNK 解析失败时仍执行一次裸扫描,尽量不遗漏
            if (parser.FileType == BaitFileType.Lnk)
            {
                var sweep = new List<EmbeddedReference>();
                StringSweeper.Sweep(content, sweep);
                references = sweep;
            }
        }

        var verdictList = new List<HostVerdict>(references.Count);
        var severity = Severity.Benign;

        foreach (var reference in references)
        {
            var verdict = _classifier.Classify(reference, out var reason);
            verdictList.Add(verdict);
            reasons.Add($"{reference.SourceField}: {reference.Raw} → {verdict}({reason})");

            severity = Aggravate(severity, VerdictSeverity(verdict));

            foreach (var agg in _classifier.GetAggravators(reference))
            {
                reasons.Add(agg);
                if (verdict != HostVerdict.AllowedInternal)
                    severity = Aggravate(severity, Severity.Suspicious);
            }
        }

        if (parseError && severity == Severity.Benign)
            severity = Severity.Suspicious;

        return new AnalysisResult
        {
            FilePath = filePath,
            FileType = parser.FileType,
            References = references,
            Verdicts = verdictList,
            Severity = severity,
            Reasons = reasons,
            ParseError = parseError,
            FileSize = info.Length,
            LastWriteTimeUtc = info.LastWriteTimeUtc,
        };
    }

    /// <summary>外部/非信任后缀/未知 IP 直接 Malicious;单标签名只到 Suspicious。</summary>
    private static Severity VerdictSeverity(HostVerdict verdict) => verdict switch
    {
        HostVerdict.External => Severity.Malicious,
        HostVerdict.UnknownIp => Severity.Malicious,
        HostVerdict.UntrustedSuffix => Severity.Malicious,
        HostVerdict.SingleLabel => Severity.Suspicious,
        HostVerdict.LinkLocal => Severity.Suspicious,
        HostVerdict.Loopback => Severity.Benign,
        HostVerdict.AllowedInternal => Severity.Benign,
        _ => Severity.Benign,
    };

    private static Severity Aggravate(Severity current, Severity incoming)
        => (Severity)Math.Max((int)current, (int)incoming);

    internal static byte[] ReadAllBytesShared(string path)
    {
        // FileShare.ReadWrite:共享目录上的文件可能正被其他人打开
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite
            | FileShare.Delete);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }

    private static long SafeSize(FileInfo info) { try { return info.Length; } catch { return -1; } }
    private static DateTime SafeTime(FileInfo info) { try { return info.LastWriteTimeUtc; } catch { return DateTime.MinValue; } }
}
