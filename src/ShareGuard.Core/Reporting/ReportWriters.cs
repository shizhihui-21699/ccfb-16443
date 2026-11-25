using System.Text;
using System.Text.Json;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Reporting;

/// <summary>
/// JSONL 结果写入器:每行一个 AnalysisResult,适合 SIEM 摄入与 jq 后处理。
/// 同步 + 锁:扫描引擎的并行消费者会多线程调用,且 IProgress 回调不保证在
/// 扫描完成前排空,异步 fire-and-forget 会丢数据。
/// </summary>
public sealed class JsonlReportWriter : IDisposable
{
    private readonly StreamWriter _writer;
    private readonly object _gate = new();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public JsonlReportWriter(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
    }

    public void Write(AnalysisResult result)
    {
        var line = JsonSerializer.Serialize(result, JsonOptions);
        lock (_gate) _writer.WriteLine(line);
    }

    public void Dispose()
    {
        lock (_gate) _writer.Dispose();
    }
}

/// <summary>CSV 写入器,供安全运营在表格软件中复核;含 RFC 4180 转义。</summary>
public sealed class CsvReportWriter : IDisposable
{
    private readonly StreamWriter _writer;
    private readonly object _gate = new();
    private bool _headerWritten;

    public CsvReportWriter(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(true)) { AutoFlush = true };
    }

    public void Write(AnalysisResult result)
    {
        lock (_gate)
        {
            if (!_headerWritten)
            {
                _writer.WriteLine(
                    "Severity,FileType,FilePath,Hosts,ReferenceCount,ParseError,FileSize,LastWriteTimeUtc,Reasons");
                _headerWritten = true;
            }

            var hosts = string.Join(";", result.References.Where(r => r.Host != null)
                .Select(r => r.Host!).Distinct());
            var reasons = string.Join(" | ", result.Reasons);
            var line = string.Join(",",
                result.Severity,
                result.FileType,
                Escape(result.FilePath),
                Escape(hosts),
                result.References.Count,
                result.ParseError,
                result.FileSize,
                result.LastWriteTimeUtc.ToString("O"),
                Escape(reasons));
            _writer.WriteLine(line);
        }
    }

    private static string Escape(string value)
    {
        if (value.IndexOfAny([',', '"', '\n', '\r']) < 0) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    public void Dispose()
    {
        lock (_gate) _writer.Dispose();
    }
}
