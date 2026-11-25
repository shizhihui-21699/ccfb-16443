using System.Text;
using System.Text.Json;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Reporting;

/// <summary>JSONL 流式写入器：千万级结果不进内存，边扫边落盘。</summary>
public sealed class JsonlFindingWriter : IDisposable
{
    private readonly StreamWriter _writer;
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = false };

    public JsonlFindingWriter(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _writer = new StreamWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };
    }

    public void Write(Finding finding)
    {
        lock (_writer)
        {
            _writer.WriteLine(JsonSerializer.Serialize(finding, Opts));
        }
    }

    public void Dispose() => _writer.Dispose();
}

/// <summary>learn 模式的主机盘点：按主机聚合计数与角色，输出 CSV 供管理员编制允许列表。</summary>
public sealed class HostInventory
{
    public sealed class Row
    {
        public string Host { get; init; } = string.Empty;
        /// <summary>引用该主机的引用条目数（同一文件多个字段分别计数）。</summary>
        public int ReferenceCount { get; set; }
        /// <summary>引用该主机的去重文件数。</summary>
        public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int FileCount => Files.Count;
        public HashSet<string> Roles { get; } = new();
        public HashSet<string> Schemes { get; } = new();
        public bool IsIpLiteral { get; set; }
        public bool HasSuspiciousSignals { get; set; }
        public string SampleFile { get; set; } = string.Empty;
    }

    private readonly Dictionary<string, Row> _rows = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>线程安全：扫描管道的多个消费者会并发调用。</summary>
    public void Add(Finding finding)
    {
        lock (_lock)
        {
            foreach (var r in finding.References)
            {
                if (string.IsNullOrEmpty(r.Host)) continue;
                if (!_rows.TryGetValue(r.Host, out var row))
                {
                    row = new Row { Host = r.Host, SampleFile = finding.FilePath };
                    _rows[r.Host] = row;
                }
                row.ReferenceCount++;
                row.Files.Add(finding.FilePath);
                row.Roles.Add(r.Role);
                if (r.Scheme != null) row.Schemes.Add(r.Scheme);
                row.IsIpLiteral |= r.IsIpLiteral;
                row.HasSuspiciousSignals |= r.IsObfuscatedIp || r.HasEmbeddedCredentials;
            }
        }
    }

    public IReadOnlyCollection<Row> Rows => _rows.Values;

    public void WriteCsv(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var sb = new StringBuilder();
        sb.AppendLine("host,file_count,reference_count,is_ip_literal,has_suspicious_signals,schemes,roles,sample_file");
        foreach (var row in _rows.Values.OrderByDescending(r => r.FileCount).ThenByDescending(r => r.ReferenceCount))
        {
            sb.AppendJoin(',',
                Csv(row.Host), row.FileCount, row.ReferenceCount, row.IsIpLiteral, row.HasSuspiciousSignals,
                Csv(string.Join(';', row.Schemes)), Csv(string.Join(';', row.Roles)), Csv(row.SampleFile));
            sb.AppendLine();
        }
        File.WriteAllText(path, sb.ToString());
    }

    private static string Csv(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }
}
