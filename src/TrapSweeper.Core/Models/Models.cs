using System.Text.Json.Serialization;

namespace TrapSweeper.Core.Models;

/// <summary>诱饵文件类别，覆盖 Windows 外壳强制认证的主要载体。</summary>
public enum DecoyKind
{
    Lnk,
    DesktopIni,
    UrlFile,
    ScfFile,
    SearchConnector,
    SearchMs,
    LibraryMs,
    SettingContentMs,
    OtherShellXml
}

/// <summary>单条引用的判定结论。</summary>
public enum Verdict
{
    /// <summary>命中允许列表，属于合法内部引用。</summary>
    Allowed,
    /// <summary>明确指向外部地址（公网 IP / 外部后缀 / http 外域）。</summary>
    External,
    /// <summary>可疑：无法被任何允许规则解释，且带有可疑信号。</summary>
    Suspicious,
    /// <summary>引用无法解析（主机名不存在等，仅在启用 DNS 校验时出现）。</summary>
    Unresolvable
}

public enum Severity { Info, Low, Medium, High, Critical }

/// <summary>从诱饵文件中解析出的一条网络/路径引用。</summary>
public sealed class HostReference
{
    /// <summary>原始字符串（如 IconLocation 的值）。</summary>
    public string Raw { get; set; } = string.Empty;

    /// <summary>引用角色：Target / IconLocation / Arguments / WorkingDirectory / URL / iconResource 等。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>unc / file / http / https / webdav。</summary>
    public string? Scheme { get; set; }

    public string? Host { get; set; }
    public int? Port { get; set; }
    public string? Share { get; set; }
    public string? Path { get; set; }

    public bool IsIpLiteral { get; set; }
    public bool IsObfuscatedIp { get; set; }
    public bool HasEmbeddedCredentials { get; set; }

    /// <summary>来源编码：utf16 / ansi / ascii。</summary>
    public string Encoding { get; set; } = "ascii";

    public override string ToString() => $"{Role}: {Raw}";
}

/// <summary>单个主机的分类明细，用于报告解释“为什么报/不报”。</summary>
public sealed class HostVerdict
{
    public string Host { get; set; } = string.Empty;
    public Verdict Verdict { get; set; }
    public Severity Severity { get; set; }
    public int Score { get; set; }
    public List<string> Signals { get; set; } = new();
    public List<string> MatchedAllowRules { get; set; } = new();

    [JsonIgnore]
    public bool IsBad => Verdict is Verdict.External or Verdict.Suspicious or Verdict.Unresolvable;
}

/// <summary>一个诱饵文件的完整扫描结论。</summary>
public sealed class Finding
{
    public string FilePath { get; set; } = string.Empty;
    public DecoyKind Kind { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
    public bool IsHiddenOrSystem { get; set; }
    public bool ParseTruncated { get; set; }

    public List<HostReference> References { get; set; } = new();
    public List<HostVerdict> HostVerdicts { get; set; } = new();
    public List<string> Reasons { get; set; } = new();

    public Verdict Verdict { get; set; }
    public Severity Severity { get; set; }
    public int Score { get; set; }

    /// <summary>解析失败时记录错误信息（文件仍会以可疑级别上报，避免静默漏报）。</summary>
    public string? Error { get; set; }

    [JsonIgnore]
    public bool IsActionable => Verdict is Verdict.External or Verdict.Suspicious or Verdict.Unresolvable;
}

/// <summary>一次扫描任务的汇总统计。</summary>
public sealed class ScanCounters
{
    public long FilesEnumerated;
    public long DirectoriesVisited;
    public long CandidatesOpened;
    public long FindingsTotal;
    public long FindingsActionable;
    public long ParseErrors;
    public long AccessDenied;
    public long Quarantined;
    public long QuarantineFailures;
}

public sealed class ScanReport
{
    public string ToolVersion { get; set; } = string.Empty;
    public DateTime StartedUtc { get; set; }
    public DateTime FinishedUtc { get; set; }
    public List<string> Roots { get; set; } = new();
    public string ConfigPath { get; set; } = string.Empty;
    public ScanCounters Counters { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
}
