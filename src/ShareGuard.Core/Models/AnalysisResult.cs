namespace ShareGuard.Core.Models;

/// <summary>
/// 引用主机的判定结果。分级依据是"自动认证外发"的可达性,
/// 而不是文件本身是否为恶意软件——诱饵文件本身可以完全合法。
/// </summary>
public enum HostVerdict
{
    /// <summary>白名单内的内部主机(域控、文件服务器、批准的 DFS 命名空间等)。</summary>
    AllowedInternal,

    /// <summary>公网 IP / 公网域名:浏览目录即可能向互联网发起 NTLM/认证,高危。</summary>
    External,

    /// <summary>IP 字面量但不在内部网段白名单内(含公网 IP、陌生内网段)。</summary>
    UnknownIp,

    /// <summary>单标签主机名,无法确认归属;可能被 LLMNR/NBT-NS 投毒响应。</summary>
    SingleLabel,

    /// <summary>主机名后缀不在企业 DNS 后缀白名单内。</summary>
    UntrustedSuffix,

    /// <summary>引用指向本机(127.0.0.1 / localhost / ::1),通常无害,保留审计。</summary>
    Loopback,

    /// <summary>多播/链路本地地址(224.0.0.0/4、169.254/16、fe80::/10 等)。</summary>
    LinkLocal,

    /// <summary>无法解析出主机的本地引用。</summary>
    NoHost,
}

/// <summary>文件级处置建议,取该文件全部引用中的最高风险。</summary>
public enum Severity
{
    /// <summary>全部引用均为内部白名单主机或本地路径。</summary>
    Benign = 0,

    /// <summary>可疑:单标签名、未知内网 IP、显式凭据、非标准端口等,需要人工复核。</summary>
    Suspicious = 1,

    /// <summary>高危:明确指向外部 / 非信任地址,满足强制认证诱饵特征。</summary>
    Malicious = 2,
}

/// <summary>
/// 一次文件分析的完整结论。
/// </summary>
public sealed class AnalysisResult
{
    public required string FilePath { get; init; }
    public BaitFileType FileType { get; init; }
    public required IReadOnlyList<EmbeddedReference> References { get; init; }
    public required IReadOnlyList<HostVerdict> Verdicts { get; init; }
    public Severity Severity { get; init; }

    /// <summary>触发判定的可读理由,供报告与审计使用。</summary>
    public required IReadOnlyList<string> Reasons { get; init; }

    /// <summary>解析失败但文件扩展名可疑时置位(扫描器仍可据此要求人工查看)。</summary>
    public bool ParseError { get; init; }

    /// <summary>文件大小(字节),用于报告。</summary>
    public long FileSize { get; init; }

    /// <summary>最后写入时间(UTC)。</summary>
    public DateTime LastWriteTimeUtc { get; init; }

    public bool HasExternal => Verdicts.Any(v => v is HostVerdict.External
        or HostVerdict.UnknownIp or HostVerdict.UntrustedSuffix);
}
