namespace ShareGuard.Core.Classification;

/// <summary>
/// 企业环境白名单配置。JSON 格式,由安全团队结合 AD 站点、DFS 命名空间与资产台账维护。
/// 设计原则:默认保守——不在白名单内的外部引用一律判 Suspicious 起步,
/// 但内部网段内的陌生单标签名只给 Suspicious 而非 Malicious,避免误伤新上线服务器。
/// </summary>
public sealed class AllowListConfig
{
    /// <summary>企业 DNS 后缀,例如 ["corp.example.com", "emea.corp.example.com"]。
    /// 主机名等于此后缀或以此后缀结尾(含前导点)即视为内部。</summary>
    public List<string> AllowedSuffixes { get; set; } = new();

    /// <summary>显式批准的主机名(DFS 根、文件服务器群集名等),大小写不敏感。</summary>
    public List<string> AllowedHosts { get; set; } = new();

    /// <summary>内部 IPv4/IPv6 网段(CIDR),例如 ["10.0.0.0/8", "fd00::/8"]。</summary>
    public List<string> AllowedCidrs { get; set; } = new();

    /// <summary>显式批准的单标签名(传统 NetBIOS 服务器、NAS 别名)。</summary>
    public List<string> AllowedSingleLabelNames { get; set; } = new();

    /// <summary>
    /// 允许出现的非默认端口。正常文件服务器引用几乎不带端口;
    /// 列表外的带端口 URL 会被加重判罚。
    /// </summary>
    public List<int> AllowedPorts { get; set; } = new() { 445, 139, 80, 443, 5985, 5986 };

    /// <summary>判定为"外部"后仍只给 Suspicious 而非 Malicious 的主机后缀(并购过渡期等场景)。</summary>
    public List<string> PendingReviewSuffixes { get; set; } = new();

    public static AllowListConfig Default => new()
    {
        AllowedCidrs =
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",   // 链路本地,默认归内网观察
            "127.0.0.0/8",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ],
    };
}
