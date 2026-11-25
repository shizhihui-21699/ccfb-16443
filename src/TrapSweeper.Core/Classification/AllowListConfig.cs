using System.Text.Json;
using System.Text.Json.Serialization;

namespace TrapSweeper.Core.Classification;

/// <summary>
/// 允许列表配置。判定流程是"先证据后结论"：只有能被规则解释的内部引用才放行，
/// 无法解释的引用进入可疑/外部结论并保留全部信号，供分析师复核。
/// 由 <c>learn</c> 命令输出的主机清单可辅助人工补齐本配置。
/// </summary>
public sealed class AllowListConfig
{
    /// <summary>可信 DNS 后缀，如 corp.local、branch.corp.local。子域自动命中（a.b.corp.local 命中 corp.local）。</summary>
    public List<string> AllowedSuffixes { get; set; } = new();

    /// <summary>精确主机名（不区分大小写），用于无后缀的 NetBIOS 名/短名白名单。</summary>
    public List<string> AllowedHosts { get; set; } = new();

    /// <summary>主机名正则白名单（如 ^fs-\d+\.corp\.local$），编译失败会在加载时报错而不是静默跳过。</summary>
    public List<string> AllowedHostRegex { get; set; } = new();

    /// <summary>可信 IPv4/IPv6 网段，如 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、fc00::/7。</summary>
    public List<string> AllowedCidrs { get; set; } = new();

    /// <summary>DFS 根与命名空间主机，通常承载 \\domain\Sysvol 等跨站点路径。</summary>
    public List<string> AllowedDfsRoots { get; set; } = new();

    /// <summary>
    /// 单标签主机（如 \\fileserver\share）策略：Allow（内网普遍使用短名时）、
    /// RequireAllow（必须在 AllowedHosts 中显式列出，最稳妥，默认）、Deny。
    /// </summary>
    public string SingleLabelPolicy { get; set; } = "RequireAllow";

    /// <summary>仅放行这些端口上的引用；为空表示不限制端口。SMB 445/139、WebDAV 80/443 默认在内。</summary>
    public List<int> TrustedPorts { get; set; } = new() { 80, 139, 443, 445, 5985, 5986 };

    /// <summary>允许明文 http 引用（默认仅允许 https 与 SMB）。</summary>
    public bool AllowCleartextHttp { get; set; }

    /// <summary>启用 DNS 解析校验：主机无法解析时标记 Unresolvable（需联网，离线扫描请关闭）。</summary>
    public bool EnableDnsCheck { get; set; }

    /// <summary>
    /// 企业内部使用的非标准公共后缀（默认空）。命中后缀视为内部主机，
    /// 例如收购的子公司域 acme-holdings.io 可写入此处，避免被按"公共后缀 + 外部域"处理。
    /// </summary>
    public List<string> InternalPublicSuffixes { get; set; } = new();

    /// <summary>内部反向代理/网关主机：经其 80/443 提供 WebDAV，允许 http(s) 形式的内部引用。</summary>
    public List<string> WebDavGateways { get; set; } = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static AllowListConfig Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"允许列表配置不存在: {path}");
        var json = File.ReadAllText(path);
        var cfg = JsonSerializer.Deserialize<AllowListConfig>(json, JsonOpts)
                  ?? throw new InvalidDataException("允许列表配置反序列化结果为空");
        cfg.Validate();
        return cfg;
    }

    public void Save(string path)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        }));
    }

    public void Validate()
    {
        AllowedSuffixes = AllowedSuffixes.ConvertAll(x => x.Trim().TrimStart('.').ToLowerInvariant());
        AllowedHosts = AllowedHosts.ConvertAll(x => x.Trim().ToLowerInvariant());
        AllowedDfsRoots = AllowedDfsRoots.ConvertAll(x => x.Trim().TrimStart('\\').ToLowerInvariant());
        InternalPublicSuffixes = InternalPublicSuffixes.ConvertAll(x => x.Trim().TrimStart('.').ToLowerInvariant());
        WebDavGateways = WebDavGateways.ConvertAll(x => x.Trim().ToLowerInvariant());
        SingleLabelPolicy = SingleLabelPolicy.Trim().ToLowerInvariant();
        if (SingleLabelPolicy is not ("allow" or "requireallow" or "deny"))
            throw new InvalidDataException($"SingleLabelPolicy 取值非法: {SingleLabelPolicy}（允许 allow/requireallow/deny）");
        foreach (var cidr in AllowedCidrs)
        {
            if (!CidrMatcher.IsValid(cidr))
                throw new InvalidDataException($"CIDR 配置非法: {cidr}");
        }
        // 预编译正则，提前暴露配置错误
        foreach (var rx in AllowedHostRegex)
        {
            try { _ = new System.Text.RegularExpressions.Regex(rx); }
            catch (Exception ex) { throw new InvalidDataException($"允许列表正则非法 '{rx}': {ex.Message}"); }
        }
    }
}
