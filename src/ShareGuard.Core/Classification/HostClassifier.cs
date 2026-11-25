using System.Net;
using System.Net.Sockets;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Classification;

/// <summary>
/// 主机分级:这是整个工具防误报的核心。
/// 判定完全离线完成(不做 DNS 解析),依据白名单后缀、显式主机清单与内网 CIDR。
/// </summary>
public sealed class HostClassifier
{
    private readonly AllowListConfig _config;
    private readonly CidrSet _allowedCidrs;
    private readonly HashSet<string> _allowedHosts;
    private readonly HashSet<string> _allowedSingleLabel;
    private readonly SortedSet<string> _suffixes;
    private readonly HashSet<string> _pendingSuffixes;

    public HostClassifier(AllowListConfig config)
    {
        _config = config;
        _allowedCidrs = new CidrSet(config.AllowedCidrs);
        _allowedHosts = new HashSet<string>(
            config.AllowedHosts.Select(ReferenceParser.NormalizeHost), StringComparer.Ordinal);
        _allowedSingleLabel = new HashSet<string>(
            config.AllowedSingleLabelNames.Select(h => h.TrimEnd('.').ToLowerInvariant()), StringComparer.Ordinal);
        _suffixes = new SortedSet<string>(
            config.AllowedSuffixes.Select(s => s.TrimStart('.').TrimEnd('.').ToLowerInvariant()),
            StringComparer.Ordinal);
        _pendingSuffixes = new HashSet<string>(
            config.PendingReviewSuffixes.Select(s => s.TrimStart('.').TrimEnd('.').ToLowerInvariant()),
            StringComparer.Ordinal);
    }

    public HostVerdict Classify(EmbeddedReference reference, out string reason)
    {
        reason = string.Empty;
        var host = reference.Host;
        if (string.IsNullOrEmpty(host))
        {
            reason = "引用不含主机(本地路径)";
            return HostVerdict.NoHost;
        }

        if (IsLoopback(host))
        {
            reason = $"回环地址 {host}";
            return HostVerdict.Loopback;
        }

        // 1) 显式主机白名单(最高优先级,覆盖 DFS 根 / 群集名)
        if (_allowedHosts.Contains(host))
        {
            reason = $"主机 {host} 在显式白名单内";
            return HostVerdict.AllowedInternal;
        }

        // 2) IP 字面量
        if (IPAddress.TryParse(host, out var ip))
        {
            if (IsLinkLocal(ip))
            {
                reason = $"链路本地地址 {host}";
                return HostVerdict.LinkLocal;
            }
            if (_allowedCidrs.Contains(ip))
            {
                reason = $"IP {host} 落在内网白名单网段";
                return HostVerdict.AllowedInternal;
            }

            reason = $"IP {host} 不在任何已批准内网网段";
            return HostVerdict.UnknownIp;
        }

        // 3) 单标签名(无点):靠 LLMNR/NBT-NS/广播解析,投毒风险高
        if (!host.Contains('.'))
        {
            if (_allowedSingleLabel.Contains(host))
            {
                reason = $"单标签名 {host} 在批准清单内";
                return HostVerdict.AllowedInternal;
            }
            reason = $"单标签主机名 {host}:依赖本地名称解析,可能被 LLMNR/NBT-NS 投毒";
            return HostVerdict.SingleLabel;
        }

        // 4) 后缀匹配
        if (HasAllowedSuffix(host, out var matchedSuffix))
        {
            reason = $"主机 {host} 匹配企业后缀 {matchedSuffix}";
            return HostVerdict.AllowedInternal;
        }

        if (HasPendingSuffix(host, out var pending))
        {
            reason = $"主机 {host} 属于待观察后缀 {pending}";
            return HostVerdict.UntrustedSuffix;
        }

        reason = $"主机 {host} 的 DNS 后缀不在企业白名单内";
        return HostVerdict.External;
    }

    /// <summary>引用级别的加重因子:显式凭据、非标准端口、可疑 scheme。</summary>
    public IReadOnlyList<string> GetAggravators(EmbeddedReference reference)
    {
        var list = new List<string>();
        if (reference.HasExplicitCredentials)
            list.Add($"引用 {reference.Raw} 内嵌显式凭据(userinfo),正常内部引用不会这样写");
        if (reference.Port is int p && !_config.AllowedPorts.Contains(p))
            list.Add($"引用使用非标准端口 {p}");
        if (reference.Scheme is ReferenceScheme.WebDav)
            list.Add("使用 dav/davs scheme,会触发 WebClient 服务外发认证");
        if (reference.Scheme is ReferenceScheme.Http && reference.Port is null or 80)
            list.Add("明文 HTTP 引用,可能经中间人返回 401 触发认证");
        return list;
    }

    public bool IsPendingReviewHost(string host) =>
        _pendingSuffixes.Any(s => host == s || host.EndsWith("." + s, StringComparison.Ordinal));

    private static bool IsLoopback(string host)
    {
        if (host is "localhost" or "ip6-localhost" or "ip6-loopback") return true;
        return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
    }

    private static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            // 169.254.0.0/16(APIPA),224.0.0.0/4 多播
            return (b[0] == 169 && b[1] == 254) || (b[0] >= 224 && b[0] <= 239);
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6Multicast;
    }

    private bool HasAllowedSuffix(string host, out string matched)
    {
        // SortedSet 无法直接做后缀查询;后缀数量通常几十条,线性扫描可接受。
        foreach (var suffix in _suffixes)
        {
            if (host == suffix || host.EndsWith("." + suffix, StringComparison.Ordinal))
            {
                matched = suffix;
                return true;
            }
        }
        matched = string.Empty;
        return false;
    }

    private bool HasPendingSuffix(string host, out string matched)
    {
        foreach (var suffix in _pendingSuffixes)
        {
            if (host == suffix || host.EndsWith("." + suffix, StringComparison.Ordinal))
            {
                matched = suffix;
                return true;
            }
        }
        matched = string.Empty;
        return false;
    }
}
