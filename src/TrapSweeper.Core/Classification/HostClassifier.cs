using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Classification;

/// <summary>
/// 主机分类引擎。把一条 <see cref="HostReference"/> 转换为带完整证据链的 <see cref="HostVerdict"/>：
/// 先收集全部可疑信号，再用允许列表逐条解释，最后按分数给出结论。
/// 设计原则：宁可让可疑项进人工复核，也不让未解释的外部主机静默通过。
/// </summary>
public sealed class HostClassifier
{
    private readonly AllowListConfig _cfg;
    private readonly CidrMatcher _allowedNets;
    private readonly List<Regex> _hostRegex;

    // RFC1918 / 链路本地 / 环回 / 唯一本地地址等"天然内网"范围
    private static readonly string[] PrivateCidrs =
    {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
        "fc00::/7", "fe80::/10", "::1/128"
    };
    private readonly CidrMatcher _privateNets = new(PrivateCidrs);

    public HostClassifier(AllowListConfig cfg)
    {
        _cfg = cfg;
        _allowedNets = new CidrMatcher(cfg.AllowedCidrs);
        _hostRegex = cfg.AllowedHostRegex.Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)).ToList();
    }

    public HostVerdict Classify(HostReference reference)
    {
        var host = reference.Host ?? string.Empty;
        var v = new HostVerdict { Host = host };
        var score = 0;
        // 硬性规避信号：无论分数高低，只要出现就不能静默放行
        var strongEvasionSignal = false;

        // ---------- 1. 信号收集 ----------
        if (reference.IsObfuscatedIp)
        {
            v.Signals.Add("IP 字面量采用非标准进制/编码（十进制整数、八进制、十六进制或混合写法）");
            score += 45;
            strongEvasionSignal = true;
        }
        if (reference.HasEmbeddedCredentials)
        {
            v.Signals.Add("URI 内嵌用户名/密码（可能用于凭据收集或绕过简单规则）");
            score += 35;
            strongEvasionSignal = true;
        }
        if (reference.Port is { } port && _cfg.TrustedPorts.Count > 0 && !_cfg.TrustedPorts.Contains(port))
        {
            v.Signals.Add($"非标准端口 {port}（可信端口列表之外，常见于绕过边界设备）");
            score += 20;
        }
        if (reference.Scheme == "http" && !_cfg.AllowCleartextHttp && !_cfg.WebDavGateways.Contains(host.ToLowerInvariant()))
        {
            v.Signals.Clear();
            v.Signals.Add("明文 http 引用（启用了 WebDAV 重定向器时可触发 Basic/NTLM 凭据外发）");
            score += 30;
        }
        if (reference.Scheme == "http" || reference.Scheme == "https")
        {
            v.Signals.Add("http(s) URL 引用（WebClient 服务启用时会发起 WebDAV/HTTP 认证）");
            score += 10;
        }
        if (host.Contains('%'))
        {
            v.Signals.Add("主机名含百分号编码（典型规避手法）");
            score += 25;
            strongEvasionSignal = true;
        }
        if (host.EndsWith('.'))
        {
            v.Signals.Add("主机名带尾随点（规避后缀匹配的常见手法）");
            score += 15;
        }
        if (host.StartsWith("xn--", StringComparison.OrdinalIgnoreCase) || host.Contains(".xn--"))
        {
            v.Signals.Add("Punycode 主机名（同形异义/IDN 仿冒）");
            score += 20;
        }

        // ---------- 2. 允许列表解释 ----------
        var allowed = false;
        var h = host.TrimEnd('.').ToLowerInvariant();

        if (IPAddress.TryParse(h, out var ip))
        {
            if (_allowedNets.Contains(ip))
            {
                allowed = true;
                v.MatchedAllowRules.Add($"AllowedCidrs(含 {ip})");
            }
            else if (!_privateNets.Contains(ip))
            {
                v.Signals.Add($"公网 IP 字面量 {ip}");
                score += 50;
            }
            else
            {
                v.Signals.Add($"私有地址 {ip} 但不在 AllowedCidrs 中（未登记网段）");
                score += 15;
            }
        }
        else
        {
            // 精确主机 / DFS 根
            if (_cfg.AllowedHosts.Contains(h) || _cfg.AllowedDfsRoots.Contains(h))
            {
                allowed = true;
                v.MatchedAllowRules.Add("AllowedHosts/AllowedDfsRoots");
            }

            // 后缀（子域命中）
            var suffix = _cfg.AllowedSuffixes.FirstOrDefault(s => h == s || h.EndsWith("." + s));
            if (suffix != null)
            {
                allowed = true;
                v.MatchedAllowRules.Add($"AllowedSuffixes:{suffix}");
            }

            // 正则白名单
            var rx = _hostRegex.FirstOrDefault(r => r.IsMatch(h));
            if (rx != null)
            {
                allowed = true;
                v.MatchedAllowRules.Add($"AllowedHostRegex:{rx}");
            }

            var isSingleLabel = !h.Contains('.');
            if (isSingleLabel)
            {
                switch (_cfg.SingleLabelPolicy)
                {
                    case "allow" when !allowed:
                        allowed = true;
                        v.MatchedAllowRules.Add("SingleLabelPolicy=allow");
                        break;
                    case "deny":
                        v.Signals.Add("单标签主机名且策略为 Deny");
                        score += 25;
                        break;
                    case "requireallow" when !allowed:
                        v.Signals.Add("单标签主机名未在 AllowedHosts 登记（短名可被 LLMNR/NBNS 投毒响应）");
                        score += 25;
                        break;
                }
            }
            else if (!allowed && suffix == null && LooksLikeExternalDomain(h))
            {
                v.Signals.Add("主机名位于公共后缀之下且未命中任何允许规则");
                score += 45;
            }
        }

        // WebDAV 网关豁免明文 http 的提示性信号
        if (allowed && (reference.Scheme is "http" or "https") && _cfg.WebDavGateways.Contains(h))
            v.MatchedAllowRules.Add("WebDavGateways");

        // ---------- 3. 可选 DNS 校验 ----------
        if (_cfg.EnableDnsCheck && !IPAddress.TryParse(h, out _) && v.Severity != Severity.Critical)
        {
            try
            {
                _ = Dns.GetHostAddressesAsync(h).Wait(TimeSpan.FromSeconds(3));
            }
            catch
            {
                v.Signals.Add("DNS 无法解析该主机（可能是已下线的攻击基础设施或内部未登记主机）");
                v.Verdict = Verdict.Unresolvable;
                v.Severity = Severity.Medium;
                v.Score = score;
                return v;
            }
        }

        // ---------- 4. 结论 ----------
        v.Score = score;
        if (allowed && !strongEvasionSignal && score < 40)
        {
            v.Verdict = Verdict.Allowed;
            v.Severity = Severity.Info;
        }
        else if (allowed)
        {
            // 允许名单内但带强信号（内嵌凭证/混淆 IP/编码规避等）：降级为可疑，强制人工看一眼
            v.Verdict = Verdict.Suspicious;
            v.Severity = score >= 60 ? Severity.High : Severity.Medium;
            v.Signals.Add("命中允许列表但同时存在高风险信号，降级为可疑");
        }
        else
        {
            v.Verdict = score >= 45 ? Verdict.External : Verdict.Suspicious;
            v.Severity = score switch
            {
                >= 75 => Severity.Critical,
                >= 45 => Severity.High,
                >= 20 => Severity.Medium,
                _ => Severity.Low
            };
        }

        return v;
    }

    /// <summary>
    /// 轻量公共后缀判断：取最后两段，若后缀是常见双段公共后缀(co.uk 等)则取最后三段。
    /// 不追求 PSL 全覆盖——未命中允许列表的域名本来就需要人工确认，这里只决定分数高低。
    /// </summary>
    private bool LooksLikeExternalDomain(string h)
    {
        if (_cfg.InternalPublicSuffixes.Any(s => h == s || h.EndsWith("." + s))) return false;

        var labels = h.Split('.');
        if (labels.Length < 2) return false;

        var tld = labels[^1];
        // 内网/私有顶级域：local, internal, corp, lan, home, intranet, site, test, private, AD 域名等
        var privateTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "local", "internal", "corp", "lan", "home", "intranet", "site", "test", "private", "ad", "domain", "office"
        };
        if (privateTlds.Contains(tld)) return false;

        return true;
    }
}
