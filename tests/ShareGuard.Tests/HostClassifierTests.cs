using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;
using Xunit;

namespace ShareGuard.Tests;

public class HostClassifierTests
{
    private static HostClassifier Create() => new(new AllowListConfig
    {
        AllowedSuffixes = ["corp.example.com"],
        AllowedHosts = ["dfs-root.corp.example.com", "filer.internal"],
        AllowedCidrs = ["10.0.0.0/8", "192.168.0.0/16"],
        AllowedSingleLabelNames = ["legacynas"],
        AllowedPorts = [445, 139, 80, 443],
        PendingReviewSuffixes = ["acquired.example"],
    });

    private static EmbeddedReference Ref(string raw) => ReferenceParser.Parse(raw, "test");

    [Fact]
    public void InternalSuffix_IsAllowed()
    {
        var v = Create().Classify(Ref(@"\\fileshare.corp.example.com\s"), out _);
        Assert.Equal(HostVerdict.AllowedInternal, v);
    }

    [Fact]
    public void ExternalDomain_IsMaliciousVerdict()
    {
        var c = Create();
        var v = c.Classify(Ref(@"\\evil.attacker.test\share"), out var reason);
        Assert.Equal(HostVerdict.External, v);
        Assert.Contains("白名单", reason);
    }

    [Fact]
    public void ExplicitHostAllowList_BeatsSuffixLogic()
    {
        var v = Create().Classify(Ref(@"\\filer.internal\share"), out _);
        Assert.Equal(HostVerdict.AllowedInternal, v);
    }

    [Fact]
    public void UnknownSingleLabelName_IsSuspiciousOnly()
    {
        // 关键防误报:陌生单标签名可能是新上线服务器,不能直接判 Malicious
        var v = Create().Classify(Ref(@"\\brandnew-server\share"), out _);
        Assert.Equal(HostVerdict.SingleLabel, v);
    }

    [Fact]
    public void ApprovedSingleLabelName_IsAllowed()
    {
        var v = Create().Classify(Ref(@"\\legacynas\share"), out _);
        Assert.Equal(HostVerdict.AllowedInternal, v);
    }

    [Fact]
    public void InternalIp_IsAllowed_PublicIp_IsUnknown()
    {
        var c = Create();
        Assert.Equal(HostVerdict.AllowedInternal,
            c.Classify(Ref(@"\\10.20.30.40\share"), out _));
        Assert.Equal(HostVerdict.UnknownIp,
            c.Classify(Ref(@"\\203.0.113.7\share"), out _));
    }

    [Fact]
    public void Ipv4MappedIpv6_CannotBypassCidr()
    {
        // ::ffff:10.1.2.3 必须还原成 IPv4 后命中 10.0.0.0/8
        var v = Create().Classify(Ref(@"\\[::ffff:10.1.2.3]\share"), out _);
        Assert.Equal(HostVerdict.AllowedInternal, v);
    }

    [Fact]
    public void PendingReviewSuffix_IsUntrustedNotFullyExternal()
    {
        var v = Create().Classify(Ref(@"\\fs.acquired.example\share"), out _);
        Assert.Equal(HostVerdict.UntrustedSuffix, v);
    }

    [Fact]
    public void LoopbackAndLinkLocal_AreSpecialVerdicts()
    {
        var c = Create();
        Assert.Equal(HostVerdict.Loopback, c.Classify(Ref(@"\\127.0.0.1\pipe"), out _));
        Assert.Equal(HostVerdict.LinkLocal, c.Classify(Ref(@"\\169.254.1.1\s"), out _));
    }

    [Fact]
    public void Aggravators_FlagNonStandardPortAndCredentialsAndWebDav()
    {
        var c = Create();
        Assert.Contains(c.GetAggravators(Ref("http://h.example.com:9999/")), a => a.Contains("非标准端口"));
        Assert.Contains(c.GetAggravators(Ref("dav://h.example.com/")), a => a.Contains("WebClient"));
        Assert.Contains(c.GetAggravators(Ref("https://u:p@h.example.com/")), a => a.Contains("显式凭据"));
    }

    [Fact]
    public void CidrSet_HandlesBoundaries()
    {
        var set = new CidrSet(["192.168.1.0/24"]);
        Assert.True(set.Contains(System.Net.IPAddress.Parse("192.168.1.0")));
        Assert.True(set.Contains(System.Net.IPAddress.Parse("192.168.1.255")));
        Assert.False(set.Contains(System.Net.IPAddress.Parse("192.168.2.0")));
    }
}
