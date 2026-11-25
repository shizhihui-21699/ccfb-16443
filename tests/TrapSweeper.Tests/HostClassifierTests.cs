using TrapSweeper.Core.Classification;
using TrapSweeper.Core.Models;
using Xunit;

namespace TrapSweeper.Tests;

public class HostClassifierTests
{
    private static HostClassifier Build(AllowListConfig? cfg = null)
    {
        cfg ??= new AllowListConfig
        {
            AllowedSuffixes = new() { "corp.local" },
            AllowedHosts = new() { "fileserver", "nas01" },
            AllowedHostRegex = new() { @"^fs-\d+\.corp\.local$" },
            AllowedCidrs = new() { "10.0.0.0/8", "172.16.0.0/12" },
            AllowedDfsRoots = new() { "dc01.corp.local" },
            SingleLabelPolicy = "requireallow"
        };
        return new HostClassifier(cfg);
    }

    private static HostReference Ref(string host, string scheme = "unc", int? port = null,
        bool obf = false, bool creds = false, bool ip = false) => new()
    {
        Host = host, Scheme = scheme, Port = port, IsObfuscatedIp = obf,
        HasEmbeddedCredentials = creds, IsIpLiteral = ip, Raw = host, Role = "test"
    };

    [Fact]
    public void InternalSuffix_Allowed()
    {
        var v = Build().Classify(Ref("fs02.corp.local"));
        Assert.Equal(Verdict.Allowed, v.Verdict);
        Assert.Contains(v.MatchedAllowRules, r => r.Contains("AllowedSuffixes"));
    }

    [Fact]
    public void RegexWhitelist_Allowed()
    {
        var v = Build().Classify(Ref("fs-42.corp.local"));
        Assert.Equal(Verdict.Allowed, v.Verdict);
    }

    [Fact]
    public void PublicDomain_External()
    {
        var v = Build().Classify(Ref("attacker.evil.example.com"));
        Assert.Equal(Verdict.External, v.Verdict);
        Assert.Contains(v.Signals, s => s.Contains("公共后缀"));
    }

    [Fact]
    public void PublicIp_External()
    {
        var v = Build().Classify(Ref("203.0.113.9", ip: true));
        Assert.Equal(Verdict.External, v.Verdict);
        Assert.Contains(v.Signals, s => s.Contains("公网 IP"));
    }

    [Fact]
    public void PrivateIpOutsideAllowList_SuspiciousNotSilent()
    {
        var v = Build().Classify(Ref("192.168.5.5", ip: true));
        Assert.Equal(Verdict.Suspicious, v.Verdict);
        Assert.Contains(v.Signals, s => s.Contains("未登记网段"));
    }

    [Fact]
    public void AllowedIpRange_Allowed()
    {
        var v = Build().Classify(Ref("10.20.30.40", ip: true));
        Assert.Equal(Verdict.Allowed, v.Verdict);
    }

    [Fact]
    public void SingleLabelUnknown_SuspiciousByDefault()
    {
        var v = Build().Classify(Ref("randombox"));
        Assert.Equal(Verdict.Suspicious, v.Verdict);
        Assert.Contains(v.Signals, s => s.Contains("单标签"));
    }

    [Fact]
    public void SingleLabelAllowPolicy_Allowed()
    {
        var cfg = new AllowListConfig { SingleLabelPolicy = "allow" };
        var v = new HostClassifier(cfg).Classify(Ref("whatever"));
        Assert.Equal(Verdict.Allowed, v.Verdict);
    }

    [Fact]
    public void ObfuscatedIp_EvenOnAllowedNetwork_Downgraded()
    {
        // 混淆 10.0.0.1 且 10/8 在允许列表：强信号应把结论压回可疑
        var v = Build().Classify(Ref("10.0.0.1", ip: true, obf: true));
        Assert.Equal(Verdict.Suspicious, v.Verdict);
        Assert.Contains(v.Signals, s => s.Contains("非标准进制"));
    }

    [Fact]
    public void NonStandardPort_AddsSignal()
    {
        var v = Build().Classify(Ref("fs02.corp.local", port: 8445));
        Assert.Contains(v.Signals, s => s.Contains("非标准端口"));
    }

    [Fact]
    public void CleartextHttp_Flagged()
    {
        var v = Build().Classify(Ref("dav.corp.local", scheme: "http"));
        Assert.Contains(v.Signals, s => s.Contains("明文 http"));
    }

    [Fact]
    public void EmbeddedCredentialsOnAllowedHost_Downgraded()
    {
        var v = Build().Classify(Ref("fs02.corp.local", creds: true));
        Assert.Equal(Verdict.Suspicious, v.Verdict);
    }

    [Fact]
    public void DfsRoot_Allowed()
    {
        var v = Build().Classify(Ref("dc01.corp.local"));
        Assert.Equal(Verdict.Allowed, v.Verdict);
    }

    [Fact]
    public void PrivateTldLocal_NotTreatedAsExternal()
    {
        var cfg = new AllowListConfig { SingleLabelPolicy = "allow" };
        var v = new HostClassifier(cfg).Classify(Ref("printer.office"));
        // .office 被视为私有 TLD，不应叠加"公共后缀外部域"45 分
        Assert.DoesNotContain(v.Signals, s => s.Contains("公共后缀"));
    }
}
