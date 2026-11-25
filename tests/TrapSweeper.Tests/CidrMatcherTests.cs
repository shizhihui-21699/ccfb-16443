using System.Net;
using TrapSweeper.Core.Classification;
using Xunit;

namespace TrapSweeper.Tests;

public class CidrMatcherTests
{
    [Theory]
    [InlineData("10.0.0.5", "10.0.0.0/8", true)]
    [InlineData("11.0.0.5", "10.0.0.0/8", false)]
    [InlineData("172.16.5.5", "172.16.0.0/12", true)]
    [InlineData("172.32.0.1", "172.16.0.0/12", false)]
    [InlineData("192.168.1.1", "192.168.0.0/16", true)]
    public void Ipv4Cidr_Matches(string ip, string cidr, bool expected)
    {
        var m = new CidrMatcher(new[] { cidr });
        Assert.Equal(expected, m.Contains(IPAddress.Parse(ip)));
    }

    [Fact]
    public void Ipv6Cidr_Works()
    {
        var m = new CidrMatcher(new[] { "fc00::/7" });
        Assert.True(m.Contains(IPAddress.Parse("fd12::1")));
        Assert.False(m.Contains(IPAddress.Parse("2606:4700::1")));
        Assert.True(m.Contains(IPAddress.Parse("::1")) == false);
    }

    [Fact]
    public void MappedIpv6_HitsIpv4Rule()
    {
        var m = new CidrMatcher(new[] { "10.0.0.0/8" });
        Assert.True(m.Contains(IPAddress.Parse("::ffff:10.20.30.40")));
    }

    [Fact]
    public void Slash32AndBareIp_AreValid()
    {
        Assert.True(CidrMatcher.IsValid("192.168.1.1"));
        Assert.True(CidrMatcher.IsValid("192.168.1.1/32"));
        Assert.False(CidrMatcher.IsValid("192.168.1.0/33"));
        Assert.False(CidrMatcher.IsValid("not-an-ip/8"));
    }

    [Fact]
    public void ZeroPrefix_MatchesEverything()
    {
        var m = new CidrMatcher(new[] { "0.0.0.0/0" });
        Assert.True(m.Contains(IPAddress.Parse("8.8.8.8")));
    }
}
