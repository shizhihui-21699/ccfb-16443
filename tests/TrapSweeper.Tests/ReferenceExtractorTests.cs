using System.Linq;
using TrapSweeper.Core.Analysis;
using Xunit;

namespace TrapSweeper.Tests;

public class ReferenceExtractorTests
{
    [Fact]
    public void Extract_UncPath_ParsesHostShareAndPath()
    {
        var refs = ReferenceExtractor.Extract(@"\\fileserver01.corp.local\share\dir\icon.ico", "IconLocation").ToList();
        var r = Assert.Single(refs);
        Assert.Equal("unc", r.Scheme);
        Assert.Equal("fileserver01.corp.local", r.Host);
        Assert.Equal("share", r.Share);
        Assert.Equal(@"dir\icon.ico", r.Path);
    }

    [Fact]
    public void Extract_LongUncPrefix_Works()
    {
        var refs = ReferenceExtractor.Extract(@"\\?\UNC\evil.example.com\share\x", "Target").ToList();
        Assert.Equal("evil.example.com", Assert.Single(refs).Host);
    }

    [Fact]
    public void Extract_HttpUrl_CapturesHostAndPort()
    {
        var refs = ReferenceExtractor.Extract("https://attacker.example:8443/dav/folder", "Url").ToList();
        var r = Assert.Single(refs);
        Assert.Equal("https", r.Scheme);
        Assert.Equal("attacker.example", r.Host);
        Assert.Equal(8443, r.Port);
    }

    [Fact]
    public void Extract_EmbeddedCredentials_Flagged()
    {
        var refs = ReferenceExtractor.Extract(@"\\user:pass@fileserver\share", "Target").ToList();
        Assert.True(Assert.Single(refs).HasEmbeddedCredentials);
    }

    [Fact]
    public void Extract_ObfuscatedDecimalIp_DetectedAndNormalized()
    {
        // 0x0A000001 = 167772161 = 10.0.0.1
        var refs = ReferenceExtractor.Extract(@"\\167772161\share", "IconLocation").ToList();
        var r = Assert.Single(refs);
        Assert.True(r.IsObfuscatedIp);
        Assert.Equal("10.0.0.1", r.Host);
    }

    [Fact]
    public void Extract_OctalAndHexLabels_Detected()
    {
        Assert.True(ReferenceExtractor.IsObfuscatedIpLiteral("012.0x0.0.1"));
        Assert.Equal("10.0.0.1", ReferenceExtractor.NormalizeObfuscatedIp("012.0x0.0.1"));
        // 标准点分十进制不算混淆
        Assert.False(ReferenceExtractor.IsObfuscatedIpLiteral("10.0.0.1"));
        // 域名不算
        Assert.False(ReferenceExtractor.IsObfuscatedIpLiteral("fs01.corp.local"));
    }

    [Fact]
    public void Extract_Ipv6Literal_Parsed()
    {
        var refs = ReferenceExtractor.Extract(@"\\[fe80::1]\share", "Target").ToList();
        Assert.Equal("fe80::1", Assert.Single(refs).Host);
        Assert.True(Assert.Single(refs).IsIpLiteral);
    }

    [Fact]
    public void Extract_DriveLetter_NotTreatedAsHost()
    {
        var refs = ReferenceExtractor.Extract(@"C:\Windows\System32\shell32.dll", "IconLocation").ToList();
        Assert.Empty(refs);
    }

    [Fact]
    public void SweepRawBytes_FindsUtf16AndAnsiReferences()
    {
        // UTF-16LE 编码的 UNC
        var utf16 = System.Text.Encoding.Unicode.GetBytes(@"\\evil.example.com\share");
        var ansi = System.Text.Encoding.Latin1.GetBytes("garbage\\\\10.1.2.3\\share");
        var all = utf16.Concat(new byte[] { 0, 0, 0, 0 }).Concat(ansi).ToArray();

        var refs = ReferenceExtractor.SweepRawBytes(all).ToList();
        Assert.Contains(refs, r => r.Host == "evil.example.com");
        Assert.Contains(refs, r => r.Host == "10.1.2.3");
    }

    [Fact]
    public void Extract_TrailingDotHost_PreservedForEvasionSignal()
    {
        var refs = ReferenceExtractor.Extract(@"\\fs01.corp.local.\share", "IconLocation").ToList();
        Assert.Equal("fs01.corp.local.", Assert.Single(refs).Host);
    }
}
