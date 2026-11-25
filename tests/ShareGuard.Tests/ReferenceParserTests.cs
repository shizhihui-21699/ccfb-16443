using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;
using Xunit;

namespace ShareGuard.Tests;

public class ReferenceParserTests
{
    [Theory]
    [InlineData(@"\\server01\share\icon.ico", "server01", ReferenceScheme.Unc)]
    [InlineData(@"\\?\UNC\filer.corp.example.com\dfs\a.lnk", "filer.corp.example.com", ReferenceScheme.Unc)]
    [InlineData("http://evil.example.com/x.ico", "evil.example.com", ReferenceScheme.Http)]
    [InlineData("https://evil.example.com:8443/x", "evil.example.com", ReferenceScheme.Http)]
    [InlineData("file://server/share/f.txt", "server", ReferenceScheme.FileUrl)]
    [InlineData(@"C:\Windows\system32\imageres.dll", null, ReferenceScheme.Local)]
    [InlineData("%SystemRoot%\\system32\\shell32.dll", null, ReferenceScheme.Local)]
    public void Parse_ClassifiesSchemeAndHost(string raw, string? expectedHost, ReferenceScheme expectedScheme)
    {
        var r = ReferenceParser.Parse(raw, "test");
        Assert.Equal(expectedScheme, r.Scheme);
        Assert.Equal(expectedHost, r.Host);
    }

    [Fact]
    public void Parse_UrlWithUserInfo_FlagsExplicitCredentials()
    {
        var r = ReferenceParser.Parse("https://user:pass@evil.example.com/x", "test");
        Assert.True(r.HasExplicitCredentials);
        Assert.Equal("evil.example.com", r.Host);
    }

    [Fact]
    public void Parse_Ipv6Literal_StripsBrackets()
    {
        var r = ReferenceParser.Parse(@"\\[2001:db8::1]\share", "test");
        Assert.Equal("2001:db8::1", r.Host);
        Assert.Equal(ReferenceScheme.Unc, r.Scheme);
    }

    [Fact]
    public void Parse_NonStandardPort_IsCaptured()
    {
        var r = ReferenceParser.Parse("http://evil.example.com:4444/x", "test");
        Assert.Equal(4444, r.Port);
    }

    [Fact]
    public void NormalizeHost_StripsTrailingDotAndLowercases()
    {
        Assert.Equal("host.corp.example.com",
            ReferenceParser.NormalizeHost("HOST.Corp.Example.COM."));
    }

    [Fact]
    public void ExtractNetworkStrings_FindsMultipleUncInOneLine()
    {
        var text = @"args \\a.example.com\s1 x \\b.example.com\s2";
        var hits = ReferenceParser.ExtractNetworkStrings(text).ToList();
        Assert.Equal(2, hits.Count);
        Assert.Contains(hits, h => h.Value.StartsWith(@"\\a.example.com"));
        Assert.Contains(hits, h => h.Value.StartsWith(@"\\b.example.com"));
    }

    [Fact]
    public void ExtractNetworkStrings_DevicePathsAreNotTreatedAsUnc()
    {
        var hits = ReferenceParser.ExtractNetworkStrings(@"\\.\pipe\foo").ToList();
        Assert.Empty(hits);
    }
}
