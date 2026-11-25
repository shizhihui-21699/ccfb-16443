using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;
using ShareGuard.Tests.Support;
using Xunit;

namespace ShareGuard.Tests;

public class LnkParserTests
{
    private readonly LnkParser _parser = new();

    [Fact]
    public void NetworkLnk_ExtractsUncTarget()
    {
        var bytes = LnkSampleBuilder.BuildNetworkLnk("evil.example.com", "share");
        var refs = _parser.Parse("sample.lnk", bytes);

        Assert.Contains(refs, r => r.Scheme == ReferenceScheme.Unc && r.Host == "evil.example.com");
    }

    [Fact]
    public void NetworkLnk_InternalServer_IsAlsoExtracted()
    {
        // 解析层不做善恶判断——内部引用同样要提取,判罚在 Classifier
        var bytes = LnkSampleBuilder.BuildNetworkLnk("filer.corp.example.com", "dfs");
        var refs = _parser.Parse("sample.lnk", bytes);
        Assert.Contains(refs, r => r.Host == "filer.corp.example.com");
    }

    [Fact]
    public void NetworkLnk_WithIconLocation_ExtractsBothReferences()
    {
        var bytes = LnkSampleBuilder.BuildNetworkLnk(
            "evil.example.com", "share", @"\\cdn.attacker.test\icons\a.ico");
        var refs = _parser.Parse("sample.lnk", bytes);

        Assert.Contains(refs, r => r.Host == "evil.example.com");
        Assert.Contains(refs, r => r.Host == "cdn.attacker.test");
    }

    [Fact]
    public void CorruptHeader_ThrowsBaitParseException()
    {
        var bytes = LnkSampleBuilder.BuildCorruptLnk();
        Assert.Throws<BaitParseException>(() => _parser.Parse("bad.lnk", bytes));
    }

    [Fact]
    public void TruncatedFile_ThrowsRatherThanCrashes()
    {
        var bytes = LnkSampleBuilder.BuildNetworkLnk("evil.example.com", "share");
        var truncated = bytes[..40];
        Assert.Throws<BaitParseException>(() => _parser.Parse("trunc.lnk", truncated));
    }

    [Fact]
    public void SweepFallback_RecoversUncFromCorruptLnkViaAnalyzer()
    {
        // 端到端:FileAnalyzer 在 LNK 结构解析失败后会跑字符串扫描兜底
        var bytes = LnkSampleBuilder.BuildCorruptLnk();
        var sink = new List<EmbeddedReference>();
        StringSweeper.Sweep(bytes, sink);
        Assert.Contains(sink, r => r.Host != null && r.Host.Contains("example.com"));
    }

    [Fact]
    public void Utf16EncodedUncInBinary_IsDetectedBySweeper()
    {
        var utf16 = System.Text.Encoding.Unicode.GetBytes(@"junk \\utf16.evil.test\share\f.ico trailing");
        var sink = new List<EmbeddedReference>();
        StringSweeper.Sweep(utf16, sink);
        Assert.Contains(sink, r => r.Host == "utf16.evil.test");
    }
}
