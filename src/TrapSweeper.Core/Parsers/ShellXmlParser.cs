using System.Xml;
using System.Xml.Linq;
using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Parsers;

/// <summary>
/// 解析外壳 XML 配置：.search-ms、.searchConnector-ms、.library-ms、.settingcontent-ms。
/// 诱饵关注 &lt;url&gt;、&lt;iconReference&gt;、&lt;propertyStore&gt; 内的 UNC/WebDAV 位置；
/// 浏览或单击时 Search Connector / Library 会自动连接 location 并携带当前用户凭据。
/// 关闭 DTD/外部实体解析（XXE 防护），命名空间无关地按本地名匹配。
/// </summary>
public static class ShellXmlParser
{
    // 本地名 → 引用角色
    private static readonly Dictionary<string, string> InterestingElements = new(StringComparer.Ordinal)
    {
        ["url"] = "SearchLocation.Url",
        ["serialized"] = "SearchLocation.Serialized",
        ["iconReference"] = "IconReference",
        ["property"] = "PropertyStore",
        ["simpleLocation"] = "Library.SimpleLocation",
        ["folder"] = "Library.Folder",
        ["defaultSaveFolder"] = "Library.DefaultSaveFolder",
        ["owner"] = "Library.Owner",
    };

    // 属性元素里值得检查的 name 属性
    private static readonly HashSet<string> InterestingPropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.TileIcon", "System.Icon", "System.Link.TargetParsingPath",
        "System.PropList.FileOpenPrompt", "System.Shell.SFGAOFlagsStrings"
    };

    public static ParsedFile Parse(byte[] bytes, DecoyKind kind)
    {
        var result = new ParsedFile { Kind = kind };
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 4 * 1024 * 1024,
                IgnoreWhitespace = true
            };

            using var ms = new MemoryStream(bytes);
            using var xr = XmlReader.Create(ms, settings);
            var doc = XDocument.Load(xr, LoadOptions.None);
            if (doc.Root is null)
            {
                result.Error = "XML 无根元素";
                result.Add(ReferenceExtractor.SweepRawBytes(bytes));
                return result;
            }

            foreach (var el in doc.Descendants())
            {
                var local = el.Name.LocalName;
                if (!InterestingElements.TryGetValue(local, out var role)) continue;

                var text = el.Value;
                if (local == "property")
                {
                    var name = el.Attribute("name")?.Value ?? el.Attribute("key")?.Value;
                    if (name == null || !InterestingPropertyNames.Contains(name)) continue;
                    role = $"PropertyStore.{name}";
                    var propValue = el.Attribute("value")?.Value ?? text;
                    Emit(result, propValue, role);
                    continue;
                }

                // 元素属性里也可能携带路径（如 simpleLocation url="..."）
                foreach (var attr in el.Attributes())
                {
                    if (attr.Name.LocalName is "url" or "href" or "path" or "value")
                        Emit(result, attr.Value, $"{role}.{attr.Name.LocalName}");
                }
                Emit(result, text, role);
            }
        }
        catch (XmlException ex)
        {
            result.Truncated = true;
            result.Error = $"XML 解析失败: {ex.Message}";
            result.Add(ReferenceExtractor.SweepRawBytes(bytes));
        }

        return result;
    }

    private static void Emit(ParsedFile result, string? value, string role)
    {
        if (!string.IsNullOrWhiteSpace(value))
            result.Add(ReferenceExtractor.Extract(value, role, "xml"));
    }
}
