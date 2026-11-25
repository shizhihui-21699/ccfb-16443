using System.Text;
using System.Text.RegularExpressions;
using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// 搜索连接器 / 库 / OpenSearch 描述文件的解析器。
/// 三类文件都是 XML,攻击面包括:
///   - &lt;simpleLocation url="\\server\share" /&gt;(浏览连接器即连接)
///   - &lt;url template="http://..." /&gt;(联合搜索,可指向攻击者服务器)
///   - &lt;iconReference&gt;、&lt;thumbnail&gt; 等图标引用
/// 不依赖 XmlDocument:诱饵可能包含畸形编码或超大实体,正则提取更抗攻击,
/// 且我们只关心其中的 UNC/URL 字符串。
/// </summary>
public sealed class SearchConnectorParser : IBaitParser
{
    // 捕获 attribute="value" 形式,便于把属性名作为 SourceField
    private static readonly Regex AttributeRegex = new(
        @"(?<attr>[A-Za-z_][\w:.-]*)\s*=\s*""(?<val>[^""]*)""",
        RegexOptions.Compiled);

    // 捕获 >text< 元素文本
    private static readonly Regex TextNodeRegex = new(
        @">\s*(?<val>[^<>\r\n]{3,})\s*<",
        RegexOptions.Compiled);

    public BaitFileType FileType => BaitFileType.SearchConnector;
    public IReadOnlySet<string> Extensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".searchconnector-ms", ".searchconnector", ".library-ms", ".osdx",
        };

    public IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content)
    {
        var text = Decode(content);
        var refs = new List<EmbeddedReference>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (Match m in AttributeRegex.Matches(text))
        {
            var attr = m.Groups["attr"].Value;
            var val = m.Groups["val"].Value;

            // xmlns / xmlns:xxx 是 XML 命名空间声明(典型值 schemas.microsoft.com),
            // 只用于解析、不产生任何网络连接,排除以免把标准 schema 误报成外发主机
            if (attr.Equals("xmlns", StringComparison.OrdinalIgnoreCase) ||
                attr.StartsWith("xmlns:", StringComparison.OrdinalIgnoreCase))
                continue;

            AddCandidates(val, $"xml:attr:{attr}", refs, seen);
        }

        foreach (Match m in TextNodeRegex.Matches(text))
        {
            AddCandidates(m.Groups["val"].Value, "xml:text", refs, seen);
        }
        return refs;
    }

    private static void AddCandidates(string value, string field,
        List<EmbeddedReference> refs, HashSet<string> seen)
    {
        // 属性里可能直接是 UNC/URL,也可能在长文本中夹带
        var direct = ReferenceParser.Parse(value, field);
        if (direct.Scheme != ReferenceScheme.Local && seen.Add(direct.Raw))
            refs.Add(direct);

        foreach (var (candidate, _) in ReferenceParser.ExtractNetworkStrings(value))
        {
            if (seen.Add(candidate))
                refs.Add(ReferenceParser.Parse(candidate, field));
        }
    }

    private static string Decode(byte[] content)
    {
        if (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
            return Encoding.UTF8.GetString(content, 3, content.Length - 3);
        if (content.Length >= 2 && content[0] == 0xFF && content[1] == 0xFE)
            return Encoding.Unicode.GetString(content, 2, content.Length - 2);
        if (content.Length >= 2 && content[0] == 0xFE && content[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(content, 2, content.Length - 2);

        var probe = Math.Min(content.Length, 512);
        var zeros = 0;
        for (var i = 0; i < probe; i++) if (content[i] == 0) zeros++;
        return zeros > probe / 4
            ? Encoding.Unicode.GetString(content)
            : Encoding.UTF8.GetString(content);
    }
}
