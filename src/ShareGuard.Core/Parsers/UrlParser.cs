using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// .url(Internet Shortcut)解析。
/// 攻击面:URL=、IconFile=、任何 URLn= 备用地址,以及经 Base64 编码的 PropList 扩展。
/// 除显式 URL 外,IconFile 的 UNC 路径同样会在浏览目录时触发认证。
/// </summary>
public sealed class UrlParser : IBaitParser
{
    public BaitFileType FileType => BaitFileType.Url;
    public IReadOnlySet<string> Extensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".url", ".website" };

    public IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content)
    {
        var ini = IniFile.Parse(content);
        var refs = new List<EmbeddedReference>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (section, key, value) in ini.EnumerateEntries())
        {
            var field = $"[{section}].{key}";

            // URL 类键:整值就是一个 URL(可能不带 // 的特殊 scheme,先尝试标准解析)
            if (key.Equals("URL", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("URL", StringComparison.OrdinalIgnoreCase))
            {
                var direct = ReferenceParser.Parse(value, field);
                if (direct.Scheme != ReferenceScheme.Local && seen.Add(direct.Raw))
                    refs.Add(direct);
            }

            // 其余键(IconFile、ModifiedCache 等)做子串提取;
            // URL 键也跑一遍以覆盖同一值里夹带第二个 UNC 的情况,靠 seen 去重
            foreach (var (candidate, _) in ReferenceParser.ExtractNetworkStrings(value))
            {
                if (seen.Add(candidate))
                    refs.Add(ReferenceParser.Parse(candidate, field));
            }
        }
        return refs;
    }
}
