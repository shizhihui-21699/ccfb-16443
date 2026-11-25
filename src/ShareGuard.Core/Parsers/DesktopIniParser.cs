using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// desktop.ini 解析。正常的文件夹图标大量引用本地 %SystemRoot%\system32\imageres.dll,
/// 也有合法的 UNC 图标(统一桌面映像场景),因此这里只提取、不判罚——判罚交给白名单。
/// 攻击面集中在 IconFile / IconResource / 任何含 "icon" 的键。
/// </summary>
public sealed class DesktopIniParser : IBaitParser
{
    public BaitFileType FileType => BaitFileType.DesktopIni;
    public IReadOnlySet<string> Extensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ini" };

    public IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content)
    {
        var ini = IniFile.Parse(content);
        var refs = new List<EmbeddedReference>();

        foreach (var (section, key, value) in ini.EnumerateEntries())
        {
            // IconResource 的典型形态:C:\path\icon.dll,5 或 \\server\share\icon.ico,0
            var field = $"[{section}].{key}";
            foreach (var (candidate, _) in ReferenceParser.ExtractNetworkStrings(value))
                refs.Add(ReferenceParser.Parse(candidate, field));

            // 不带反斜杠的纯主机形式不会被 UNC 正则命中,IconFile 直接给整值再解析一次
            if (key.Contains("icon", StringComparison.OrdinalIgnoreCase) &&
                value.StartsWith(@"\\", StringComparison.Ordinal))
            {
                refs.Add(ReferenceParser.Parse(value, field));
            }
        }
        return refs;
    }
}
