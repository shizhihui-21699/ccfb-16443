using TrapSweeper.Core.Models;
using TrapSweeper.Core.Parsers;

namespace TrapSweeper.Core.Analysis;

/// <summary>扩展名 → 诱饵类型/解析方式的注册表。集中维护，避免枚举器里散落魔法字符串。</summary>
public static class FileTypeRegistry
{
    public sealed record FileTypeSpec(DecoyKind Kind, string DisplayName, bool SniffLnkHeader);

    private static readonly Dictionary<string, FileTypeSpec> ByExtension = new(StringComparer.OrdinalIgnoreCase)
    {
        [".lnk"] = new(DecoyKind.Lnk, "Shell 快捷方式", true),
        [".ini"] = new(DecoyKind.DesktopIni, "文件夹配置(desktop.ini 类)", false),
        [".url"] = new(DecoyKind.UrlFile, "Internet 快捷方式", true),
        [".scf"] = new(DecoyKind.ScfFile, "Explorer 命令文件", true),
        [".search-ms"] = new(DecoyKind.SearchMs, "已保存搜索", false),
        [".searchconnector-ms"] = new(DecoyKind.SearchConnector, "搜索连接器", false),
        [".library-ms"] = new(DecoyKind.LibraryMs, "库定义", false),
        [".settingcontent-ms"] = new(DecoyKind.SettingContentMs, "设置内容文件", false),
    };

    /// <summary>枚举阶段使用的扩展名集合。</summary>
    public static IReadOnlyCollection<string> TrackedExtensions => ByExtension.Keys;

    /// <summary>按完整文件名匹配（多段扩展名优先，如 .searchconnector-ms 优先于 .ms）。</summary>
    public static FileTypeSpec? ByName(string fileName)
    {
        // 精确优先（.searchconnector-ms 含多段扩展），再回退到最后一段扩展名
        foreach (var (ext, spec) in ByExtension)
        {
            if (fileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return spec;
        }
        return null;
    }

    /// <summary>按扩展名（含点）直接查表；嗅探伪造 lnk 时可传入任意 x.lnk 取得规范类型。</summary>
    public static FileTypeSpec? ByExtensionFirst(string pathOrName)
    {
        var ext = Path.GetExtension(pathOrName);
        return string.IsNullOrEmpty(ext) ? null
            : ByExtension.TryGetValue(ext, out var spec) ? spec : ByName(pathOrName);
    }

    public static bool IsDesktopIni(string pathOrName) =>
        Path.GetFileName(pathOrName).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);

    /// <summary>按类型分派解析。<paramref name="candidate"/> 已按扩展名或嗅探命中。</summary>
    public static ParsedFile Parse(byte[] bytes, DecoyKind kind) => kind switch
    {
        DecoyKind.Lnk => LnkParser.Parse(bytes),
        DecoyKind.DesktopIni => IniLikeParser.Parse(bytes, kind, IniLikeParser.DesktopIniRoles),
        DecoyKind.UrlFile => IniLikeParser.Parse(bytes, kind, IniLikeParser.UrlRoles),
        DecoyKind.ScfFile => IniLikeParser.Parse(bytes, kind, IniLikeParser.ScfRoles),
        DecoyKind.SearchMs or DecoyKind.SearchConnector or DecoyKind.LibraryMs or DecoyKind.SettingContentMs
            => ShellXmlParser.Parse(bytes, kind),
        _ => new ParsedFile { Kind = kind, Error = "未注册的解析类型" }
    };
}
