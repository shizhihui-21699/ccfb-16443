using System.Text;
using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Parsers;

/// <summary>
/// 解析 INI 风格的外壳文件：desktop.ini、.url(InternetShortcut)、.scf(Explorer Command)。
/// 这些文件只需出现在被浏览的目录中，外壳就会解析其中的 IconFile/IconResource/IconIndex 等字段，
/// 对 UNC 路径自动发起 SMB/WebDAV 认证。文件常为 UTF-16LE 编码，先做 BOM 嗅探。
/// </summary>
public static class IniLikeParser
{
    public static ParsedFile Parse(byte[] bytes, DecoyKind kind, IReadOnlyDictionary<string, string[]> roleMap)
    {
        var result = new ParsedFile { Kind = kind };
        var text = DecodeText(bytes);
        if (text == null)
        {
            result.Error = "无法解码文本内容";
            result.Truncated = true;
            result.Add(ReferenceExtractor.SweepRawBytes(bytes));
            return result;
        }

        var rolesByKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (role, keys) in roleMap)
            foreach (var k in keys) rolesByKey[k] = role;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r');
            if (line.Length == 0 || line[0] is ';' or '#' or '[') continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length == 0) continue;

            var role = rolesByKey.TryGetValue(key, out var mapped) ? mapped : key;
            result.Add(ReferenceExtractor.Extract(value, role, DetectedEncoding(bytes)));
        }

        return result;
    }

    /// <summary>desktop.ini 关心的字段：图标、CLSID 目标、文件夹提示。</summary>
    public static readonly Dictionary<string, string[]> DesktopIniRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["IconLocation"] = new[] { "IconLocation", "IconFile", "IconResource" },
        ["FolderTarget"] = new[] { "CLSID", "Target" },
    };

    /// <summary>.url 关心的字段：目标 URL、图标 UNC。</summary>
    public static readonly Dictionary<string, string[]> UrlRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Url"] = new[] { "URL", "URL1", "URL2", "URL3", "URL4", "URL5", "URL6" },
        ["IconLocation"] = new[] { "IconFile", "IconIndex" },
        ["WorkingDirectory"] = new[] { "WorkingDirectory" },
    };

    /// <summary>.scf 关心的字段：Explorer 命令与图标 UNC（仅浏览目录即触发图标加载）。</summary>
    public static readonly Dictionary<string, string[]> ScfRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["IconLocation"] = new[] { "IconFile" },
        ["Command"] = new[] { "Command", "Task" },
    };

    private static string? DecodeText(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);

        // 无 BOM：UTF-16LE 启发式（大量可打印 ASCII 字符后紧跟 0x00）
        var zeroCount = 0;
        var limit = Math.Min(bytes.Length, 512);
        for (var i = 1; i < limit; i += 2) if (bytes[i] == 0) zeroCount++;
        if (limit >= 16 && zeroCount > limit / 4)
            return Encoding.Unicode.GetString(bytes);

        try { return Encoding.UTF8.GetString(bytes); }
        catch { return Encoding.Latin1.GetString(bytes); }
    }

    private static string DetectedEncoding(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) return "utf16";
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) return "utf16be";
        return bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? "utf8bom" : "ansi";
    }
}
