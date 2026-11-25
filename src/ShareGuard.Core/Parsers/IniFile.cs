using System.Text;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// 极简 Windows INI 解析器:只做 section/key=value 提取,
/// 容忍无 BOM 的 UTF-16LE(.url 文件常见)与 UTF-8。
/// </summary>
public sealed class IniFile
{
    public IReadOnlyDictionary<string, string> Global => _global;
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Sections => _sections;

    private readonly Dictionary<string, string> _global = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IReadOnlyDictionary<string, string>> _sections =
        new(StringComparer.OrdinalIgnoreCase);

    public static IniFile Parse(byte[] content)
    {
        var text = Decode(content);
        var ini = new IniFile();
        var current = "_global";
        var sectionMap = ini._global;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                current = line[1..^1].Trim();
                if (!ini._sections.TryGetValue(current, out var existing))
                {
                    var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    ini._sections[current] = dict;
                    sectionMap = dict;
                }
                else
                {
                    sectionMap = (Dictionary<string, string>)existing;
                }
                continue;
            }

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            sectionMap[key] = value;
        }

        return ini;
    }

    /// <summary>在所有 section 中查找键(取第一个匹配)。</summary>
    public bool TryFind(string key, out string value)
    {
        if (_global.TryGetValue(key, out value!)) return true;
        foreach (var section in _sections.Values)
        {
            if (section.TryGetValue(key, out value!)) return true;
        }
        value = string.Empty;
        return false;
    }

    public IEnumerable<(string Section, string Key, string Value)> EnumerateEntries()
    {
        foreach (var (k, v) in _global) yield return ("_global", k, v);
        foreach (var (section, kv) in _sections)
        foreach (var (k, v) in kv)
            yield return (section, k, v);
    }

    private static string Decode(byte[] content)
    {
        // BOM 探测
        if (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
            return Encoding.UTF8.GetString(content, 3, content.Length - 3);
        if (content.Length >= 2 && content[0] == 0xFF && content[1] == 0xFE)
            return Encoding.Unicode.GetString(content, 2, content.Length - 2);
        if (content.Length >= 2 && content[0] == 0xFE && content[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(content, 2, content.Length - 2);

        // 无 BOM:若前 512 字节中出现大量 \0,按 UTF-16LE 处理
        var probe = Math.Min(content.Length, 512);
        var zeros = 0;
        for (var i = 0; i < probe; i++) if (content[i] == 0) zeros++;
        if (zeros > probe / 4)
            return Encoding.Unicode.GetString(content);

        return Encoding.UTF8.GetString(content);
    }
}
