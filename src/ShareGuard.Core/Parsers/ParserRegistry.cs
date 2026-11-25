using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>按扩展名分发解析器;desktop.ini 这种无固定扩展名的按文件名匹配。</summary>
public sealed class ParserRegistry
{
    private readonly Dictionary<string, IBaitParser> _byExtension =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IBaitParser> _byFileName =
        new(StringComparer.OrdinalIgnoreCase);

    public ParserRegistry(IEnumerable<IBaitParser>? parsers = null)
    {
        foreach (var parser in parsers ?? CreateDefault())
        {
            foreach (var ext in parser.Extensions)
                _byExtension.TryAdd(ext, parser);
        }

        // desktop.ini 没有独立扩展名,按完整文件名注册
        var desktop = new DesktopIniParser();
        _byFileName["desktop.ini"] = desktop;
    }

    public static IReadOnlyList<IBaitParser> CreateDefault() =>
    [
        new LnkParser(),
        new ScfParser(),
        new UrlParser(),
        new SearchConnectorParser(),
    ];

    public bool IsCandidate(string fileName)
    {
        if (_byFileName.ContainsKey(fileName)) return true;
        var ext = Path.GetExtension(fileName);
        return ext.Length > 0 && _byExtension.ContainsKey(ext);
    }

    public IBaitParser? Resolve(string fileName)
    {
        if (_byFileName.TryGetValue(fileName, out var byName)) return byName;
        var ext = Path.GetExtension(fileName);
        return ext.Length > 0 ? _byExtension.GetValueOrDefault(ext) : null;
    }
}
