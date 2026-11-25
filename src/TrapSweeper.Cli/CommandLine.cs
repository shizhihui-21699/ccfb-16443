namespace TrapSweeper.Cli;

/// <summary>极简参数解析：--key value / --flag / 位置参数，零第三方依赖。</summary>
public sealed class CommandLine
{
    private readonly Dictionary<string, string?> _named = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Positional { get; } = new();

    public static CommandLine Parse(string[] args)
    {
        var cl = new CommandLine();
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                var key = a[2..];
                string? value = null;
                var eq = key.IndexOf('=');
                if (eq >= 0) { value = key[(eq + 1)..]; key = key[..eq]; }
                else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    value = args[++i];
                }
                cl._named[key] = value;
            }
            else
            {
                cl.Positional.Add(a);
            }
        }
        return cl;
    }

    public string? Get(string key) => _named.TryGetValue(key, out var v) ? v : null;

    public string Require(string key) =>
        _named.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v)
            ? v!
            : throw new ArgumentException($"缺少必需参数 --{key}");

    public bool Flag(string key) => _named.ContainsKey(key);

    public int GetInt(string key, int fallback) =>
        _named.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : fallback;

    public List<string> GetList(string key) =>
        _named.TryGetValue(key, out var v) && v != null
            ? v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
            : new();
}
