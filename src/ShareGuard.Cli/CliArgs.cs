namespace ShareGuard.Cli;

/// <summary>极简命令行参数解析,避免外部依赖。支持 --key value、--flag、位置参数。</summary>
public sealed class CliArgs
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _positionals = new();

    public static CliArgs Parse(string[] args)
    {
        var result = new CliArgs();
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                var key = a[2..];
                var eq = key.IndexOf('=');
                if (eq >= 0)
                {
                    result._options[key[..eq]] = key[(eq + 1)..];
                    continue;
                }
                // 布尔标志:后面没有值,或下一个 token 仍是选项
                if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    result._options[key] = "true";
                }
                else
                {
                    result._options[key] = args[++i];
                }
            }
            else
            {
                result._positionals.Add(a);
            }
        }
        return result;
    }

    public string? Get(string key) =>
        _options.TryGetValue(key, out var v) ? v : null;

    public string GetOrDefault(string key, string fallback) =>
        _options.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v) ? v : fallback;

    public int GetInt(string key, int fallback) =>
        _options.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : fallback;

    public long GetLong(string key, long fallback) =>
        _options.TryGetValue(key, out var v) && long.TryParse(v, out var n) ? n : fallback;

    public bool HasFlag(string key) =>
        _options.TryGetValue(key, out var v) && v is not null &&
        (v == "true" || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<string> Positionals => _positionals;

    public string? Verb => _positionals.FirstOrDefault();
    public IReadOnlyList<string> RemainingPositionals => _positionals.Skip(1).ToList();
}
