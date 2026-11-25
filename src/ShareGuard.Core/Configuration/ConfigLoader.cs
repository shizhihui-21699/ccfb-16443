using System.Text.Json;
using ShareGuard.Core.Classification;

namespace ShareGuard.Core.Configuration;

/// <summary>白名单 JSON 配置加载与校验。</summary>
public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static async Task<AllowListConfig> LoadAsync(string path, CancellationToken ct = default)
    {
        await using var fs = File.OpenRead(path);
        var config = await JsonSerializer.DeserializeAsync<AllowListConfig>(fs, Options, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException($"配置文件 {path} 反序列化为空");

        Validate(config);
        Normalize(config);
        return config;
    }

    public static Task SaveSampleAsync(string path, CancellationToken ct = default)
    {
        var sample = new AllowListConfig
        {
            AllowedSuffixes = ["corp.example.com", "emea.corp.example.com"],
            AllowedHosts = ["dfs-root.corp.example.com", "filer-cluster.corp.example.com"],
            AllowedCidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
            AllowedSingleLabelNames = ["legacy-nas", "print01"],
            AllowedPorts = [445, 139, 80, 443],
            PendingReviewSuffixes = ["acquired-company.example"],
        };
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        return JsonSerializer.SerializeAsync(fs, sample, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        }, ct);
    }

    private static void Validate(AllowListConfig config)
    {
        foreach (var cidr in config.AllowedCidrs)
        {
            var parts = cidr.Split('/');
            if (!System.Net.IPAddress.TryParse(parts[0], out _))
                throw new InvalidDataException($"AllowedCidrs 中的 {cidr} 不是合法 CIDR");
            if (parts.Length > 1 && (!int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > 128))
                throw new InvalidDataException($"AllowedCidrs 中的 {cidr} 前缀长度非法");
        }
    }

    private static void Normalize(AllowListConfig config)
    {
        config.AllowedSuffixes = config.AllowedSuffixes
            .Select(s => s.TrimStart('.').TrimEnd('.').ToLowerInvariant()).ToList();
        config.AllowedHosts = config.AllowedHosts
            .Select(ReferenceParser.NormalizeHost).ToList();
        config.AllowedSingleLabelNames = config.AllowedSingleLabelNames
            .Select(h => h.TrimEnd('.').ToLowerInvariant()).ToList();
    }
}
