using ShareGuard.Core.Models;
using ShareGuard.Core.Remediation;

namespace ShareGuard.Cli.Commands;

/// <summary>
/// restore:按 manifest 条目恢复被隔离文件。
/// 支持传单个 manifest JSONL(恢复其中全部条目)或隔离区根目录(恢复全部日期)。
/// </summary>
public static class RestoreCommand
{
    public static async Task<int> RunAsync(CliArgs args, CancellationToken ct)
    {
        var target = args.RemainingPositionals.FirstOrDefault();
        if (target == null)
        {
            Console.Error.WriteLine("用法: shareguard restore <manifest.jsonl | 隔离区根目录>");
            return 2;
        }

        var manifests = new List<string>();
        if (Directory.Exists(target))
        {
            manifests.AddRange(Directory.GetFiles(target, "manifest-*.jsonl"));
        }
        else if (File.Exists(target))
        {
            manifests.Add(target);
        }
        else
        {
            Console.Error.WriteLine($"找不到 {target}");
            return 2;
        }

        if (manifests.Count == 0)
        {
            Console.Error.WriteLine("未发现 manifest 文件。");
            return 1;
        }

        // QuarantineRoot 仅用于构造 manager,恢复路径完全取自 manifest
        var manager = new QuarantineManager(new QuarantineOptions { QuarantineRoot = Path.GetDirectoryName(manifests[0])! });
        var ok = 0;
        var failed = 0;

        foreach (var manifest in manifests)
        {
            // 一个 manifest 里可能有多条记录,逐行处理(RestoreAsync 接受单条目文件,
            // 这里把每行拆成临时条目再调用核心恢复逻辑)
            await foreach (var line in File.ReadLinesAsync(manifest, ct))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var entry = System.Text.Json.JsonSerializer.Deserialize<QuarantineManager.ManifestEntry>(line);
                if (entry is null || entry.RestoredAtUtc != null) continue;

                var single = Path.GetTempFileName();
                try
                {
                    await File.WriteAllTextAsync(single, line, ct);
                    var result = await manager.RestoreAsync(single, ct);
                    if (result.Success)
                    {
                        ok++;
                        Console.WriteLine($"[恢复] {result.OriginalPath}");
                    }
                    else
                    {
                        failed++;
                        Console.Error.WriteLine($"[恢复失败] {entry.OriginalPath}: {result.Error}");
                    }
                }
                finally
                {
                    File.Delete(single);
                }
            }
        }

        Console.Error.WriteLine($"恢复完成:成功 {ok},失败 {failed}。");
        return failed == 0 ? 0 : 1;
    }
}
