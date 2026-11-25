using System.Text;
using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Classification;
using TrapSweeper.Core.Engine;
using TrapSweeper.Core.Models;
using TrapSweeper.Core.Quarantine;
using TrapSweeper.Core.Reporting;

namespace TrapSweeper.Cli;

/// <summary>scan / learn 共用的扫描装配逻辑。</summary>
public static class ScanRunner
{
    public sealed class RunResult
    {
        public ScanReport Report { get; set; } = new();
        public HostInventory Inventory { get; set; } = new();
        public string? JsonlPath { get; set; }
        public string? CsvPath { get; set; }
        public string? HtmlPath { get; set; }
    }

    public static RunResult Run(CommandLine cl, bool learnOnly)
    {
        var roots = cl.GetList("roots");
        if (roots.Count == 0 && cl.Positional.Count > 0) roots = cl.Positional.ToList();
        if (roots.Count == 0) throw new ArgumentException("必须通过 --roots 或位置参数提供至少一个共享目录根");
        foreach (var r in roots)
        {
            if (!Directory.Exists(r)) throw new DirectoryNotFoundException($"根目录不存在或不可访问: {r}");
        }

        var configPath = cl.Require("config");
        var config = AllowListConfig.Load(configPath);
        var classifier = new HostClassifier(config);
        var analyzer = new DecoyAnalyzer(classifier);

        var outDir = cl.Get("out") ?? Path.Combine(Directory.GetCurrentDirectory(), "trapsweeper-output");
        Directory.CreateDirectory(outDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var jsonlPath = Path.Combine(outDir, $"findings-{stamp}.jsonl");
        var csvPath = Path.Combine(outDir, $"host-inventory-{stamp}.csv");
        var htmlPath = Path.Combine(outDir, $"report-{stamp}.html");

        QuarantineStore? store = null;
        var apply = cl.Flag("apply");
        if (apply)
        {
            var qRoot = cl.Get("quarantine-dir") ?? Path.Combine(outDir, "quarantine");
            store = new QuarantineStore(qRoot);
            Console.WriteLine($"[!] --apply 已启用：可操作发现项将被移动到隔离区 {qRoot}");
        }

        var options = new ScanOptions
        {
            Roots = roots,
            CheckpointPath = cl.Flag("resume") ? Path.Combine(outDir, "checkpoint.json") : null,
            MaxDegreeOfParallelism = cl.GetInt("threads", Math.Max(2, Environment.ProcessorCount - 1)),
            ChannelCapacity = cl.GetInt("queue", 2000),
            SniffAllFiles = cl.Flag("sniff"),
            FollowReparsePoints = cl.Flag("follow-reparse"),
            MaxFileSizeBytes = cl.GetInt("max-size-mb", 8) * 1024L * 1024L,
            CheckpointDepth = cl.GetInt("checkpoint-depth", 2),
            Quarantine = store,
            ApplyQuarantine = apply,
            ProgressInterval = TimeSpan.FromSeconds(cl.GetInt("progress-seconds", 5))
        };

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Console.Error.WriteLine("\n[!] 收到中断，正在落盘断点与结果…"); };
        options.CancellationToken = cts.Token;

        var engine = new ScanEngine(analyzer, options);
        var inventory = new HostInventory();
        using var jsonl = learnOnly ? null : new JsonlFindingWriter(jsonlPath);

        engine.FindingEmitted += finding =>
        {
            inventory.Add(finding);
            if (!learnOnly)
            {
                jsonl!.Write(finding);
                lock (engine)
                {
                    if (finding.IsActionable) ConsoleLine(finding);
                }
            }
        };
        options.ProgressCallback = counters =>
        {
            Console.Error.Write(
                $"\r[进度] 文件 {counters.FilesEnumerated:N0}  目录 {counters.DirectoriesVisited:N0}  " +
                $"候选 {counters.CandidatesOpened:N0}  可操作 {counters.FindingsActionable:N0}  " +
                $"拒绝访问 {counters.AccessDenied:N0}   ");
        };

        var report = engine.Run();
        report.ConfigPath = configPath;
        report.Roots = roots;
        report.ToolVersion = VersionInfo.Version;
        Console.Error.WriteLine();

        inventory.WriteCsv(csvPath);

        if (!learnOnly)
        {
            // 报告内联数据从 JSONL 回读（引擎不长期持有全部 Finding，控制内存）
            report.Findings = ReadBackFindings(jsonlPath);
            HtmlReport.Write(htmlPath, report);
        }

        return new RunResult
        {
            Report = report,
            Inventory = inventory,
            JsonlPath = learnOnly ? null : jsonlPath,
            CsvPath = csvPath,
            HtmlPath = learnOnly ? null : htmlPath
        };
    }

    private static List<Finding> ReadBackFindings(string jsonlPath)
    {
        var list = new List<Finding>();
        foreach (var line in File.ReadLines(jsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var f = System.Text.Json.JsonSerializer.Deserialize<Finding>(line);
                if (f != null) list.Add(f);
            }
            catch { /* 单行损坏不影响报告生成 */ }
        }
        return list;
    }

    private static void ConsoleLine(Finding f)
    {
        var sb = new StringBuilder();
        sb.Append('[').Append(f.Severity).Append('/').Append(f.Verdict).Append("] ");
        sb.Append(f.FilePath);
        var badHosts = string.Join(", ", f.HostVerdicts.Where(h => h.IsBad).Select(h => h.Host));
        if (badHosts.Length > 0) sb.Append("  -> ").Append(badHosts);
        Console.WriteLine(sb.ToString());
    }
}
