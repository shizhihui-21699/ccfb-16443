using ShareGuard.Core.Configuration;
using ShareGuard.Core.Engine;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;
using ShareGuard.Core.Remediation;
using ShareGuard.Core.Reporting;
using ShareGuard.Core.Classification;

namespace ShareGuard.Cli.Commands;

/// <summary>
/// scan:扫描共享目录,输出 JSONL/CSV 报告。默认只报告不处置。
/// </summary>
public static class ScanCommand
{
    public static async Task<int> RunAsync(CliArgs args, CancellationToken ct)
    {
        var roots = args.RemainingPositionals;
        if (roots.Count == 0)
        {
            Console.Error.WriteLine("用法: shareguard scan <共享目录1> [共享目录2 ...] --config allowlist.json [选项]");
            return 2;
        }

        var configPath = args.Get("config");
        var config = configPath != null
            ? await ConfigLoader.LoadAsync(configPath, ct)
            : AllowListConfig.Default;
        if (configPath == null)
            Console.Error.WriteLine("[警告] 未提供 --config,使用内置默认(仅 RFC1918 内网网段),误报率会偏高。");

        var classifier = new HostClassifier(config);
        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, classifier, args.GetLong("max-file-size", 16 * 1024 * 1024));

        var options = new ScanOptions
        {
            Roots = roots,
            Parallelism = args.GetInt("parallelism", Math.Max(2, Environment.ProcessorCount * 2)),
            QueueCapacity = args.GetInt("queue", 4096),
            CheckpointPath = args.Get("checkpoint"),
            OnlyReportFindings = !args.HasFlag("include-benign"),
        };

        var jsonlPath = args.Get("jsonl");
        var csvPath = args.Get("csv");
        using var jsonl = jsonlPath != null ? new JsonlReportWriter(jsonlPath) : null;
        using var csv = csvPath != null ? new CsvReportWriter(csvPath) : null;

        var quarantineDir = args.Get("quarantine-dir");
        var quarantine = quarantineDir != null
            ? new QuarantineManager(new QuarantineOptions
            {
                QuarantineRoot = quarantineDir,
                MinimumSeverity = ParseSeverity(args.GetOrDefault("quarantine-min-severity", "Malicious")),
            })
            : null;

        if (quarantine != null)
            Console.Error.WriteLine("[注意] 已启用隔离模式,Malicious 及以上文件将被移动(可凭 manifest 恢复)。");

        var findings = 0;
        Action<AnalysisResult> onResult = result =>
        {
            Interlocked.Increment(ref findings);
            // 同步写入:扫描消费者线程直接调用,回调完成即落盘,不依赖同步上下文
            jsonl?.Write(result);
            csv?.Write(result);
            if (quarantine != null && result.Severity >= QuarantineSeverity(args))
            {
                var qr = quarantine.QuarantineAsync(result, ct).GetAwaiter().GetResult();
                Console.Error.WriteLine(qr.Success
                    ? $"[隔离] {result.FilePath} -> {qr.QuarantinedPath}"
                    : $"[隔离失败] {result.FilePath}: {qr.Error}");
            }
            Console.WriteLine(FormatLine(result));
        };

        Action<string> onMessage = m => Console.Error.WriteLine($"[进度] {m}");
        var scanner = new Scanner(analyzer, parsers);

        Console.Error.WriteLine($"开始扫描 {roots.Count} 个根,并行度 {options.Parallelism} ...");
        var stats = await scanner.ScanAsync(options, onResult, onMessage, ct);

        Console.Error.WriteLine();
        Console.Error.WriteLine("========== 扫描汇总 ==========");
        Console.Error.WriteLine($"目录数:        {stats.DirectoriesVisited:N0}");
        Console.Error.WriteLine($"文件总数:      {stats.FilesEnumerated:N0}");
        Console.Error.WriteLine($"候选诱饵文件:  {stats.CandidateFiles:N0}");
        Console.Error.WriteLine($"已分析:        {stats.FilesAnalyzed:N0}");
        Console.Error.WriteLine($"  Benign:      {stats.Benign:N0}");
        Console.Error.WriteLine($"  Suspicious:  {stats.Suspicious:N0}");
        Console.Error.WriteLine($"  Malicious:   {stats.Malicious:N0}");
        Console.Error.WriteLine($"解析错误:      {stats.ParseErrors:N0}");
        Console.Error.WriteLine($"访问错误:      {stats.AccessErrors:N0}");
        if (jsonlPath != null) Console.Error.WriteLine($"JSONL 报告:    {jsonlPath}");
        if (csvPath != null) Console.Error.WriteLine($"CSV 报告:      {csvPath}");
        if (options.CheckpointPath != null) Console.Error.WriteLine($"检查点:        {options.CheckpointPath}");

        return stats.Malicious > 0 ? 1 : 0;
    }

    private static Severity QuarantineSeverity(CliArgs args) =>
        ParseSeverity(args.GetOrDefault("quarantine-min-severity", "Malicious"));

    private static Severity ParseSeverity(string value) =>
        Enum.TryParse<Severity>(value, ignoreCase: true, out var s) ? s : Severity.Malicious;

    private static string FormatLine(AnalysisResult r)
    {
        var hosts = string.Join(",", r.References.Where(x => x.Host != null)
            .Select(x => x.Host).Distinct());
        return $"[{r.Severity}] {r.FileType} {r.FilePath}" +
               (hosts.Length > 0 ? $"  -> {hosts}" : "");
    }
}
