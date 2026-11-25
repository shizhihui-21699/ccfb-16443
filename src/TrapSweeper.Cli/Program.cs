using TrapSweeper.Cli;
using TrapSweeper.Core.Quarantine;

internal static class VersionInfo
{
    public const string Version = "1.0.0";
}

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        try
        {
            var cl = CommandLine.Parse(args[1..]);
            return command switch
            {
                "scan" => Scan(cl, learnOnly: false),
                "learn" => Scan(cl, learnOnly: true),
                "inspect" => InspectRunner.Run(cl),
                "quarantine" => Quarantine(cl),
                "policy" => PolicyRunner.Run(cl),
                _ => throw new ArgumentException($"未知命令: {command}")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[error] {ex.Message}");
            if (Environment.GetEnvironmentVariable("TRAPSWEEPER_DEBUG") == "1")
                Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static int Scan(CommandLine cl, bool learnOnly)
    {
        var result = ScanRunner.Run(cl, learnOnly);
        var c = result.Report.Counters;
        Console.WriteLine();
        Console.WriteLine("===== 扫描完成 =====");
        Console.WriteLine($"枚举文件: {c.FilesEnumerated:N0}  目录: {c.DirectoriesVisited:N0}  打开候选: {c.CandidatesOpened:N0}");
        Console.WriteLine($"发现总数: {c.FindingsTotal:N0}  可操作: {c.FindingsActionable:N0}  解析错误: {c.ParseErrors:N0}  拒绝访问: {c.AccessDenied:N0}");
        Console.WriteLine($"已隔离: {c.Quarantined:N0}（失败 {c.QuarantineFailures:N0}）");
        Console.WriteLine($"主机盘点(CSV): {result.CsvPath}");
        if (!learnOnly)
        {
            Console.WriteLine($"明细(JSONL): {result.JsonlPath}");
            Console.WriteLine($"HTML 报告: {result.HtmlPath}");
        }
        else
        {
            Console.WriteLine("learn 模式不产生判定报告：请依据主机盘点补充允许列表后再执行 scan。");
        }
        return 0;
    }

    private static int Quarantine(CommandLine cl)
    {
        var action = cl.Positional.ElementAtOrDefault(0)
                     ?? throw new ArgumentException("需要子动作: list | restore");
        var root = cl.Require("quarantine-dir");
        var store = new QuarantineStore(root);

        switch (action.ToLowerInvariant())
        {
            case "list":
                foreach (var rec in store.LoadManifest())
                {
                    Console.WriteLine($"{rec.Id}  [{rec.Verdict}] {rec.DecoyKind}  {rec.OriginalPath}");
                    Console.WriteLine($"    -> {rec.QuarantinedPath}  ({rec.QuarantinedUtc:u})");
                }
                return 0;
            case "restore":
                var all = cl.Flag("all");
                var key = cl.Get("id") ?? cl.Get("path");
                if (!all && key == null)
                    throw new ArgumentException("restore 需要 --all 或 --id/--path 指定条目");
                var (restored, failed) = store.Restore(key, all);
                Console.WriteLine($"恢复完成: 成功 {restored}，失败 {failed}");
                return failed == 0 ? 0 : 3;
            default:
                throw new ArgumentException($"未知隔离动作: {action}");
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"""
TrapSweeper v{VersionInfo.Version} — 共享目录强制认证诱饵检测与终端外发认证收敛工具

用法: trapsweeper <command> [options]

命令:
  scan        扫描共享目录中的强制认证诱饵文件（默认仅审计，不改文件）
  learn       只盘点被引用主机并输出 CSV，用于编制允许列表（不产生判定）
  inspect     深度解析单个文件，输出全部引用与判定证据（退出码 2=可操作）
  quarantine  隔离区管理: list | restore --all | restore --id <id>
  policy      终端策略: audit | apply | export-reg | export-firewall

scan/learn 选项:
  --roots <dir,...>          共享目录根，可多个（也可用位置参数）
  --config <file>            允许列表 JSON 配置（必需）
  --out <dir>                输出目录（默认 ./trapsweeper-output）
  --threads <n>              解析消费者并行度（默认 CPU-1）
  --queue <n>                有界通道容量（默认 2000）
  --sniff                    对伪装后缀文件按 ShellLink CLSID 头嗅探
  --follow-reparse           跟随挂载点/符号链接（默认跳过，防循环越界）
  --max-size-mb <n>          单文件大小上限（默认 8）
  --resume                   启用断点续扫（检查点存于输出目录）
  --checkpoint-depth <n>     断点记录的目录深度（默认 2）
  --apply                    真正隔离可操作发现项（默认 dry-run，仅审计）
  --quarantine-dir <dir>     隔离区根目录（默认输出目录下 quarantine/）
  --progress-seconds <n>     进度刷新间隔（默认 5）

policy 选项:
  --profile <audit|balanced|strict>   基线档位（默认 balanced）
  --force                              apply 时真正写入注册表（默认 dry-run）
  --ntlm-exceptions <host,...>        NTLM 出站阻断的例外文件服务器清单
  --internal-cidrs <cidr,...>         防火墙脚本放行的内部网段
  --out <dir>                          .reg/.ps1/备份输出目录

示例:
  # 1) 先盘点环境，编制允许列表
  trapsweeper learn --roots \\fs01\share,\\fs02\share --config allowlist.json
  # 2) 审计扫描（不动任何文件）
  trapsweeper scan --roots \\fs01\share --config allowlist.json
  # 3) 试点隔离
  trapsweeper scan --roots \\fs01\share --config allowlist.json --apply --quarantine-dir D:\trap-q
  # 4) 终端策略先审计再应用
  trapsweeper policy audit --profile balanced
  trapsweeper policy apply --profile balanced --ntlm-exceptions nas01.corp.local,print01 --force
  trapsweeper policy export-firewall --internal-cidrs 10.0.0.0/8,172.16.0.0/12
""");
    }
}
