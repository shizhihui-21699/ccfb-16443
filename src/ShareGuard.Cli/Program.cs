using ShareGuard.Cli.Commands;
using ShareGuard.Core.Configuration;

namespace ShareGuard.Cli;

public static class Program
{
    public static async Task<int> Main(string[] argv)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var args = CliArgs.Parse(argv);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            return args.Verb switch
            {
                "scan" => await ScanCommand.RunAsync(args, cts.Token),
                "inspect" => await InspectCommand.RunAsync(args, cts.Token),
                "policy" => await PolicyCommand.RunAsync(args, cts.Token),
                "restore" => await RestoreCommand.RunAsync(args, cts.Token),
                "init-config" => await InitConfig(args, cts.Token),
                "version" => Version(),
                _ => Usage(),
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("已中断(检查点已保存,下次带相同 --checkpoint 参数可续扫)。");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[致命错误] {ex.GetType().Name}: {ex.Message}");
            if (args.HasFlag("verbose")) Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    private static async Task<int> InitConfig(CliArgs args, CancellationToken ct)
    {
        var path = args.RemainingPositionals.FirstOrDefault() ?? "allowlist.json";
        await ConfigLoader.SaveSampleAsync(path, ct);
        Console.WriteLine($"已写入示例白名单配置: {path}");
        Console.WriteLine("请结合 AD 站点、DFS 命名空间与资产台账填写后再用于扫描。");
        return 0;
    }

    private static int Version()
    {
        Console.WriteLine("ShareGuard 1.0.0 (.NET)");
        return 0;
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            ShareGuard — 共享目录强制认证诱饵检测与终端外发认证防护

            用法:
              shareguard init-config [allowlist.json]
                  生成白名单配置模板(企业后缀 / 文件服务器 / 内网网段)

              shareguard scan <共享目录...> --config allowlist.json [选项]
                  --jsonl <文件>          JSONL 明细输出(供 SIEM)
                  --csv <文件>            CSV 报告(供运营复核)
                  --checkpoint <文件>     断点续扫检查点
                  --parallelism <n>       解析并行度(默认 2*CPU)
                  --quarantine-dir <目录> 启用隔离(默认仅报告)
                  --quarantine-min-severity <Suspicious|Malicious>
                  --include-benign        报告中保留良性文件
                  --max-file-size <字节>  单文件解析上限

              shareguard inspect <文件> [--config allowlist.json]
                  单文件详细分析,输出全部引用与逐条判定依据

              shareguard policy <audit|gen-script|apply> --config allowlist.json [--out ps1]
                  audit      检查终端 LLMNR/mDNS/NetBIOS/WebClient/NTLM 外发/SMB 配置
                  gen-script 生成 PowerShell 加固脚本(GPO/MDM 下发,含回滚注释)
                  apply      本机直接应用(需管理员,试点使用)

            退出码: 0=无高危 1=发现高危或策略不合规 2=参数错误 3=平台不支持 130=中断
            """);
        return 2;
    }
}
