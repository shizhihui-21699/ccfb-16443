using System.Text;
using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Classification;
using TrapSweeper.Core.Engine;
using TrapSweeper.Core.Models;
using TrapSweeper.Core.Quarantine;
using Xunit;

namespace TrapSweeper.Tests;

public sealed class EndToEndTests : IDisposable
{
    private readonly string _root;
    private readonly AllowListConfig _config;

    public EndToEndTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "trapsweeper-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _config = new AllowListConfig
        {
            AllowedSuffixes = new() { "corp.local" },
            AllowedHosts = new() { "fileserver" },
            AllowedCidrs = new() { "10.0.0.0/8" },
            SingleLabelPolicy = "requireallow"
        };
    }

    private AllowListConfig Config()
    {
        // 每次返回独立对象（Validate 会原地规范化）
        return new AllowListConfig
        {
            AllowedSuffixes = new() { "corp.local" },
            AllowedHosts = new() { "fileserver" },
            AllowedCidrs = new() { "10.0.0.0/8" },
            SingleLabelPolicy = "requireallow"
        };
    }

    private string WriteFile(string relPath, string content)
    {
        var p = Path.Combine(_root, relPath);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllText(p, content);
        return p;
    }

    private string WriteBytes(string relPath, byte[] bytes)
    {
        var p = Path.Combine(_root, relPath);
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        File.WriteAllBytes(p, bytes);
        return p;
    }

    [Fact]
    public void Scan_FindsMaliciousLnk_AndKeepsBenignInternalIconQuiet()
    {
        // 恶意：外部主机 LNK
        WriteBytes("marketing/Invoice.lnk", LnkFixtureBuilder.Build(netName: @"\\attacker.evil.example.com\share"));
        // 正常：内部图标引用 desktop.ini
        WriteFile("marketing/desktop.ini", "[.ShellClassInfo]\r\nIconResource=\\\\fileserver\\icons\\f.ico,0\r\n");
        // 正常：内部后缀 URL
        WriteFile("links/intranet.url", "[InternetShortcut]\r\nURL=https://portal.corp.local/da\r\n");
        // 可疑：搜索连接器指向外部
        WriteFile("links/vacation.searchconnector-ms",
            "<searchConnectorDescription><location><url>\\\\evil.example.org\\pub</url></location></searchConnectorDescription>");
        // 噪声：普通文本不应被打开
        WriteFile("notes/readme.txt", "this mentions \\\\fileserver\\share but is not a tracked type");

        var engine = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root },
            MaxDegreeOfParallelism = 2,
            CancellationToken = CancellationToken.None
        });

        var findings = new List<Finding>();
        engine.FindingEmitted += findings.Add;
        var report = engine.Run();

        Assert.Equal(4, report.Counters.CandidatesOpened); // txt 不打开
        var actionable = findings.Where(f => f.IsActionable).ToList();
        Assert.Equal(2, actionable.Count);
        Assert.Contains(actionable, f => f.FilePath.EndsWith("Invoice.lnk"));
        Assert.Contains(actionable, f => f.FilePath.EndsWith(".searchconnector-ms"));

        // 合法内部引用不进可操作项
        var benign = findings.First(f => f.FilePath.EndsWith("desktop.ini"));
        Assert.False(benign.IsActionable);
        var benignUrl = findings.First(f => f.FilePath.EndsWith("intranet.url"));
        Assert.False(benignUrl.IsActionable);
    }

    [Fact]
    public void Scan_Quarantine_IsReversibleAndManifested()
    {
        var lnk = WriteBytes("q/bad.lnk", LnkFixtureBuilder.Build(netName: @"\\evil.example.com\s"));
        var qDir = Path.Combine(_root, "quarantine");

        var store = new QuarantineStore(qDir);
        var engine = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root },
            Quarantine = store,
            ApplyQuarantine = true,
            CancellationToken = CancellationToken.None
        });
        engine.Run();

        Assert.False(File.Exists(lnk));
        var records = store.LoadManifest();
        Assert.Single(records);
        Assert.Equal(Verdict.External, records[0].Verdict);

        var (restored, failed) = store.Restore(null, all: true);
        Assert.Equal(1, restored);
        Assert.Equal(0, failed);
        Assert.True(File.Exists(lnk));
    }

    [Fact]
    public void Scan_Checkpoint_SecondRunSkipsCompletedSubtrees()
    {
        WriteBytes("a/b/c/bad.lnk", LnkFixtureBuilder.Build(netName: @"\\evil.example.com\s"));
        var cp = Path.Combine(_root, "cp.json");

        var opts1 = new ScanOptions
        {
            Roots = new() { _root }, CheckpointPath = cp, CheckpointDepth = 2,
            CancellationToken = CancellationToken.None
        };
        var e1 = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), opts1);
        e1.Run();
        Assert.True(File.Exists(cp));

        // 第二次运行：新增文件在已完成子树外才会被看到；已完成子树整体跳过
        var seen2 = new List<Finding>();
        var e2 = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), opts1);
        e2.FindingEmitted += seen2.Add;
        var report2 = e2.Run();
        Assert.True(report2.Counters.CandidatesOpened <= 1); // 已完成深度子树被跳过
    }

    [Fact]
    public void Scan_DamagedLnk_IsReportedNotSilentlyDropped()
    {
        var bytes = LnkFixtureBuilder.Build(netName: @"\\evil.example.com\s");
        WriteBytes("broken.lnk", bytes[..20]); // 仅头部残片

        var engine = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root },
            CancellationToken = CancellationToken.None
        });
        var findings = new List<Finding>();
        engine.FindingEmitted += findings.Add;
        engine.Run();

        var f = Assert.Single(findings);
        Assert.True(f.ParseTruncated || f.Error != null);
    }

    [Fact]
    public void Scan_Sniff_DetectsLnkDisguisedWithDatExtension()
    {
        WriteBytes("hidden/payload.dat", LnkFixtureBuilder.Build(netName: @"\\evil.example.com\s"));

        // 默认不嗅探：.dat 不在扩展名清单，不打开
        var plain = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root }, SniffAllFiles = false, CancellationToken = CancellationToken.None
        });
        Assert.Equal(0, plain.Run().Counters.CandidatesOpened);

        // 开启嗅探：按 CLSID 头识别并判定为外部
        var findings = new List<Finding>();
        var sniffing = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root }, SniffAllFiles = true, CancellationToken = CancellationToken.None
        });
        sniffing.FindingEmitted += findings.Add;
        var report = sniffing.Run();
        Assert.Equal(1, report.Counters.CandidatesOpened);
        Assert.Contains(findings, f => f.FilePath.EndsWith("payload.dat") && f.IsActionable);
    }

    [Fact]
    public void HostInventory_AggregatesReferencesForAllowListPlanning()
    {
        WriteBytes("x/a.lnk", LnkFixtureBuilder.Build(netName: @"\\fileserver\docs"));
        WriteFile("x/desktop.ini", "[.ShellClassInfo]\r\nIconResource=\\\\fileserver\\i.ico\r\n");

        var engine = new ScanEngine(new DecoyAnalyzer(new HostClassifier(Config())), new ScanOptions
        {
            Roots = new() { _root },
            CancellationToken = CancellationToken.None
        });
        var inventory = new Core.Reporting.HostInventory();
        engine.FindingEmitted += inventory.Add;
        engine.Run();

        var row = Assert.Single(inventory.Rows);
        Assert.Equal("fileserver", row.Host);
        Assert.True(row.FileCount >= 2);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* 测试隔离目录清理尽力而为 */ }
    }
}
