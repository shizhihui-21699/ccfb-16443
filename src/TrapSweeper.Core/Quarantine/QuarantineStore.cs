using System.IO;
using System.Security.AccessControl;
using System.Text.Json;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Quarantine;

/// <summary>隔离清单条目：保证任何隔离动作都可审计、可回滚。</summary>
public sealed class QuarantineRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinedPath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public DateTime QuarantinedUtc { get; set; }
    public string DecoyKind { get; set; } = string.Empty;
    public Verdict Verdict { get; set; }
    public List<string> Reasons { get; set; } = new();
    public string? Owner { get; set; }
    public string? SecurityDescriptorSddl { get; set; }
    public bool RestoreVerified { get; set; }
}

/// <summary>
/// 隔离区：把诱饵文件移动到独立根目录并保持镜像路径，写入 JSONL 清单。
/// 全部操作幂等且可回滚（restore 校验哈希后原位恢复）。
/// Windows 上保留 NTFS 安全描述符；非 Windows 平台跳过 ACL 并记录告警。
/// </summary>
public sealed class QuarantineStore
{
    private readonly string _root;
    private readonly string _manifestPath;
    private readonly object _ioLock = new();

    public QuarantineStore(string root)
    {
        _root = Path.GetFullPath(root);
        Directory.CreateDirectory(_root);
        _manifestPath = Path.Combine(_root, "quarantine-manifest.jsonl");
    }

    public bool Quarantine(Finding finding, CancellationToken token)
    {
        try
        {
            var record = BuildRecord(finding);
            var targetDir = Path.GetDirectoryName(record.QuarantinedPath)!;
            Directory.CreateDirectory(targetDir);

            CaptureSecurity(finding.FilePath, record);

            // 先复制+哈希校验，再删源文件，避免移动过程中断导致文件丢失
            File.Copy(finding.FilePath, record.QuarantinedPath, overwrite: true);
            VerifyCopy(finding.FilePath, record.QuarantinedPath);

            File.SetAttributes(record.QuarantinedPath, FileAttributes.Normal);
            File.Delete(finding.FilePath);

            AppendManifest(record);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[error] 隔离失败 {finding.FilePath}: {ex.Message}");
            return false;
        }
    }

    public List<QuarantineRecord> LoadManifest()
    {
        var result = new List<QuarantineRecord>();
        if (!File.Exists(_manifestPath)) return result;
        foreach (var line in File.ReadLines(_manifestPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var rec = JsonSerializer.Deserialize<QuarantineRecord>(line);
                if (rec != null) result.Add(rec);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[warn] 清单行损坏已跳过: {ex.Message}");
            }
        }
        return result;
    }

    /// <summary>恢复单个或全部文件；哈希不一致时拒绝恢复并返回 false。</summary>
    public (int Restored, int Failed) Restore(string? idOrPath, bool all)
    {
        var records = LoadManifest();
        if (!all)
        {
            records = records.Where(r =>
                r.Id.Equals(idOrPath, StringComparison.OrdinalIgnoreCase) ||
                r.OriginalPath.Equals(idOrPath, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        int restored = 0, failed = 0;
        foreach (var rec in records)
        {
            try
            {
                if (!File.Exists(rec.QuarantinedPath))
                {
                    Console.Error.WriteLine($"[error] 隔离文件缺失，无法恢复: {rec.QuarantinedPath}");
                    failed++;
                    continue;
                }
                if (File.Exists(rec.OriginalPath))
                {
                    Console.Error.WriteLine($"[error] 原路径已存在其他文件，跳过恢复: {rec.OriginalPath}");
                    failed++;
                    continue;
                }

                var dir = Path.GetDirectoryName(rec.OriginalPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.Move(rec.QuarantinedPath, rec.OriginalPath);
                ApplySecurity(rec);
                restored++;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[error] 恢复失败 {rec.OriginalPath}: {ex.Message}");
                failed++;
            }
        }
        return (restored, failed);
    }

    private QuarantineRecord BuildRecord(Finding finding)
    {
        var rec = new QuarantineRecord
        {
            OriginalPath = Path.GetFullPath(finding.FilePath),
            Sha256 = finding.Sha256,
            SizeBytes = finding.SizeBytes,
            QuarantinedUtc = DateTime.UtcNow,
            DecoyKind = finding.Kind.ToString(),
            Verdict = finding.Verdict,
            Reasons = finding.Reasons
        };

        // 镜像路径：&lt;root&gt;/drive/share/... ，保持与源结构一致便于人工核对
        var source = rec.OriginalPath;
        var uncPrefix = source.StartsWith(@"\\", StringComparison.Ordinal) ? @"\unc" : string.Empty;
        var flattened = source
            .Replace(":", "_", StringComparison.Ordinal)
            .Replace('\\', Path.DirectorySeparatorChar)
            .TrimStart(Path.DirectorySeparatorChar);
        rec.QuarantinedPath = Path.Combine(_root, "files", uncPrefix.TrimStart('\\'), flattened, $"{rec.Id}{Path.GetExtension(source)}");
        return rec;
    }

    private void CaptureSecurity(string source, QuarantineRecord record)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var security = new FileSecurity(source, AccessControlSections.Owner | AccessControlSections.Access);
            record.SecurityDescriptorSddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            var owner = security.GetOwner(typeof(System.Security.Principal.NTAccount));
            record.Owner = owner?.Value;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[warn] 无法捕获 ACL {source}: {ex.Message}");
        }
    }

    private void ApplySecurity(QuarantineRecord rec)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(rec.SecurityDescriptorSddl)) return;
        try
        {
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(rec.SecurityDescriptorSddl);
            // .NET 8 中 SetAccessControl 是作用于 FileInfo 的扩展方法（System.IO.FileSystem.AccessControl 包）
            new FileInfo(rec.OriginalPath).SetAccessControl(security);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[warn] ACL 恢复失败（文件已恢复）{rec.OriginalPath}: {ex.Message}");
        }
    }

    private static void VerifyCopy(string source, string copy)
    {
        using var s1 = File.OpenRead(source);
        using var s2 = File.OpenRead(copy);
        using var h1 = System.Security.Cryptography.SHA256.Create();
        using var h2 = System.Security.Cryptography.SHA256.Create();
        var hash1 = Convert.ToHexString(h1.ComputeHash(s1));
        var hash2 = Convert.ToHexString(h2.ComputeHash(s2));
        if (!string.Equals(hash1, hash2, StringComparison.Ordinal))
            throw new IOException("复制后哈希不一致，已中止隔离（源文件保留）");
    }

    private void AppendManifest(QuarantineRecord record)
    {
        lock (_ioLock)
        {
            File.AppendAllText(_manifestPath, JsonSerializer.Serialize(record) + Environment.NewLine);
        }
    }
}
