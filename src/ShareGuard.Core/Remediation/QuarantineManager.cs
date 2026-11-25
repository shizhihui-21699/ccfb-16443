using System.Text.Json;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Remediation;

/// <summary>
/// 处置动作。默认隔离而非删除:文件移动到隔离区并保留完整元数据,
/// 配合 manifest 支持一键恢复——白名单误报时业务可无损回滚。
/// </summary>
public enum RemediationAction
{
    /// <summary>只报告不动文件(默认,先审计后处置)。</summary>
    ReportOnly,

    /// <summary>移动到隔离区,原路径放一个说明占位(可选)。</summary>
    Quarantine,

    /// <summary>从隔离区恢复。</summary>
    Restore,
}

public sealed class QuarantineOptions
{
    /// <summary>隔离区根目录,建议放在与共享不同的卷并限制 ACL。</summary>
    public required string QuarantineRoot { get; init; }

    /// <summary>是否在原位置留占位说明文件(避免用户反复点击失效链接)。</summary>
    public bool LeavePlaceholder { get; init; } = true;

    /// <summary>仅处置该级别及以上的结果。</summary>
    public Severity MinimumSeverity { get; init; } = Severity.Malicious;
}

public sealed class QuarantineResult
{
    public required string OriginalPath { get; init; }
    public string? QuarantinedPath { get; init; }
    public bool Success { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// 隔离区布局:
///   &lt;root&gt;/files/&lt;yyyyMMdd&gt;/&lt;guid&gt;__&lt;原始文件名&gt;
///   &lt;root&gt;/manifest-&lt;yyyyMMdd&gt;.jsonl   每条处置一行,恢复的依据
/// </summary>
public sealed class QuarantineManager
{
    private readonly QuarantineOptions _options;
    private readonly SemaphoreSlim _manifestLock = new(1, 1);

    public QuarantineManager(QuarantineOptions options) => _options = options;

    public async Task<QuarantineResult> QuarantineAsync(AnalysisResult result, CancellationToken ct = default)
    {
        if (result.Severity < _options.MinimumSeverity)
        {
            return new QuarantineResult { OriginalPath = result.FilePath, Success = false, Error = "低于处置阈值,跳过" };
        }

        try
        {
            var day = DateTime.UtcNow.ToString("yyyyMMdd");
            var dir = Path.Combine(_options.QuarantineRoot, "files", day);
            Directory.CreateDirectory(dir);

            var safeName = Sanitize(Path.GetFileName(result.FilePath));
            var storedName = $"{Guid.NewGuid():N}__{safeName}";
            var storedPath = Path.Combine(dir, storedName);

            // 先复制后删除:移动跨卷会退化为复制+删除,显式写出来便于处理部分失败
            File.Copy(result.FilePath, storedPath, overwrite: false);
            TryCopyAlternateDataStreams(result.FilePath, storedPath);

            var manifestEntry = new ManifestEntry
            {
                TimestampUtc = DateTime.UtcNow,
                OriginalPath = result.FilePath,
                StoredPath = storedPath,
                FileType = result.FileType.ToString(),
                Severity = result.Severity.ToString(),
                Reasons = result.Reasons,
                OriginalSize = result.FileSize,
                OriginalLastWriteTimeUtc = result.LastWriteTimeUtc,
            };
            await AppendManifestAsync(manifestEntry, ct).ConfigureAwait(false);

            // 处理只读/系统属性
            var attrs = File.GetAttributes(result.FilePath);
            if (attrs.HasFlag(FileAttributes.ReadOnly))
                File.SetAttributes(result.FilePath, attrs & ~FileAttributes.ReadOnly);

            if (_options.LeavePlaceholder)
            {
                var placeholder = result.FilePath + ".shareguard-quarantined.txt";
                await File.WriteAllTextAsync(placeholder,
                    $"该文件因包含指向非信任地址的强制认证引用,已被 ShareGuard 隔离。\n" +
                    $"时间(UTC):{DateTime.UtcNow:O}\n风险级别:{result.Severity}\n" +
                    $"隔离位置:{storedPath}\n判定依据:\n{string.Join("\n", result.Reasons)}\n" +
                    $"如有异议请联系安全团队,凭 manifest 恢复。\n", ct).ConfigureAwait(false);
            }

            File.Delete(result.FilePath);

            return new QuarantineResult
            {
                OriginalPath = result.FilePath,
                QuarantinedPath = storedPath,
                Success = true,
            };
        }
        catch (Exception ex)
        {
            return new QuarantineResult { OriginalPath = result.FilePath, Success = false, Error = ex.Message };
        }
    }

    public async Task<QuarantineResult> RestoreAsync(string manifestPath, CancellationToken ct = default)
    {
        ManifestEntry? entry;
        await using (var fs = File.OpenRead(manifestPath))
        using (var doc = await JsonDocument.ParseAsync(fs, cancellationToken: ct).ConfigureAwait(false))
        {
            entry = JsonSerializer.Deserialize<ManifestEntry>(doc.RootElement.GetRawText());
        }
        if (entry is null)
            return new QuarantineResult { OriginalPath = manifestPath, Success = false, Error = "manifest 无法解析" };

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(entry.OriginalPath)!);
            File.Copy(entry.StoredPath, entry.OriginalPath, overwrite: true);
            File.SetLastWriteTimeUtc(entry.OriginalPath, entry.OriginalLastWriteTimeUtc);
            File.Delete(entry.OriginalPath + ".shareguard-quarantined.txt");

            entry.RestoredAtUtc = DateTime.UtcNow;
            await AppendManifestAsync(entry, ct).ConfigureAwait(false);
            return new QuarantineResult
            {
                OriginalPath = entry.OriginalPath,
                QuarantinedPath = entry.StoredPath,
                Success = true,
            };
        }
        catch (Exception ex)
        {
            return new QuarantineResult { OriginalPath = entry.OriginalPath, Success = false, Error = ex.Message };
        }
    }

    private async Task AppendManifestAsync(ManifestEntry entry, CancellationToken ct)
    {
        var day = DateTime.UtcNow.ToString("yyyyMMdd");
        var path = Path.Combine(_options.QuarantineRoot, $"manifest-{day}.jsonl");
        Directory.CreateDirectory(_options.QuarantineRoot);

        // 先在内存里拼出完整的一行(含结尾换行),再在锁内一次写入:
        // 扫描消费者并行调用本方法,无锁 append 会让多条 JSON 交错损坏;
        // 分两次写(序列化 + 手写 \n)在缓冲/中断场景下还可能留下截断行。
        var line = JsonSerializer.SerializeToUtf8Bytes(entry);
        await _manifestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            await fs.WriteAsync(line, ct).ConfigureAwait(false);
            await fs.WriteAsync("\n"u8.ToArray(), ct).ConfigureAwait(false);
            await fs.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _manifestLock.Release();
        }
    }

    /// <summary>
    /// ADS 处理:Windows 上 Zone.Identifier 等备用流可能携带攻击载荷线索,
    /// 一并备份到隔离区(以单独文件保存);非 Windows 平台无此概念,静默跳过。
    /// </summary>
    private static void TryCopyAlternateDataStreams(string original, string stored)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            foreach (var streamName in new[] { "Zone.Identifier" })
            {
                var adsPath = $"{original}:{streamName}";
                if (!File.Exists(adsPath)) continue;
                using var src = new FileStream(adsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var dst = File.Create($"{stored}.{Sanitize(streamName)}");
                src.CopyTo(dst);
            }
        }
        catch (IOException) { /* ADS 读取失败不阻断主流程 */ }
    }

    private static string Sanitize(string name) =>
        string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) || c == ':' ? '_' : c));

    public sealed class ManifestEntry
    {
        public DateTime TimestampUtc { get; set; }
        public string OriginalPath { get; set; } = "";
        public string StoredPath { get; set; } = "";
        public string FileType { get; set; } = "";
        public string Severity { get; set; } = "";
        public IReadOnlyList<string> Reasons { get; set; } = Array.Empty<string>();
        public long OriginalSize { get; set; }
        public DateTime OriginalLastWriteTimeUtc { get; set; }
        public DateTime? RestoredAtUtc { get; set; }
    }
}
