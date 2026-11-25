namespace TrapSweeper.Core.Policy;

/// <summary>
/// 注册表抽象，便于在非 Windows 上单元测试策略引擎。
/// 实现负责区分"键不存在"（未配置）与"值存在但不合规"。
/// </summary>
public interface IRegistryStore : IDisposable
{
    bool ValueExists(string keyPath, string valueName);
    object? GetValue(string keyPath, string valueName);
    void SetDword(string keyPath, string valueName, int value);
    void SetString(string keyPath, string valueName, string value);
    void SetMultiString(string keyPath, string valueName, IEnumerable<string> values);
    void BackupKey(string keyPath, string backupFile);
    IEnumerable<string> EnumerateValueNames(string keyPath);
}

public enum PolicyState { Compliant, NonCompliant, NotConfigured, NotApplicable }

/// <summary>平台无关的注册表值类型，避免内存实现依赖 Windows 专用枚举。</summary>
public enum RegValueKind { DWord, String, MultiString }

public sealed class PolicyCheck
{
    public string Id { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string RegistryKey { get; init; } = string.Empty;
    public string ValueName { get; init; } = string.Empty;
    public PolicyState State { get; set; }
    public string? CurrentValue { get; set; }
    public string ExpectedValue { get; init; } = string.Empty;
    public string Impact { get; init; } = string.Empty;
    public string Reference { get; init; } = string.Empty;
    public bool RequiresReboot { get; init; }
}

public sealed class PolicyBaselineResult
{
    public bool IsWindows { get; set; }
    public List<PolicyCheck> Checks { get; set; } = new();
    public int Compliant => Checks.Count(c => c.State == PolicyState.Compliant);
    public int NonCompliant => Checks.Count(c => c.State == PolicyState.NonCompliant);
    public int NotConfigured => Checks.Count(c => c.State == PolicyState.NotConfigured);
}
