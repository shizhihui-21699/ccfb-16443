using Microsoft.Win32;

namespace TrapSweeper.Core.Policy;

/// <summary>真实 Windows 注册表适配器；非 Windows 上构造即抛异常（调用方应先判平台）。</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class WindowsRegistryStore : IRegistryStore
{
    private const string BackupSubKey = @"SOFTWARE\TrapSweeper\PolicyBackups";

    public WindowsRegistryStore()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("注册表操作仅支持 Windows");
    }

    public bool ValueExists(string keyPath, string valueName)
    {
        using var key = OpenMachineKey(keyPath, writable: false);
        return key?.GetValue(valueName) != null;
    }

    public object? GetValue(string keyPath, string valueName)
    {
        using var key = OpenMachineKey(keyPath, writable: false);
        return key?.GetValue(valueName);
    }

    public void SetDword(string keyPath, string valueName, int value)
    {
        using var key = OpenMachineKey(keyPath, writable: true)!;
        key.SetValue(valueName, value, RegistryValueKind.DWord);
    }

    public void SetString(string keyPath, string valueName, string value)
    {
        using var key = OpenMachineKey(keyPath, writable: true)!;
        key.SetValue(valueName, value, RegistryValueKind.String);
    }

    public void SetMultiString(string keyPath, string valueName, IEnumerable<string> values)
    {
        using var key = OpenMachineKey(keyPath, writable: true)!;
        key.SetValue(valueName, values.ToArray(), RegistryValueKind.MultiString);
    }

    public IEnumerable<string> EnumerateValueNames(string keyPath)
    {
        using var key = OpenMachineKey(keyPath, writable: false);
        return key?.GetValueNames() ?? Array.Empty<string>();
    }

    /// <summary>
    /// 备份：把目标键的全部值复制到 SOFTWARE\TrapSweeper\PolicyBackups\&lt;转义键路径&gt; 下，
    /// 同时导出 .reg 文本（regedit 可直接导回），避免依赖 reg.exe 的权限上下文。
    /// </summary>
    public void BackupKey(string keyPath, string backupFile)
    {
        using var source = OpenMachineKey(keyPath, writable: false);
        using var backupRoot = Registry.LocalMachine.CreateSubKey(BackupSubKey, writable: true);
        var escaped = keyPath.Replace('\\', '_');
        using var backup = backupRoot.CreateSubKey(escaped, writable: true);

        var lines = new List<string> { "Windows Registry Editor Version 5.00", "", $"[HKEY_LOCAL_MACHINE\\{keyPath.Replace('\\', '\\')}]" };
        if (source != null)
        {
            foreach (var name in source.GetValueNames())
            {
                var value = source.GetValue(name);
                var kind = source.GetValueKind(name);
                backup.SetValue(name, value!, kind);
                lines.Add(BuildRegLine(name, value, kind));
            }
        }
        File.WriteAllLines(backupFile, lines);
    }

    private static RegistryKey? OpenMachineKey(string subKey, bool writable) =>
        writable ? Registry.LocalMachine.CreateSubKey(subKey, writable: true) : Registry.LocalMachine.OpenSubKey(subKey, writable: false);

    private static string BuildRegLine(string name, object? value, RegistryValueKind kind)
    {
        var at = string.IsNullOrEmpty(name) ? "@" : $"\"{name}\"";
        return kind switch
        {
            RegistryValueKind.DWord => $"{at}=dword:{(int)value!:X8}",
            RegistryValueKind.String => $"{at}=\"{value}\"",
            RegistryValueKind.MultiString => $"{at}=multi_sz:{string.Join("\\0,", (string[])value!)}\\0",
            _ => $"{at}=\"{value}\""
        };
    }

    public void Dispose() { /* 每个操作的键均已 using 释放 */ }
}

/// <summary>内存假实现，供单元测试与非 Windows 平台的干跑(dry-run)使用。</summary>
public sealed class InMemoryRegistryStore : IRegistryStore
{
    public Dictionary<string, Dictionary<string, (object Value, RegValueKind Kind)>> Keys { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public List<string> BackupCalls { get; } = new();

    public bool ValueExists(string keyPath, string valueName) =>
        Keys.TryGetValue(keyPath, out var k) && k.ContainsKey(valueName);

    public object? GetValue(string keyPath, string valueName) =>
        Keys.TryGetValue(keyPath, out var k) && k.TryGetValue(valueName, out var v) ? v.Value : null;

    public void SetDword(string keyPath, string valueName, int value) => Put(keyPath, valueName, value, RegValueKind.DWord);
    public void SetString(string keyPath, string valueName, string value) => Put(keyPath, valueName, value, RegValueKind.String);

    public void SetMultiString(string keyPath, string valueName, IEnumerable<string> values) =>
        Put(keyPath, valueName, values.ToArray(), RegValueKind.MultiString);

    public IEnumerable<string> EnumerateValueNames(string keyPath) =>
        Keys.TryGetValue(keyPath, out var k) ? k.Keys : Array.Empty<string>();

    public void BackupKey(string keyPath, string backupFile) => BackupCalls.Add(keyPath);

    private void Put(string keyPath, string name, object value, RegValueKind kind)
    {
        if (!Keys.TryGetValue(keyPath, out var k))
        {
            k = new Dictionary<string, (object, RegValueKind)>(StringComparer.OrdinalIgnoreCase);
            Keys[keyPath] = k;
        }
        k[name] = (value, kind);
    }

    public void Dispose() { }
}
