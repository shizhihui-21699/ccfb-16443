using System.Text.Json;

namespace TrapSweeper.Core.Engine;

/// <summary>
/// 断点续扫存储。记录"相对根达到指定深度、且已完整枚举成功"的目录集合。
/// 重扫时整棵子树跳过——深度取 2 是折中：顶层目录通常巨大，太浅记录不了多少进度，
/// 太深则检查点文件本身膨胀。检查点按根分文件，损坏时丢弃该根的进度而不是中断扫描。
/// </summary>
public sealed class CheckpointStore
{
    private readonly string? _path;
    private readonly int _depth;
    private readonly Dictionary<string, HashSet<string>> _completedByRoot = new(StringComparer.OrdinalIgnoreCase);
    private bool _dirty;

    public CheckpointStore(string? path, int depth)
    {
        _path = path;
        _depth = depth;
        if (path == null || !File.Exists(path)) return;

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var el in prop.Value.EnumerateArray())
                {
                    var s = el.GetString();
                    if (s != null) set.Add(s);
                }
                _completedByRoot[prop.Name] = set;
            }
        }
        catch (Exception ex)
        {
            // 检查点损坏不致命：从头扫该根，保证正确性优先
            Console.Error.WriteLine($"[warn] 检查点文件损坏，将忽略已有进度: {ex.Message}");
            _completedByRoot.Clear();
        }
    }

    public bool IsComplete(string root, string dir)
    {
        if (_path == null) return false;
        return _completedByRoot.TryGetValue(NormalizeRoot(root), out var set) && set.Contains(dir);
    }

    public void MarkComplete(string root, string dir)
    {
        if (_path == null) return;
        var key = NormalizeRoot(root);
        if (!_completedByRoot.TryGetValue(key, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _completedByRoot[key] = set;
        }
        if (set.Add(dir)) _dirty = true;
    }

    public void Flush()
    {
        if (_path == null || !_dirty) return;
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = _path + ".tmp";
            using (var fs = File.Create(tmp))
            using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = false }))
            {
                w.WriteStartObject();
                foreach (var (root, set) in _completedByRoot)
                {
                    w.WritePropertyName(root);
                    w.WriteStartArray();
                    foreach (var d in set) w.WriteStringValue(d);
                    w.WriteEndArray();
                }
                w.WriteEndObject();
            }
            File.Move(tmp, _path, overwrite: true);
            _dirty = false;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[warn] 检查点写入失败: {ex.Message}");
        }
    }

    private static string NormalizeRoot(string root) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)).ToLowerInvariant();
}
