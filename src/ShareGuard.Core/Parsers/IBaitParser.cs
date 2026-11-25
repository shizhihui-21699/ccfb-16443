using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>诱饵文件解析器:从特定类型文件中提取全部可触发认证的外部引用。</summary>
public interface IBaitParser
{
    BaitFileType FileType { get; }

    /// <summary>该解析器处理的扩展名(小写,含点)。</summary>
    IReadOnlySet<string> Extensions { get; }

    /// <summary>解析文件内容,返回提取到的引用。解析失败应抛 <see cref="BaitParseException"/>。</summary>
    IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content);
}

public sealed class BaitParseException : Exception
{
    public BaitParseException(string message) : base(message) { }
    public BaitParseException(string message, Exception inner) : base(message, inner) { }
}
