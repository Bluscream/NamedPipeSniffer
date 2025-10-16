namespace NamedPipeSniffer;

/// <summary>
/// Information about a named pipe
/// </summary>
public class NamedPipeInfo
{
    /// <summary>
    /// Name of the pipe
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Number of current active instances (-1 if unknown)
    /// </summary>
    public int CurrentInstances { get; set; } = -1;

    /// <summary>
    /// Maximum number of instances allowed (-1 if unlimited/unknown)
    /// </summary>
    public int MaxInstances { get; set; } = -1;

    /// <summary>
    /// Security descriptor in SDDL format (if available)
    /// </summary>
    public string? SecurityDescriptor { get; set; }

    /// <summary>
    /// Full path to the pipe
    /// </summary>
    public string? FullPath { get; set; }

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    public override string ToString()
    {
        if (CurrentInstances >= 0 && MaxInstances >= 0)
        {
            return $"{Name} ({CurrentInstances}/{MaxInstances})";
        }
        return Name;
    }

    public string ToSection() {
        var sb = new StringBuilder();
        sb.AppendLine(name);
        sb.AppendLine($"\tFullPath: {FullPath}");
        sb.AppendLine($"\tCurrentInstances: {CurrentInstances}");
        sb.AppendLine($"\tMaxInstances: {MaxInstances}");
        sb.AppendLine($"\tSecurityDescriptor: {SecurityDescriptor}");
        return sb.ToString();
    }    

    public string ToCsvString(string d)
    {
        var name = pipe.Name?.Replace(d, "%3B") ?? "";
        var fullPath = pipe.FullPath?.Replace(d, "%3B") ?? "";
        var currentInstances = pipe.CurrentInstances >= 0 ? pipe.CurrentInstances.ToString() : "";
        var maxInstances = pipe.MaxInstances >= 0 ? pipe.MaxInstances.ToString() : "";
        var securityDescriptor = pipe.SecurityDescriptor?.Replace(d, "%3B") ?? "";
        return $"{Name}{d}{FullPath}{d}{CurrentInstances}{d}{MaxInstances}{d}{SecurityDescriptor}";
    }
}
