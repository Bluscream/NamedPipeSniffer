namespace NamedPipeSniffer;

/// <summary>
/// Interface for different methods of listing named pipes
/// </summary>
public interface IPipeLister
{
    /// <summary>
    /// Name of this listing method
    /// </summary>
    string MethodName { get; }

    /// <summary>
    /// Description of this listing method
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Get all named pipes on the system
    /// </summary>
    IEnumerable<NamedPipeInfo> GetPipes();
}
