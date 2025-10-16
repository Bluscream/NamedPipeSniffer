namespace NamedPipeSniffer.Listers;

/// <summary>
/// Lists pipes using Directory.GetFiles (simple but limited metadata)
/// </summary>
public class DirectoryLister : IPipeLister
{
    public string MethodName => "directory";
    public string Description => "Use Directory.GetFiles (fast, limited metadata)";

    public IEnumerable<NamedPipeInfo> GetPipes()
    {
        var pipes = new List<NamedPipeInfo>();
        
        try
        {
            var files = Directory.GetFiles(@"\\.\pipe\");
            foreach (var file in files)
            {
                var name = Path.GetFileName(file);
                if (name != null)
                {
                    pipes.Add(new NamedPipeInfo
                    {
                        Name = name,
                        FullPath = file
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Program.WriteColorLine($"Error listing pipes: {ex.Message}", ConsoleColor.Red);
        }
        
        return pipes;
    }
}
