using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NamedPipeSniffer.Listers;

/// <summary>
/// Lists pipes by calling Sysinternals pipelist.exe and parsing output
/// </summary>
public class PipeListLister : IPipeLister
{
    private readonly string _pipeListPath;

    public string MethodName => "pipelist";
    public string Description => "Use Sysinternals pipelist.exe (requires pipelist.exe in PATH or same directory)";

    public PipeListLister(string? pipeListPath = null)
    {
        _pipeListPath = pipeListPath ?? "pipelist.exe";
    }

    public IEnumerable<NamedPipeInfo> GetPipes()
    {
        var pipes = new List<NamedPipeInfo>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _pipeListPath,
                Arguments = "-nobanner",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                Program.WriteColorLine($"Failed to start pipelist.exe", ConsoleColor.Red);
                return pipes;
            }

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                Program.WriteColorLine($"pipelist.exe failed with exit code {process.ExitCode}", ConsoleColor.Red);
                if (!string.IsNullOrEmpty(error))
                {
                    Program.WriteColorLine($"Error: {error}", ConsoleColor.Red);
                }
                return pipes;
            }

            // Parse output
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var headerPassed = false;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                
                // Skip until we pass the header separator
                if (trimmed.StartsWith("---"))
                {
                    headerPassed = true;
                    continue;
                }

                if (!headerPassed || string.IsNullOrWhiteSpace(trimmed))
                    continue;

                // Parse line format: "PipeName    Instances    MaxInstances"
                // Example: "InitShutdown                                      3               -1"
                var parts = Regex.Split(trimmed, @"\s{2,}");
                if (parts.Length >= 3)
                {
                    var name = parts[0].Trim();
                    var instances = parts[1].Trim();
                    var maxInstances = parts[2].Trim();

                    pipes.Add(new NamedPipeInfo
                    {
                        Name = name,
                        FullPath = $@"\\.\pipe\{name}",
                        CurrentInstances = int.TryParse(instances, out var curr) ? curr : -1,
                        MaxInstances = int.TryParse(maxInstances, out var max) ? max : -1
                    });
                }
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Program.WriteColorLine($"pipelist.exe not found. Please ensure it's in PATH or the same directory.", ConsoleColor.Red);
        }
        catch (Exception ex)
        {
            Program.WriteColorLine($"Error calling pipelist.exe: {ex.Message}", ConsoleColor.Red);
        }

        return pipes;
    }
}
