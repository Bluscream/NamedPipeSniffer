using System.CommandLine;
using System.IO.Pipes;
using System.Text;
using DotNet.Globbing;
using NamedPipeSniffer.Listers;

namespace NamedPipeSniffer;

class Program
{
    private static readonly object ConsoleLock = new();
    private static readonly Dictionary<string, PipeMonitor> ActiveMonitors = new();
    private static List<Glob> FilterGlobs = new();
    private static bool IsRunning = true;
    private static int MonitorIntervalMs = 1000;
    internal static bool NoErrors = false;
    internal static bool NoLog = false;
    private static IPipeLister PipeLister = new DirectoryLister();

    static async Task<int> Main(string[] args)
    {
        var patternsOption = new Option<string[]>(
            aliases: new[] { "--pattern", "-p" },
            description: "Glob patterns to filter pipes (e.g., -p *mojo* -p *chrome*)",
            getDefaultValue: () => new[] { "*" })
        {
            AllowMultipleArgumentsPerToken = false
        };

        var intervalOption = new Option<int>(
            aliases: new[] { "--interval", "-i" },
            description: "Pipe scan interval in milliseconds",
            getDefaultValue: () => 1000);

        var noEventsOption = new Option<bool>(
            aliases: new[] { "--no-events", "-ne" },
            description: "Don't show when pipes are added or removed");

        var noMessagesOption = new Option<bool>(
            aliases: new[] { "--no-messages", "-nm" },
            description: "Don't connect to pipes or read messages (list mode only)");

        var listOption = new Option<bool>(
            aliases: new[] { "--list", "-l" },
            description: "List matching pipes and exit (don't monitor)");

        var verboseOption = new Option<bool>(
            aliases: new[] { "--verbose", "-v" },
            description: "Show verbose output (startup info, filter details, etc.)");

        var methodOption = new Option<string>(
            aliases: new[] { "--method", "-m" },
            description: "Pipe listing method: directory (default), native (NtQueryDirectoryFile), pipelist (Sysinternals)",
            getDefaultValue: () => "directory");

        var csvOption = new Option<bool>(
            aliases: new[] { "--csv", "-c" },
            description: "Output in CSV format");

        var noErrorsOption = new Option<bool>(
            aliases: new[] { "--no-errors", "-nx" },
            description: "Hide connection errors (timeout, access denied, etc.)");

        var noLogOption = new Option<bool>(
            aliases: new[] { "--no-log", "-nl" },
            description: "Hide connection and disconnection messages");

        var rootCommand = new RootCommand("Monitor and sniff Windows Named Pipes.\n\n" +
            "NOTES:\n" +
            "  - Named pipes are point-to-point communication channels\n" +
            "  - Only pipes that accept client connections can be monitored\n" +
            "  - Data read from a pipe is consumed (not true passive sniffing)\n" +
            "  - Some pipes may reject connections due to permissions")
        {
            patternsOption,
            intervalOption,
            noEventsOption,
            noMessagesOption,
            listOption,
            verboseOption,
            methodOption,
            csvOption,
            noErrorsOption,
            noLogOption
        };

        rootCommand.SetHandler(async (context) =>
        {
            var patterns = context.ParseResult.GetValueForOption(patternsOption);
            var interval = context.ParseResult.GetValueForOption(intervalOption);
            var noEvents = context.ParseResult.GetValueForOption(noEventsOption);
            var noMessages = context.ParseResult.GetValueForOption(noMessagesOption);
            var listOnly = context.ParseResult.GetValueForOption(listOption);
            var verbose = context.ParseResult.GetValueForOption(verboseOption);
            var method = context.ParseResult.GetValueForOption(methodOption);
            var csv = context.ParseResult.GetValueForOption(csvOption);
            var noErrors = context.ParseResult.GetValueForOption(noErrorsOption);
            var noLog = context.ParseResult.GetValueForOption(noLogOption);
            
            await RunMonitorAsync(patterns!, interval, noEvents, noMessages, listOnly, verbose, method!, csv, noErrors, noLog);
        });

        return await rootCommand.InvokeAsync(args);
    }

    static async Task RunMonitorAsync(string[] patterns, int interval, bool noEvents, bool noMessages, bool listOnly, bool verbose, string method, bool csv, bool noErrors, bool noLog)
    {
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            IsRunning = false;
        };

        // Select the pipe lister based on method
        PipeLister = method.ToLowerInvariant() switch
        {
            "native" => new NativeLister(),
            "pipelist" => new PipeListLister(),
            _ => new DirectoryLister()
        };

        if (verbose)
        {
            WriteColorLine($"Using method: {PipeLister.MethodName} - {PipeLister.Description}", ConsoleColor.Gray);
        }

        MonitorIntervalMs = interval;
        NoErrors = noErrors;
        NoLog = noLog;
        FilterGlobs = patterns.Select(p => Glob.Parse(p, new GlobOptions { Evaluation = { CaseInsensitive = true } })).ToList();

        // Show header only in verbose mode or list mode
        if (verbose)
        {
            WriteColorLine($"NamedPipeSniffer - Monitoring named pipes on {Environment.MachineName}", ConsoleColor.Cyan);
            WriteColorLine($"Filter patterns: {string.Join(", ", patterns)}", ConsoleColor.Gray);
        }

        // Get initial pipe listing
        var initialPipes = GetFilteredPipes();

        // Show mode info only in verbose mode
        if (verbose)
        {
            if (noEvents)
            {
                WriteColorLine("Mode: Events disabled", ConsoleColor.Gray);
            }
            if (noMessages)
            {
                WriteColorLine("Mode: Message monitoring disabled (list only)", ConsoleColor.Gray);
            }
            WriteColorLine("Press Ctrl+C to exit\n", ConsoleColor.Gray);
            Console.WriteLine();
            WriteColorLine($"Found {initialPipes.Count} pipe(s) matching filter", ConsoleColor.Yellow);
            Console.WriteLine();
        }

        // List mode or verbose: show the full list
        if (listOnly)
        {
            foreach (var pipe in initialPipes.OrderBy(p => p.Name))
            {
                if (csv) Console.WriteLine(pipe.ToCsvString(";"));
                else Console.WriteLine(pipe.ToSection());
            }
            return;
        }

        // Start monitoring
        var monitorTask = MonitorPipesAsync(noEvents, noMessages);

        await monitorTask;

        // Cleanup
        foreach (var monitor in ActiveMonitors.Values)
        {
            monitor.Dispose();
        }

        if (verbose)
        {
            WriteColorLine("\nShutdown complete.", ConsoleColor.Cyan);
        }
    }

    static List<NamedPipeInfo> GetFilteredPipes()
    {
        try
        {
            var allPipes = PipeLister.GetPipes().ToList();

            var filtered = new Dictionary<string, NamedPipeInfo>();
            foreach (var glob in FilterGlobs)
            {
                foreach (var pipe in allPipes)
                {
                    if (glob.IsMatch(pipe.Name))
                    {
                        filtered[pipe.Name] = pipe;
                    }
                }
            }

            return filtered.Values.ToList();
        }
        catch (Exception ex)
        {
            WriteColorLine($"Error enumerating pipes: {ex.Message}", ConsoleColor.Red);
            return new List<NamedPipeInfo>();
        }
    }

    static async Task MonitorPipesAsync(bool noEvents, bool noMessages)
    {
        var previousPipes = new HashSet<string>();

        while (IsRunning)
        {
            try
            {
                var currentPipeInfos = GetFilteredPipes();
                var currentPipes = currentPipeInfos.Select(p => p.Name).ToHashSet();

                // Detect new pipes
                var addedPipes = currentPipes.Except(previousPipes).ToList();
                foreach (var pipeName in addedPipes)
                {
                    var pipeInfo = currentPipeInfos.First(p => p.Name == pipeName);
                    
                    if (!noEvents)
                    {
                        WriteColor("[", ConsoleColor.DarkGray);
                        WriteColor("+", ConsoleColor.Green);
                        WriteColor("] ", ConsoleColor.DarkGray);
                        WriteColor("New pipe detected: ", ConsoleColor.Gray);
                        
                        if (pipeInfo.CurrentInstances >= 0 || pipeInfo.MaxInstances >= 0)
                        {
                            WriteColor(pipeName, ConsoleColor.Cyan);
                            WriteColorLine($" ({pipeInfo.CurrentInstances}/{pipeInfo.MaxInstances})", ConsoleColor.DarkCyan);
                        }
                        else
                        {
                            WriteColorLine(pipeName, ConsoleColor.Cyan);
                        }
                    }
                    
                    if (!noMessages)
                    {
                        StartMonitoringPipe(pipeName);
                    }
                }

                // Detect removed pipes
                var removedPipes = previousPipes.Except(currentPipes).ToList();
                foreach (var pipeName in removedPipes)
                {
                    if (!noEvents)
                    {
                        WriteColor("[", ConsoleColor.DarkGray);
                        WriteColor("-", ConsoleColor.Red);
                        WriteColor("] ", ConsoleColor.DarkGray);
                        WriteColor("Pipe removed: ", ConsoleColor.Gray);
                        WriteColorLine(pipeName, ConsoleColor.DarkRed);
                    }
                    
                    if (ActiveMonitors.TryGetValue(pipeName, out var monitor))
                    {
                        monitor.Dispose();
                        ActiveMonitors.Remove(pipeName);
                    }
                }

                previousPipes = currentPipes;

                await Task.Delay(MonitorIntervalMs);
            }
            catch (Exception ex)
            {
                WriteColorLine($"Error in monitoring loop: {ex.Message}", ConsoleColor.Red);
                await Task.Delay(MonitorIntervalMs);
            }
        }
    }

    static void StartMonitoringPipe(string pipeName)
    {
        if (ActiveMonitors.ContainsKey(pipeName))
        {
            return;
        }

        var monitor = new PipeMonitor(pipeName);
        ActiveMonitors[pipeName] = monitor;
        
        _ = Task.Run(async () =>
        {
            try
            {
                await monitor.MonitorAsync();
            }
            catch (Exception ex)
            {
                if (!NoErrors)
                {
                    WriteColor("[", ConsoleColor.DarkGray);
                    WriteColor(pipeName, ConsoleColor.Red);
                    WriteColor("] ", ConsoleColor.DarkGray);
                    WriteColor("✗ ", ConsoleColor.Red);
                    WriteColorLine($"Monitor error: {ex.Message}", ConsoleColor.DarkRed);
                }
            }
        });
    }

    public static void WriteColorLine(string message, ConsoleColor color)
    {
        lock (ConsoleLock)
        {
            var oldColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ForegroundColor = oldColor;
        }
    }

    public static void WriteColor(string message, ConsoleColor color)
    {
        lock (ConsoleLock)
        {
            var oldColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.Write(message);
            Console.ForegroundColor = oldColor;
        }
    }
}

class PipeMonitor : IDisposable
{
    private readonly string _pipeName;
    private bool _isDisposed;
    private CancellationTokenSource? _cts;

    public PipeMonitor(string pipeName)
    {
        _pipeName = pipeName;
        _cts = new CancellationTokenSource();
    }

    public async Task MonitorAsync()
    {
        if (_isDisposed || _cts == null) return;

        // Try to connect to the pipe
        try
        {
            using var pipeClient = new NamedPipeClientStream(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            // Try to connect with a short timeout
            var connectTask = pipeClient.ConnectAsync(2000, _cts.Token);
            await connectTask;

            if (!pipeClient.IsConnected)
            {
                if (!Program.NoErrors)
                {
                    Program.WriteColor("[", ConsoleColor.DarkGray);
                    Program.WriteColor(_pipeName, ConsoleColor.Yellow);
                    Program.WriteColorLine("] Failed to connect (timeout)", ConsoleColor.DarkYellow);
                }
                return;
            }

            if (!Program.NoLog)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.Cyan);
                Program.WriteColor("] ", ConsoleColor.DarkGray);
                Program.WriteColor("✓ ", ConsoleColor.Green);
                Program.WriteColorLine("Connected to pipe", ConsoleColor.Gray);
            }

            // Read from the pipe
            await ReadPipeAsync(pipeClient);
        }
        catch (TimeoutException)
        {
            if (!Program.NoErrors)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.DarkGray);
                Program.WriteColorLine("] Connection timeout (no server listening)", ConsoleColor.DarkGray);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (!Program.NoErrors)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.Yellow);
                Program.WriteColor("] ", ConsoleColor.DarkGray);
                Program.WriteColor("⚠ ", ConsoleColor.Yellow);
                Program.WriteColorLine("Access denied (insufficient permissions)", ConsoleColor.DarkYellow);
            }
        }
        catch (IOException ex)
        {
            if (!Program.NoErrors)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.DarkGray);
                Program.WriteColorLine($"] I/O error: {ex.Message}", ConsoleColor.DarkGray);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            if (!Program.NoErrors)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.Red);
                Program.WriteColor("] ", ConsoleColor.DarkGray);
                Program.WriteColor("✗ ", ConsoleColor.Red);
                Program.WriteColorLine($"Error: {ex.GetType().Name} - {ex.Message}", ConsoleColor.DarkRed);
            }
        }
    }

    private async Task ReadPipeAsync(NamedPipeClientStream pipeClient)
    {
        if (_cts == null) return;

        var buffer = new byte[4096];
        
        try
        {
            while (!_isDisposed && pipeClient.IsConnected && !_cts.Token.IsCancellationRequested)
            {
                var bytesRead = await pipeClient.ReadAsync(buffer, _cts.Token);
                
                if (bytesRead == 0)
                {
                    if (!Program.NoLog)
                    {
                        Program.WriteColor("[", ConsoleColor.DarkGray);
                        Program.WriteColor(_pipeName, ConsoleColor.DarkGray);
                        Program.WriteColorLine("] Pipe closed by server", ConsoleColor.DarkGray);
                    }
                    break;
                }

                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                var data = buffer.AsSpan(0, bytesRead);

                // Try to decode as text
                var text = TryDecodeText(data);
                
                if (text != null)
                {
                    Program.WriteColor("[", ConsoleColor.DarkGray);
                    Program.WriteColor(timestamp, ConsoleColor.DarkCyan);
                    Program.WriteColor("] [", ConsoleColor.DarkGray);
                    Program.WriteColor(_pipeName, ConsoleColor.Cyan);
                    Program.WriteColor("] ", ConsoleColor.DarkGray);
                    Program.WriteColor("📝 ", ConsoleColor.Blue);
                    Program.WriteColor("Text ", ConsoleColor.Magenta);
                    Program.WriteColorLine($"({bytesRead} bytes):", ConsoleColor.DarkMagenta);
                    Program.WriteColorLine($"  {text}", ConsoleColor.White);
                }
                else
                {
                    Program.WriteColor("[", ConsoleColor.DarkGray);
                    Program.WriteColor(timestamp, ConsoleColor.DarkCyan);
                    Program.WriteColor("] [", ConsoleColor.DarkGray);
                    Program.WriteColor(_pipeName, ConsoleColor.Cyan);
                    Program.WriteColor("] ", ConsoleColor.DarkGray);
                    Program.WriteColor("📦 ", ConsoleColor.DarkYellow);
                    Program.WriteColor("Binary ", ConsoleColor.Magenta);
                    Program.WriteColorLine($"({bytesRead} bytes):", ConsoleColor.DarkMagenta);
                    Program.WriteColorLine($"  {BitConverter.ToString(data.ToArray()).Replace("-", " ")}", ConsoleColor.DarkGray);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (IOException ex)
        {
            if (!Program.NoErrors && !Program.NoLog)
            {
                Program.WriteColor("[", ConsoleColor.DarkGray);
                Program.WriteColor(_pipeName, ConsoleColor.DarkGray);
                Program.WriteColorLine($"] Disconnected: {ex.Message}", ConsoleColor.DarkGray);
            }
        }
    }

    private static string? TryDecodeText(Span<byte> data)
    {
        try
        {
            // Try UTF-8
            var text = Encoding.UTF8.GetString(data);
            if (IsPrintable(text))
            {
                return text;
            }

            // Try ASCII
            text = Encoding.ASCII.GetString(data);
            if (IsPrintable(text))
            {
                return text;
            }

            // Try Unicode
            text = Encoding.Unicode.GetString(data);
            if (IsPrintable(text))
            {
                return text;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsPrintable(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        
        var printableCount = 0;
        foreach (var c in text)
        {
            if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t')
            {
                // Allow some control chars but not too many
                continue;
            }
            printableCount++;
        }

        // If at least 70% of characters are printable, consider it text
        return (double)printableCount / text.Length > 0.7;
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        
        _isDisposed = true;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}
