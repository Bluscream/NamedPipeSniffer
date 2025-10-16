# NamedPipeSniffer

A .NET console application for monitoring and sniffing Windows Named Pipes.

## Features

- 📋 **List all named pipes** on the system
- 🔍 **Filter pipes** using glob patterns (e.g., `*mojo*`, `*chrome*`)
- 👀 **Monitor for changes** - detects when pipes are added or removed
- 📨 **Read messages** from pipes and display them in the console
- 🎨 **Color-coded output** for better readability
- ⚡ **Async monitoring** of multiple pipes simultaneously
- 🛠️ **Professional CLI** using System.CommandLine
- 🎯 **Robust glob matching** using DotNet.Glob

## Screenshots

<img width="400" src="https://github.com/user-attachments/assets/47adfd3e-e584-4304-8da8-8f196857f81f" />&nbsp;<img width="400" src="https://github.com/user-attachments/assets/d1b17d39-d6bb-4bc4-841f-03e1e67236a8" />


## Usage

```powershell
# Build the project
dotnet build

# Monitor all pipes
dotnet run

# Monitor pipes matching specific patterns
dotnet run -- *mojo*
dotnet run -- *mojo* *chrome*

# Monitor with custom scan interval (in milliseconds)
dotnet run -- *mojo* --interval 500

# Show help
dotnet run -- --help
```

## Command-Line Arguments

```
NamedPipeSniffer [patterns...] [options]

ARGUMENTS:
    [patterns]              Glob patterns to filter pipes (e.g., *mojo* chrome*)
                           Multiple patterns can be specified
                           Default: * (all pipes)

OPTIONS:
    -i, --interval <ms>    Pipe scan interval in milliseconds (default: 1000)
    -h, --help             Show this help message
```

## Examples

```powershell
# Monitor all pipes containing 'mojo'
dotnet run -- *mojo*

# Monitor pipes matching multiple patterns
dotnet run -- *mojo* *LOCAL*

# Faster scanning (every 500ms instead of 1000ms)
dotnet run -- *mojo* --interval 500
```

## Output

The application provides color-coded output:

- 🟢 **Green**: New pipes detected
- 🔴 **Red**: Pipes removed
- 🔵 **Cyan**: Connection status
- 🟣 **Magenta**: Messages received
- ⚪ **White**: Message content
- 🟡 **Yellow**: Summary information

Example output:

```
[+] New pipe detected: mojo.7256.1424.123456789
[mojo.7256.1424.123456789] ✓ Connected to pipe
[14:32:15.123] [mojo.7256.1424.123456789] Text (42 bytes):
  Hello from the pipe!
[-] Pipe removed: mojo.7256.1424.123456789
```

## Important Notes

⚠️ **Limitations of Named Pipe Sniffing**:

1. **Not true passive sniffing**: Named pipes are point-to-point communication channels. When this tool connects to a pipe, it becomes an active participant, not a passive observer.

2. **Data is consumed**: When data is read from a pipe, it's removed from the stream. This may interfere with the intended recipient.

3. **Connection requirements**: Only pipes that accept client connections can be monitored. Many pipes are already connected to their intended client.

4. **Permissions**: Some pipes require specific permissions to connect.

5. **Server must be listening**: The pipe server must be actively accepting connections.

This tool is best used for:

- Debugging your own named pipe communications
- Understanding pipe behavior in development
- Educational purposes

**Do not use this to intercept production communications or other applications' private data without authorization.**

## Requirements

- .NET 8.0 or later
- Windows (Named pipes are Windows-specific)
- Appropriate permissions to access pipes

## Dependencies

- [System.CommandLine](https://github.com/dotnet/command-line-api) - Modern command-line parsing
- [DotNet.Glob](https://github.com/dazinator/DotNet.Glob) - Fast and flexible glob pattern matching

## References

- [Stack Overflow: How to list named pipes](https://stackoverflow.com/questions/258701/how-can-i-get-a-list-of-all-open-named-pipes-in-windows)
- [Microsoft Learn: Named Pipes](https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-use-named-pipes-for-network-interprocess-communication)
- [Sysinternals PipeList](https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist)

## License

This tool is provided for educational and debugging purposes.
