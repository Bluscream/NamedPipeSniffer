using System.Runtime.InteropServices;
using System.Text;

namespace NamedPipeSniffer.Listers;

/// <summary>
/// Lists pipes using native NtQueryDirectoryFile API (provides detailed metadata)
/// </summary>
public class NativeLister : IPipeLister
{
    public string MethodName => "native";
    public string Description => "Use NtQueryDirectoryFile (detailed metadata, requires Windows)";

    public IEnumerable<NamedPipeInfo> GetPipes()
    {
        var pipes = new List<NamedPipeInfo>();

        try
        {
            var objectName = new UNICODE_STRING(@"\Device\NamedPipe\");
            var oa = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>()),
                Attributes = 0x40 // OBJ_CASE_INSENSITIVE
            };

            Marshal.StructureToPtr(objectName, oa.ObjectName, false);

            IntPtr hFile;
            IO_STATUS_BLOCK iosb;
            
            var status = NtOpenFile(
                out hFile,
                0x00000001 | 0x00100000, // FILE_LIST_DIRECTORY | SYNCHRONIZE
                ref oa,
                out iosb,
                0x00000007, // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                0x00000002  // FILE_SYNCHRONOUS_IO_NONALERT
            );

            Marshal.FreeHGlobal(oa.ObjectName);

            if (status != 0)
            {
                Program.WriteColorLine($"Failed to open named pipe directory: 0x{status:X8}", ConsoleColor.Red);
                return pipes;
            }

            const int bufferSize = 4096;
            var buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                while (true)
                {
                    status = NtQueryDirectoryFile(
                        hFile,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out iosb,
                        buffer,
                        bufferSize,
                        1, // FileDirectoryInformation
                        false,
                        IntPtr.Zero,
                        false
                    );

                    if (status != 0)
                        break;

                    var offset = 0;
                    while (true)
                    {
                        var dirInfo = Marshal.PtrToStructure<FILE_DIRECTORY_INFORMATION>(
                            IntPtr.Add(buffer, offset));

                        var name = Marshal.PtrToStringUni(
                            IntPtr.Add(buffer, offset + 64),
                            (int)(dirInfo.FileNameLength / 2));

                        if (!string.IsNullOrEmpty(name))
                        {
                            var pipeInfo = new NamedPipeInfo
                            {
                                Name = name,
                                FullPath = $@"\\.\pipe\{name}",
                                CurrentInstances = (int)dirInfo.EndOfFile,
                                MaxInstances = dirInfo.AllocationSize > int.MaxValue ? -1 : (int)dirInfo.AllocationSize
                            };

                            // Try to get security descriptor
                            pipeInfo.SecurityDescriptor = TryGetSecurityDescriptor(name);

                            pipes.Add(pipeInfo);
                        }

                        if (dirInfo.NextEntryOffset == 0)
                            break;

                        offset += (int)dirInfo.NextEntryOffset;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                NtClose(hFile);
            }
        }
        catch (Exception ex)
        {
            Program.WriteColorLine($"Error using native API: {ex.Message}", ConsoleColor.Red);
        }

        return pipes;
    }

    private string? TryGetSecurityDescriptor(string pipeName)
    {
        try
        {
            var objectName = new UNICODE_STRING($@"\Device\NamedPipe\{pipeName}");
            var oa = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>()),
                Attributes = 0x40 // OBJ_CASE_INSENSITIVE
            };

            Marshal.StructureToPtr(objectName, oa.ObjectName, false);

            var status = NtOpenFile(
                out IntPtr hFile,
                0x00020000, // READ_CONTROL
                ref oa,
                out _,
                0x00000007, // FILE_SHARE_VALID_FLAGS
                0
            );

            Marshal.FreeHGlobal(oa.ObjectName);

            if (status != 0)
                return null;

            try
            {
                const int initialSize = 256;
                var buffer = Marshal.AllocHGlobal(initialSize);
                uint returnLength = 0;

                status = NtQuerySecurityObject(
                    hFile,
                    0x00000001 | 0x00000004 | 0x00000010, // OWNER | DACL | LABEL
                    buffer,
                    initialSize,
                    out returnLength
                );

                if (status == 0)
                {
                    if (ConvertSecurityDescriptorToStringSecurityDescriptor(
                        buffer,
                        1, // SDDL_REVISION_1
                        0x00000001 | 0x00000004 | 0x00000010, // OWNER | DACL | LABEL
                        out IntPtr stringSD,
                        out _))
                    {
                        var result = Marshal.PtrToStringUni(stringSD);
                        LocalFree(stringSD);
                        Marshal.FreeHGlobal(buffer);
                        return result;
                    }
                }

                Marshal.FreeHGlobal(buffer);
            }
            finally
            {
                NtClose(hFile);
            }
        }
        catch
        {
            // Ignore errors when getting security descriptors
        }

        return null;
    }

    #region Native Structures and P/Invoke

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            Buffer = Marshal.StringToHGlobalUni(s);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DIRECTORY_INFORMATION
    {
        public uint NextEntryOffset;
        public uint FileIndex;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public uint FileAttributes;
        public uint FileNameLength;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenFile(
        out IntPtr FileHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock,
        uint ShareAccess,
        uint OpenOptions);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryFile(
        IntPtr FileHandle,
        IntPtr Event,
        IntPtr ApcRoutine,
        IntPtr ApcContext,
        out IO_STATUS_BLOCK IoStatusBlock,
        IntPtr FileInformation,
        int Length,
        int FileInformationClass,
        bool ReturnSingleEntry,
        IntPtr FileName,
        bool RestartScan);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySecurityObject(
        IntPtr Handle,
        uint SecurityInformation,
        IntPtr SecurityDescriptor,
        uint Length,
        out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr SecurityDescriptor,
        uint RequestedStringSDRevision,
        uint SecurityInformation,
        out IntPtr StringSecurityDescriptor,
        out uint StringSecurityDescriptorLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    #endregion
}
