using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

internal static class WindowsPrivilege
{
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;

    public static void EnableSeBackupPrivilege()
    {
        using var processToken = OpenCurrentProcessToken();
        if (processToken.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not open the current process token.");
        }

        if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out var luid))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not resolve SeBackupPrivilege.");
        }

        var privileges = new TokenPrivileges
        {
            PrivilegeCount = 1,
            Privileges = new LuidAndAttributes
            {
                Luid = luid,
                Attributes = SePrivilegeEnabled
            }
        };

        if (!AdjustTokenPrivileges(
                processToken,
                false,
                ref privileges,
                0,
                IntPtr.Zero,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not enable SeBackupPrivilege.");
        }

        var error = Marshal.GetLastWin32Error();
        if (error != 0)
        {
            throw new Win32Exception(
                error,
                "Windows did not enable SeBackupPrivilege for this process.");
        }
    }

    private static SafeAccessTokenHandle OpenCurrentProcessToken()
    {
        if (!OpenProcessToken(
                GetCurrentProcess(),
                TokenAdjustPrivileges | TokenQuery,
                out var token))
        {
            var error = Marshal.GetLastWin32Error();
            token.Dispose();

            throw new Win32Exception(
                error,
                "Could not open the current process token.");
        }

        return token;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool LookupPrivilegeValue(
        string? systemName,
        string name,
        out Luid luid);

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        SafeAccessTokenHandle tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }
}
