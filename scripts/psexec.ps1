Function IPsExec 
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Parameter(Position = 2)]
        [String]
        $ServiceName = "SensorDataService",

        [Parameter(Position = 3)]
        [Switch]
        $New
    )
    $C = "c:\windows\system32\cmd.exe";
    If ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage") {
        $MS = "";
        If ($New) {
            $MS += "sc \\$ComputerName create $ServiceName obj= `"LocalSystem`" start= `"demand`" binPath= `"$C`"`n";
        }
        $MS += "sc \\$ComputerName config $ServiceName start= `"demand`" binPath= `"$C /k %COMSPEC% /c $Command`"`n";
        $MS += "sc \\$ComputerName start $ServiceName`n";
        If ($New) {
            $MS += "sc \\$ComputerName delete $ServiceName`n";
        }
        $MS | cmd;
    } else {
        If ($New) {
            Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Service -Name Create -ArgumentList @($true, " ", 2, $null, $null, $ServiceName, $C, $null, 16, "Manual", "LocalSystem", $null);
        }
        $MS = Get-WmiObject -ComputerName $ComputerName -class win32_service -Filter "name=`"$ServiceName`"";
        $MS.Change($null, "$C /k %COMSPEC% /c $Command", $null, $null, "Manual", $null, "LocalSystem")
        $MS.StartService();
        If ($New) {
            $MS.Delete();
        }
    }
}
