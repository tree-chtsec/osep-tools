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
    $MS = "";
    If ($New) {
        $MS += "sc \\$ComputerName create $ServiceName obj= `"LocalSystem`" start= `"demand`" binPath= `"c:\windows\system32\cmd.exe`"`n";
    }
    $MS += "sc \\$ComputerName config $ServiceName start= `"demand`" binPath= `"c:\windows\system32\cmd.exe /c $Command`"`n";
    $MS += "sc \\$ComputerName start $ServiceName";
    If ($New) {
        $MS += "sc \\$ComputerName delete $ServiceName";
    }
    $MS | cmd;
}
