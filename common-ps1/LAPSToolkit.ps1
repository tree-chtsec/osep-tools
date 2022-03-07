
filter Export-PowerViewCSV {
Param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[System.Management.Automation.PSObject[]]
$InputObject,
[Parameter(Mandatory=$True, Position=0)]
[String]
[ValidateNotNullOrEmpty()]
$OutFile
)
$ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation
$Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
$Null = $Mutex.WaitOne()
if (Test-Path -Path $OutFile) {
$ObjectCSV | ForEach-Object { $Start=$True }{ if ($Start) {$Start=$False} else {$_} } | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
}
else {
$ObjectCSV | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
}
$Mutex.ReleaseMutex()
}
filter Convert-SidToName {
[CmdletBinding()]
param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[String]
[ValidatePattern('^S-1-.*')]
$SID
)
try {
$SID2 = $SID.trim('*')
Switch ($SID2)
{
'S-1-0' { 'Null Authority' }
'S-1-0-0' { 'Nobody' }
'S-1-1' { 'World Authority' }
'S-1-1-0' { 'Everyone' }
'S-1-2' { 'Local Authority' }
'S-1-2-0' { 'Local' }
'S-1-2-1' { 'Console Logon ' }
'S-1-3' { 'Creator Authority' }
'S-1-3-0' { 'Creator Owner' }
'S-1-3-1' { 'Creator Group' }
'S-1-3-2' { 'Creator Owner Server' }
'S-1-3-3' { 'Creator Group Server' }
'S-1-3-4' { 'Owner Rights' }
'S-1-4' { 'Non-unique Authority' }
'S-1-5' { 'NT Authority' }
'S-1-5-1' { 'Dialup' }
'S-1-5-2' { 'Network' }
'S-1-5-3' { 'Batch' }
'S-1-5-4' { 'Interactive' }
'S-1-5-6' { 'Service' }
'S-1-5-7' { 'Anonymous' }
'S-1-5-8' { 'Proxy' }
'S-1-5-9' { 'Enterprise Domain Controllers' }
'S-1-5-10' { 'Principal Self' }
'S-1-5-11' { 'Authenticated Users' }
'S-1-5-12' { 'Restricted Code' }
'S-1-5-13' { 'Terminal Server Users' }
'S-1-5-14' { 'Remote Interactive Logon' }
'S-1-5-15' { 'This Organization ' }
'S-1-5-17' { 'This Organization ' }
'S-1-5-18' { 'Local System' }
'S-1-5-19' { 'NT Authority' }
'S-1-5-20' { 'NT Authority' }
'S-1-5-80-0' { 'All Services ' }
'S-1-5-32-544' { 'BUILTIN\Administrators' }
'S-1-5-32-545' { 'BUILTIN\Users' }
'S-1-5-32-546' { 'BUILTIN\Guests' }
'S-1-5-32-547' { 'BUILTIN\Power Users' }
'S-1-5-32-548' { 'BUILTIN\Account Operators' }
'S-1-5-32-549' { 'BUILTIN\Server Operators' }
'S-1-5-32-550' { 'BUILTIN\Print Operators' }
'S-1-5-32-551' { 'BUILTIN\Backup Operators' }
'S-1-5-32-552' { 'BUILTIN\Replicators' }
'S-1-5-32-554' { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
'S-1-5-32-555' { 'BUILTIN\Remote Desktop Users' }
'S-1-5-32-556' { 'BUILTIN\Network Configuration Operators' }
'S-1-5-32-557' { 'BUILTIN\Incoming Forest Trust Builders' }
'S-1-5-32-558' { 'BUILTIN\Performance Monitor Users' }
'S-1-5-32-559' { 'BUILTIN\Performance Log Users' }
'S-1-5-32-560' { 'BUILTIN\Windows Authorization Access Group' }
'S-1-5-32-561' { 'BUILTIN\Terminal Server License Servers' }
'S-1-5-32-562' { 'BUILTIN\Distributed COM Users' }
'S-1-5-32-569' { 'BUILTIN\Cryptographic Operators' }
'S-1-5-32-573' { 'BUILTIN\Event Log Readers' }
'S-1-5-32-574' { 'BUILTIN\Certificate Service DCOM Access' }
'S-1-5-32-575' { 'BUILTIN\RDS Remote Access Servers' }
'S-1-5-32-576' { 'BUILTIN\RDS Endpoint Servers' }
'S-1-5-32-577' { 'BUILTIN\RDS Management Servers' }
'S-1-5-32-578' { 'BUILTIN\Hyper-V Administrators' }
'S-1-5-32-579' { 'BUILTIN\Access Control Assistance Operators' }
'S-1-5-32-580' { 'BUILTIN\Access Control Assistance Operators' }
Default {
$Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
$Obj.Translate( [System.Security.Principal.NTAccount]).Value
}
}
}
catch {
Write-Debug "Invalid SID: $SID"
$SID
}
}
filter Convert-ADName {
[CmdletBinding()]
param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[String]
$ObjectName,
[String]
[ValidateSet("NT4","Simple","Canonical")]
$InputType,
[String]
[ValidateSet("NT4","Simple","Canonical")]
$OutputType
)
$NameTypes = @{
"Canonical" = 2
"NT4" = 3
"Simple" = 5
}
if(!$PSBoundParameters['InputType']) {
if( ($ObjectName.split('/')).Count -eq 2 ) {
$ObjectName = $ObjectName.replace('/', '\')
}
if($ObjectName -match "^[A-Za-z]+\\[A-Za-z ]+$") {
$InputType = 'NT4'
}
elseif($ObjectName -match "^[A-Za-z ]+@[A-Za-z\.]+") {
$InputType = 'Simple'
}
elseif($ObjectName -match "^[A-Za-z\.]+/[A-Za-z]+/[A-Za-z/ ]+") {
$InputType = 'Canonical'
}
else {
Write-Warning "Can not identify InType for $ObjectName"
return $ObjectName
}
}
elseif($InputType -eq 'NT4') {
$ObjectName = $ObjectName.replace('/', '\')
}
if(!$PSBoundParameters['OutputType']) {
$OutputType = Switch($InputType) {
'NT4' {'Canonical'}
'Simple' {'NT4'}
'Canonical' {'NT4'}
}
}
$Domain = Switch($InputType) {
'NT4' { $ObjectName.split("\")[0] }
'Simple' { $ObjectName.split("@")[1] }
'Canonical' { $ObjectName.split("/")[0] }
}
function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
$Output = $Object.GetType().InvokeMember($Method, "InvokeMethod", $Null, $Object, $Parameters)
if ( $Output ) { $Output }
}
function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
[Void] $Object.GetType().InvokeMember($Property, "SetProperty", $Null, $Object, $Parameters)
}
$Translate = New-Object -ComObject NameTranslate
try {
Invoke-Method $Translate "Init" (1, $Domain)
}
catch [System.Management.Automation.MethodInvocationException] {
Write-Debug "Error with translate init in Convert-ADName: $_"
}
Set-Property $Translate "ChaseReferral" (0x60)
try {
Invoke-Method $Translate "Set" ($NameTypes[$InputType], $ObjectName)
(Invoke-Method $Translate "Get" ($NameTypes[$OutputType]))
}
catch [System.Management.Automation.MethodInvocationException] {
Write-Debug "Error with translate Set/Get in Convert-ADName: $_"
}
}
function ConvertFrom-UACValue {
[CmdletBinding()]
param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
$Value,
[Switch]
$ShowAll
)
begin {
$UACValues = New-Object System.Collections.Specialized.OrderedDictionary
$UACValues.Add("SCRIPT", 1)
$UACValues.Add("ACCOUNTDISABLE", 2)
$UACValues.Add("HOMEDIR_REQUIRED", 8)
$UACValues.Add("LOCKOUT", 16)
$UACValues.Add("PASSWD_NOTREQD", 32)
$UACValues.Add("PASSWD_CANT_CHANGE", 64)
$UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
$UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
$UACValues.Add("NORMAL_ACCOUNT", 512)
$UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
$UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
$UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
$UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
$UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
$UACValues.Add("SMARTCARD_REQUIRED", 262144)
$UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
$UACValues.Add("NOT_DELEGATED", 1048576)
$UACValues.Add("USE_DES_KEY_ONLY", 2097152)
$UACValues.Add("DONT_REQ_PREAUTH", 4194304)
$UACValues.Add("PASSWORD_EXPIRED", 8388608)
$UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
$UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
}
process {
$ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary
if($Value -is [Int]) {
$IntValue = $Value
}
elseif ($Value -is [PSCustomObject]) {
if($Value.useraccountcontrol) {
$IntValue = $Value.useraccountcontrol
}
}
else {
Write-Warning "Invalid object input for -Value : $Value"
return $Null
}
if($ShowAll) {
foreach ($UACValue in $UACValues.GetEnumerator()) {
if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
$ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
}
else {
$ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
}
}
}
else {
foreach ($UACValue in $UACValues.GetEnumerator()) {
if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
$ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
}
}
}
$ResultUACValues
}
}
filter Get-Proxy {
param(
[Parameter(ValueFromPipeline=$True)]
[ValidateNotNullOrEmpty()]
[String]
$ComputerName = $ENV:COMPUTERNAME
)
try {
$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $ComputerName)
$RegKey = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
$ProxyServer = $RegKey.GetValue('ProxyServer')
$AutoConfigURL = $RegKey.GetValue('AutoConfigURL')
$Wpad = ""
if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
try {
$Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
}
catch {
Write-Warning "Error connecting to AutoConfigURL : $AutoConfigURL"
}
}
if($ProxyServer -or $AutoConfigUrl) {
$Properties = @{
'ProxyServer' = $ProxyServer
'AutoConfigURL' = $AutoConfigURL
'Wpad' = $Wpad
}
New-Object -TypeName PSObject -Property $Properties
}
else {
Write-Warning "No proxy settings found for $ComputerName"
}
}
catch {
Write-Warning "Error enumerating proxy settings for $ComputerName : $_"
}
}
function Get-PathAcl {
[CmdletBinding()]
param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[String]
$Path,
[Switch]
$Recurse
)
begin {
function Convert-FileRight {
[CmdletBinding()]
param(
[Int]
$FSR
)
$AccessMask = @{
[uint32]'0x80000000' = 'GenericRead'
[uint32]'0x40000000' = 'GenericWrite'
[uint32]'0x20000000' = 'GenericExecute'
[uint32]'0x10000000' = 'GenericAll'
[uint32]'0x02000000' = 'MaximumAllowed'
[uint32]'0x01000000' = 'AccessSystemSecurity'
[uint32]'0x00100000' = 'Synchronize'
[uint32]'0x00080000' = 'WriteOwner'
[uint32]'0x00040000' = 'WriteDAC'
[uint32]'0x00020000' = 'ReadControl'
[uint32]'0x00010000' = 'Delete'
[uint32]'0x00000100' = 'WriteAttributes'
[uint32]'0x00000080' = 'ReadAttributes'
[uint32]'0x00000040' = 'DeleteChild'
[uint32]'0x00000020' = 'Execute/Traverse'
[uint32]'0x00000010' = 'WriteExtendedAttributes'
[uint32]'0x00000008' = 'ReadExtendedAttributes'
[uint32]'0x00000004' = 'AppendData/AddSubdirectory'
[uint32]'0x00000002' = 'WriteData/AddFile'
[uint32]'0x00000001' = 'ReadData/ListDirectory'
}
$SimplePermissions = @{
[uint32]'0x1f01ff' = 'FullControl'
[uint32]'0x0301bf' = 'Modify'
[uint32]'0x0200a9' = 'ReadAndExecute'
[uint32]'0x02019f' = 'ReadAndWrite'
[uint32]'0x020089' = 'Read'
[uint32]'0x000116' = 'Write'
}
$Permissions = @()
$Permissions += $SimplePermissions.Keys | % {
if (($FSR -band $_) -eq $_) {
$SimplePermissions[$_]
$FSR = $FSR -band (-not $_)
}
}
$Permissions += $AccessMask.Keys |
? { $FSR -band $_ } |
% { $AccessMask[$_] }
($Permissions | ?{$_}) -join ","
}
}
process {
try {
$ACL = Get-Acl -Path $Path
$ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
$Names = @()
if ($_.IdentityReference -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+') {
$Object = Get-ADObject -SID $_.IdentityReference
$Names = @()
$SIDs = @($Object.objectsid)
if ($Recurse -and (@('268435456','268435457','536870912','536870913') -contains $Object.samAccountType)) {
$SIDs += Get-NetGroupMember -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
}
$SIDs | ForEach-Object {
$Names += ,@($_, (Convert-SidToName $_))
}
}
else {
$Names += ,@($_.IdentityReference.Value, (Convert-SidToName $_.IdentityReference.Value))
}
ForEach($Name in $Names) {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'Path' $Path
$Out | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
$Out | Add-Member Noteproperty 'IdentityReference' $Name[1]
$Out | Add-Member Noteproperty 'IdentitySID' $Name[0]
$Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
$Out
}
}
}
catch {
Write-Warning $_
}
}
}
filter Get-NameField {
[CmdletBinding()]
param(
[Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
[Object]
$Object,
[Parameter(ValueFromPipelineByPropertyName = $True)]
[String]
$DnsHostName,
[Parameter(ValueFromPipelineByPropertyName = $True)]
[String]
$Name
)
if($PSBoundParameters['DnsHostName']) {
$DnsHostName
}
elseif($PSBoundParameters['Name']) {
$Name
}
elseif($Object) {
if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
$Object.dnshostname
}
elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
$Object.name
}
else {
$Object
}
}
else {
return $Null
}
}
function Convert-LDAPProperty {
param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[ValidateNotNullOrEmpty()]
$Properties
)
$ObjectProperties = @{}
$Properties.PropertyNames | ForEach-Object {
if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
$ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
}
elseif($_ -eq "objectguid") {
$ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
}
elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
$Temp = $Properties[$_][0]
[Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
[Int32]$Low = $Temp.GetType().InvokeMember("LowPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
$ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
}
else {
$ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
}
}
elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
$Prop = $Properties[$_]
try {
$Temp = $Prop[$_][0]
Write-Verbose $_
[Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
[Int32]$Low = $Temp.GetType().InvokeMember("LowPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
$ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
}
catch {
$ObjectProperties[$_] = $Prop[$_]
}
}
elseif($Properties[$_].count -eq 1) {
$ObjectProperties[$_] = $Properties[$_][0]
}
else {
$ObjectProperties[$_] = $Properties[$_]
}
}
New-Object -TypeName PSObject -Property $ObjectProperties
}
filter Get-DomainSearcher {
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[String]
$ADSprefix,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
if(!$Credential) {
if(!$Domain){
$Domain = (Get-NetDomain).name
}
elseif(!$DomainController) {
try {
$DomainController = ((Get-NetDomain).PdcRoleOwner).Name
}
catch {
throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
}
}
}
elseif (!$DomainController) {
try {
$DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
}
catch {
throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
}
if(!$DomainController) {
throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
}
}
$SearchString = "LDAP://"
if($DomainController) {
$SearchString += $DomainController
if($Domain){
$SearchString += "/"
}
}
if($ADSprefix) {
$SearchString += $ADSprefix + ","
}
if($ADSpath) {
if($ADSpath -like "GC://*") {
$DN = $AdsPath
$SearchString = ""
}
else {
if($ADSpath -like "LDAP://*") {
if($ADSpath -match "LDAP://.+/.+") {
$SearchString = ""
}
else {
$ADSpath = $ADSpath.Substring(7)
}
}
$DN = $ADSpath
}
}
else {
if($Domain -and ($Domain.Trim() -ne "")) {
$DN = "DC=$($Domain.Replace('.', ',DC='))"
}
}
$SearchString += $DN
Write-Verbose "Get-DomainSearcher search string: $SearchString"
if($Credential) {
Write-Verbose "Using alternate credentials for LDAP connection"
$DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
$Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
}
else {
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
}
$Searcher.PageSize = $PageSize
$Searcher
}
filter Get-NetDomain {
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Domain,
[Management.Automation.PSCredential]
$Credential
)
if($Credential) {
Write-Verbose "Using alternate credentials for Get-NetDomain"
if(!$Domain) {
$Domain = $Credential.GetNetworkCredential().Domain
Write-Verbose "Extracted domain '$Domain' from -Credential"
}
$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
try {
[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
}
catch {
Write-Warning "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
$Null
}
}
elseif($Domain) {
$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
try {
[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
}
catch {
Write-Warning "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
$Null
}
}
else {
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
}
}
filter Get-NetForest {
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Forest,
[Management.Automation.PSCredential]
$Credential
)
if($Credential) {
Write-Verbose "Using alternate credentials for Get-NetForest"
if(!$Forest) {
$Forest = $Credential.GetNetworkCredential().Domain
Write-Verbose "Extracted domain '$Forest' from -Credential"
}
$ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest, $Credential.UserName, $Credential.GetNetworkCredential().Password)
try {
$ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
}
catch {
Write-Warning "The specified forest '$Forest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
$Null
}
}
elseif($Forest) {
$ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
try {
$ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
}
catch {
Write-Warning "The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust."
return $Null
}
}
else {
$ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}
if($ForestObject) {
try {
$ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$Parts = $ForestSid -Split "-"
$ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
$ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
}
catch {
Write-Verbose "Couldn't translate SID for Forest"
$ForestSid = ""
}
$ForestObject
}
}
filter Get-NetForestDomain {
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Forest,
[Management.Automation.PSCredential]
$Credential
)
$ForestObject = Get-NetForest -Forest $Forest -Credential $Credential
if($ForestObject) {
$ForestObject.Domains
}
}
filter Get-NetForestCatalog {
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Forest,
[Management.Automation.PSCredential]
$Credential
)
$ForestObject = Get-NetForest -Forest $Forest -Credential $Credential
if($ForestObject) {
$ForestObject.FindAllGlobalCatalogs()
}
}
filter Get-NetDomainController {
[CmdletBinding()]
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$Domain,
[String]
$DomainController,
[Switch]
$LDAP,
[Management.Automation.PSCredential]
$Credential
)
if($LDAP -or $DomainController) {
Get-NetComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
}
else {
$FoundDomain = Get-NetDomain -Domain $Domain -Credential $Credential
if($FoundDomain) {
$Founddomain.DomainControllers
}
}
}
function Get-ObjectAcl {
[CmdletBinding()]
Param (
[Parameter(ValueFromPipelineByPropertyName=$True)]
[String]
$SamAccountName,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[String]
$Name = "*",
[Parameter(ValueFromPipelineByPropertyName=$True)]
[String]
$DistinguishedName = "*",
[Switch]
$ResolveGUIDs,
[String]
$Filter,
[String]
$ADSpath,
[String]
$ADSprefix,
[String]
[ValidateSet("All","ResetPassword","WriteMembers")]
$RightsFilter,
[String]
$Domain,
[String]
$DomainController,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize -Credential $Credential
if($ResolveGUIDs) {
$GUIDs = Get-GUIDMap -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential
}
}
process {
if ($Searcher) {
if($SamAccountName) {
$Searcher.filter="(&(samaccountname=$SamAccountName)(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"
}
else {
$Searcher.filter="(&(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"
}
try {
$Results = $Searcher.FindAll()
$Results | Where-Object {$_} | ForEach-Object {
if($Credential) {
$Object = New-Object -TypeName System.DirectoryServices.DirectoryEntry($_.path, $($Credential.UserName),$($Credential.GetNetworkCredential().password))
}
else {
$Object = [adsi]($_.path)
}
if($Object.distinguishedname) {
$Access = $Object.PsBase.ObjectSecurity.access
$Access | ForEach-Object {
$_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
if($Object.objectsid[0]){
$S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
}
else {
$S = $Null
}
$_ | Add-Member NoteProperty 'ObjectSID' $S
$_
}
}
} | ForEach-Object {
if($RightsFilter) {
$GuidFilter = Switch ($RightsFilter) {
"ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
"WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
Default { "00000000-0000-0000-0000-000000000000"}
}
if($_.ObjectType -eq $GuidFilter) { $_ }
}
else {
$_
}
} | ForEach-Object {
if($GUIDs) {
$AclProperties = @{}
$_.psobject.properties | ForEach-Object {
if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
try {
$AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
}
catch {
$AclProperties[$_.Name] = $_.Value
}
}
else {
$AclProperties[$_.Name] = $_.Value
}
}
New-Object -TypeName PSObject -Property $AclProperties
}
else { $_ }
}
$Results.dispose()
$Searcher.dispose()
}
catch {
Write-Warning $_
}
}
}
}
function Add-ObjectAcl {
[CmdletBinding()]
Param (
[String]
$TargetSamAccountName,
[String]
$TargetName = "*",
[Alias('DN')]
[String]
$TargetDistinguishedName = "*",
[String]
$TargetFilter,
[String]
$TargetADSpath,
[String]
$TargetADSprefix,
[String]
[ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
$PrincipalSID,
[String]
$PrincipalName,
[String]
$PrincipalSamAccountName,
[String]
[ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
$Rights = "All",
[String]
$RightsGUID,
[String]
$Domain,
[String]
$DomainController,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200
)
begin {
$Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize
if(!$PrincipalSID) {
$Principal = Get-ADObject -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
if(!$Principal) {
throw "Error resolving principal"
}
$PrincipalSID = $Principal.objectsid
}
if(!$PrincipalSID) {
throw "Error resolving principal"
}
}
process {
if ($Searcher) {
if($TargetSamAccountName) {
$Searcher.filter="(&(samaccountname=$TargetSamAccountName)(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"
}
else {
$Searcher.filter="(&(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"
}
try {
$Searcher.FindAll() | Where-Object {$_} | ForEach-Object {
$TargetDN = $_.Properties.distinguishedname
$Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalSID)
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
$ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
$ACEs = @()
if($RightsGUID) {
$GUIDs = @($RightsGUID)
}
else {
$GUIDs = Switch ($Rights) {
"ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
"WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
"DCSync" { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"}
}
}
if($GUIDs) {
foreach($GUID in $GUIDs) {
$NewGUID = New-Object Guid $GUID
$ADRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
}
}
else {
$ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
}
Write-Verbose "Granting principal $PrincipalSID '$Rights' on $($_.Properties.distinguishedname)"
try {
ForEach ($ACE in $ACEs) {
Write-Verbose "Granting principal $PrincipalSID '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
$Object = [adsi]($_.path)
$Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
$Object.PsBase.commitchanges()
}
}
catch {
Write-Warning "Error granting principal $PrincipalSID '$Rights' on $TargetDN : $_"
}
}
}
catch {
Write-Warning "Error: $_"
}
}
}
}
filter Get-GUIDMap {
[CmdletBinding()]
Param (
[Parameter(ValueFromPipeline=$True)]
[String]
$Domain,
[String]
$DomainController,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
$GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}
$SchemaPath = (Get-NetForest -Credential $Credential).schema.name
$SchemaSearcher = Get-DomainSearcher -ADSpath $SchemaPath -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential
if($SchemaSearcher) {
$SchemaSearcher.filter = "(schemaIDGUID=*)"
try {
$SchemaSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
$GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
}
}
catch {
Write-Debug "Error in building GUID map: $_"
}
}
$RightsSearcher = Get-DomainSearcher -ADSpath $SchemaPath.replace("Schema","Extended-Rights") -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential
if ($RightsSearcher) {
$RightsSearcher.filter = "(objectClass=controlAccessRight)"
try {
$RightsSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
$GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
}
}
catch {
Write-Debug "Error in building GUID map: $_"
}
}
$GUIDs
}
function Get-NetComputer {
[CmdletBinding()]
Param (
[Parameter(ValueFromPipeline=$True)]
[Alias('HostName')]
[String]
$ComputerName = '*',
[String]
$SPN,
[String]
$OperatingSystem,
[String]
$ServicePack,
[String]
$Filter,
[Switch]
$Printers,
[Switch]
$Ping,
[Switch]
$FullData,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[String]
$SiteName,
[Switch]
$Unconstrained,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize -Credential $Credential
}
process {
if ($CompSearcher) {
if($Unconstrained) {
Write-Verbose "Searching for computers with for unconstrained delegation"
$Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
}
if($Printers) {
Write-Verbose "Searching for printers"
$Filter += "(objectCategory=printQueue)"
}
if($SPN) {
Write-Verbose "Searching for computers with SPN: $SPN"
$Filter += "(servicePrincipalName=$SPN)"
}
if($OperatingSystem) {
$Filter += "(operatingsystem=$OperatingSystem)"
}
if($ServicePack) {
$Filter += "(operatingsystemservicepack=$ServicePack)"
}
if($SiteName) {
$Filter += "(serverreferencebl=$SiteName)"
}
$CompFilter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"
Write-Verbose "Get-NetComputer filter : '$CompFilter'"
$CompSearcher.filter = $CompFilter
try {
$CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
$Up = $True
if($Ping) {
$Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
}
if($Up) {
if ($FullData) {
Convert-LDAPProperty -Properties $_.Properties
}
else {
$_.properties.dnshostname
}
}
}
}
catch {
Write-Warning "Error: $_"
}
}
}
}
function Get-NetOU {
[CmdletBinding()]
Param (
[Parameter(ValueFromPipeline=$True)]
[String]
$OUName = '*',
[String]
$GUID,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[Switch]
$FullData,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$OUSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
}
process {
if ($OUSearcher) {
if ($GUID) {
$OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName)(gplink=*$GUID*))"
}
else {
$OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"
}
try {
$OUSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
if ($FullData) {
Convert-LDAPProperty -Properties $_.Properties
}
else {
$_.properties.adspath
}
}
}
catch {
Write-Warning $_
}
}
}
}
function Get-NetGroup {
[CmdletBinding()]
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$GroupName = '*',
[String]
$SID,
[String]
$UserName,
[String]
$Filter,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[Switch]
$AdminCount,
[Switch]
$FullData,
[Switch]
$RawSids,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
}
process {
if($GroupSearcher) {
if($AdminCount) {
Write-Verbose "Checking for adminCount=1"
$Filter += "(admincount=1)"
}
if ($UserName) {
$User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -Credential $Credential -ReturnRaw -PageSize $PageSize
$UserDirectoryEntry = $User.GetDirectoryEntry()
$UserDirectoryEntry.RefreshCache("tokenGroups")
$UserDirectoryEntry.TokenGroups | ForEach-Object {
$GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
if(!($GroupSid -match '^S-1-5-32-545|-513$')) {
if($FullData) {
Get-ADObject -SID $GroupSid -PageSize $PageSize -Domain $Domain -DomainController $DomainController -Credential $Credential
}
else {
if($RawSids) {
$GroupSid
}
else {
Convert-SidToName $GroupSid
}
}
}
}
}
else {
if ($SID) {
$GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
}
else {
$GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
}
$GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
if ($FullData) {
Convert-LDAPProperty -Properties $_.Properties
}
else {
$_.properties.samaccountname
}
}
}
}
}
}
function Get-NetGroupMember {
[CmdletBinding()]
param(
[Parameter(ValueFromPipeline=$True)]
[String]
$GroupName,
[String]
$SID,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[Switch]
$FullData,
[Switch]
$Recurse,
[Switch]
$UseMatchingRule,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
if(!$DomainController) {
$DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
}
if(!$Domain) {
$Domain = Get-NetDomain -Credential $Credential
}
}
process {
if ($GroupSearcher) {
if ($Recurse -and $UseMatchingRule) {
if ($GroupName) {
$Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
}
elseif ($SID) {
$Group = Get-NetGroup -SID $SID -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
}
else {
$SID = (Get-DomainSID -Domain $Domain -Credential $Credential) + "-512"
$Group = Get-NetGroup -SID $SID -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize
}
$GroupDN = $Group.distinguishedname
$GroupFoundName = $Group.name
if ($GroupDN) {
$GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
$GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))
$Members = $GroupSearcher.FindAll()
$GroupFoundName = $GroupName
}
else {
Write-Error "Unable to find Group"
}
}
else {
if ($GroupName) {
$GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
}
elseif ($SID) {
$GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
}
else {
$SID = (Get-DomainSID -Domain $Domain -Credential $Credential) + "-512"
$GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
}
$GroupSearcher.FindAll() | ForEach-Object {
try {
if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }
$GroupFoundName = $_.properties.name[0]
$Members = @()
if ($_.properties.member.Count -eq 0) {
$Finished = $False
$Bottom = 0
$Top = 0
while(!$Finished) {
$Top = $Bottom + 1499
$MemberRange="member;range=$Bottom-$Top"
$Bottom += 1500
$GroupSearcher.PropertiesToLoad.Clear()
[void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
try {
$Result = $GroupSearcher.FindOne()
if ($Result) {
$RangedProperty = $_.Properties.PropertyNames -like "member;range=*"
$Results = $_.Properties.item($RangedProperty)
if ($Results.count -eq 0) {
$Finished = $True
}
else {
$Results | ForEach-Object {
$Members += $_
}
}
}
else {
$Finished = $True
}
}
catch [System.Management.Automation.MethodInvocationException] {
$Finished = $True
}
}
}
else {
$Members = $_.properties.member
}
}
catch {
Write-Verbose $_
}
}
}
$Members | Where-Object {$_} | ForEach-Object {
if ($Recurse -and $UseMatchingRule) {
$Properties = $_.Properties
}
else {
if($DomainController) {
$Result = [adsi]"LDAP://$DomainController/$_"
}
else {
$Result = [adsi]"LDAP://$_"
}
if($Result){
$Properties = $Result.Properties
}
}
if($Properties) {
$IsGroup = @('268435456','268435457','536870912','536870913') -contains $Properties.samaccounttype
if ($FullData) {
$GroupMember = Convert-LDAPProperty -Properties $Properties
}
else {
$GroupMember = New-Object PSObject
}
$GroupMember | Add-Member Noteproperty 'GroupDomain' $Domain
$GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName
try {
$MemberDN = $Properties.distinguishedname[0]
$MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
}
catch {
$MemberDN = $Null
$MemberDomain = $Null
}
if ($Properties.samaccountname) {
$MemberName = $Properties.samaccountname[0]
}
else {
try {
$MemberName = Convert-SidToName $Properties.cn[0]
}
catch {
$MemberName = $Properties.cn
}
}
if($Properties.objectSid) {
$MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
}
else {
$MemberSid = $Null
}
$GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
$GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
$GroupMember | Add-Member Noteproperty 'MemberSid' $MemberSid
$GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
$GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
$GroupMember
if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
if($FullData) {
Get-NetGroupMember -FullData -Domain $MemberDomain -DomainController $DomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
}
else {
Get-NetGroupMember -Domain $MemberDomain -DomainController $DomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
}
}
}
}
}
}
}
function Get-NetUser {
param(
[Parameter(Position=0, ValueFromPipeline=$True)]
[String]
$UserName,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[String]
$Filter,
[Switch]
$SPN,
[Switch]
$AdminCount,
[Switch]
$Unconstrained,
[Switch]
$AllowDelegation,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
$UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize -Credential $Credential
}
process {
if($UserSearcher) {
if($Unconstrained) {
Write-Verbose "Checking for unconstrained delegation"
$Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
}
if($AllowDelegation) {
Write-Verbose "Checking for users who can be delegated"
$Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
}
if($AdminCount) {
Write-Verbose "Checking for adminCount=1"
$Filter += "(admincount=1)"
}
if($UserName) {
$UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
}
elseif($SPN) {
$UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
}
else {
$UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
}
$Results = $UserSearcher.FindAll()
$Results | Where-Object {$_} | ForEach-Object {
$User = Convert-LDAPProperty -Properties $_.Properties
$User.PSObject.TypeNames.Add('PowerView.User')
$User
}
$Results.dispose()
$UserSearcher.dispose()
}
}
}
function Find-AdmPwdExtendedRights {
[CmdletBinding()]
param(
[String]
$Domain,
[String]
$DomainController,
[String]
$ComputerName,
[String]
$Filter = "(objectCategory=Computer)(ms-mcs-admpwdexpirationtime=*)",
[Switch]
$ExcludeDelegated,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
begin {
if($ComputerName) {
$LAPSFilter = "$Filter(dNSHostName=$ComputerName)"
}
else {
$LAPSFilter = "$Filter"
}
Write-Verbose "Retrieving all ExtendedRight ACLs for domain $Domain"
$ExtendedRights = Get-ObjectAcl -ResolveGUIDs -Filter $LAPSFilter -Domain $Domain -DomainController $DomainController -Credential $Credential -PageSize $PageSize | Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" }
$CompMap = @{}
$ComputerObjects = Get-NetComputer -Filter "(ms-mcs-admpwdexpirationtime=*)" -FullData -Domain $Domain -DomainController $DomainController -Credential $Credential | ForEach-Object { $CompMap.Add($_.distinguishedname, $_.dnshostname) }
if($Credential){
Write-Verbose "Retrieving all users and groups to resolve SIDs when using PSCredential"
$SIDMap = @{}
Get-NetUser -Domain $Domain -DomainController $DomainController -Credential $Credential | ForEach-Object { $SIDMap.Add($_.objectsid, $_.samaccountname) }
Get-NetGroup -FullData -Domain $Domain -DomainController $DomainController -Credential $Credential | ForEach-Object { $SIDMap.Add($_.objectsid, $_.samaccountname) }
}
}
process {
$ExtendedRights | ForEach-Object {
$ComputerName = $CompMap[$_.ObjectDN]
Write-Verbose "Parsing ACLs for $ComputerName"
$Identity = $_.IdentityReference
if($_.ObjectType -match "ms-Mcs-AdmPwd" -and !($ExcludeDelegated)) {
$Reason = "Delegated"
}
elseif($_.ObjectType -match "All" -and $_.IdentityReference -notmatch "BUILTIN") {
$Reason = "All"
}
else { return }
if($Credential) {
if($SIDMap.Contains($Identity.ToString())) {
$Identity = $SIDMap[$Identity.ToString()]
}
}
$ExtendedRightUser = New-Object PSObject
$ExtendedRightUser | Add-Member Noteproperty 'ComputerName' "$ComputerName"
$ExtendedRightUser | Add-Member Noteproperty 'Identity' "$Identity"
$ExtendedRightUser | Add-Member Noteproperty 'Reason' "$Reason"
$ExtendedRightUser
}
}
}
function Find-LAPSDelegatedGroups {
[CmdletBinding()]
param(
[String]
$DomainController,
[String]
$Domain,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
Get-NetOU -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData |
Get-ObjectAcl -Domain $Domain -DomainController $DomainController -Credential $Credential -ResolveGUIDs | Where-Object {
($_.ObjectType -like 'ms-Mcs-AdmPwd') -and
($_.ActiveDirectoryRights -match 'ReadProperty')
} | ForEach-Object {
$dn = $_.ObjectDN
$ir = $_.IdentityReference
$DelegatedGroup = New-Object PSObject
$DelegatedGroup | Add-Member NoteProperty 'OrgUnit' "$dn"
$DelegatedGroup | Add-Member Noteproperty 'Delegated Groups' "$ir"
$DelegatedGroup
}
}
function Get-LAPSComputers {
[CmdletBinding()]
Param (
[Parameter(ValueFromPipeline=$True)]
[Alias('HostName')]
[String]
$ComputerName = '*',
[String]
$SPN,
[String]
$Domain,
[String]
$DomainController,
[String]
$ADSpath,
[String]
$SiteName,
[Switch]
$Unconstrained,
[ValidateRange(1,10000)]
[Int]
$PageSize = 200,
[Management.Automation.PSCredential]
$Credential
)
process {
Get-NetComputer -FullData -Filter "(ms-mcs-admpwdexpirationtime=*)" @PSBoundParameters | ForEach-Object {
$HostName = $_.dnshostname
$Password = $_."ms-mcs-admpwd"
If ($_."ms-MCS-AdmPwdExpirationTime" -ge 0) {
$CurrentExpiration = $([datetime]::FromFileTime([convert]::ToInt64($_."ms-MCS-AdmPwdExpirationTime",10)))
}
Else{
$CurrentExpiration = "N/A"
}
$Computer = New-Object PSObject
$Computer | Add-Member NoteProperty 'ComputerName' "$HostName"
$Computer | Add-Member Noteproperty 'Password' "$Password"
$Computer | Add-Member Noteproperty 'Expiration' "$CurrentExpiration"
$Computer
}
}
}

