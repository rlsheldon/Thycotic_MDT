<# 
    WinPE-UpdateDellBIOS.ps1

    Searches %DEPLOYROOT%\BIOSUpdates for the machine model and
    applies the update during the first restart.

#>

$TSEnv          = New-Object -ComObject Microsoft.SMS.TSEnvironment
$Model          = $TSEnv.Value('Model')
$IsLaptop       = $TSEnv.Value('IsLaptop')
$BiosPassword   = $TSEnv.Value('CUSTOMBIOSPassword')
$BiosPath       = $TSEnv.Value('DeployRoot') + "\BIOSUpdates\" + "$Model"
$UpdaterName    = Get-ChildItem -File -Name -Filter *.exe -Path $BiosPath
$UpdaterPath    = "$BiosPath" + "\" + "$UpdaterName"
$ToolsPath      = $TSEnv.Value('DeployRoot') + "\Tools\x64"
$SerialNumber   = $TSEnv.Value('SerialNumber')
$LoggingPath    = $TSEnv.Value('X:\MININT\SMSOSD\OSDLOGS')
$LoggingPath    = $LoggingPath + "\" + $SerialNumber + "_BIOSUpdate.log"

switch($IsLaptop){
    'True'  { & "$ToolsPath\Flash64W.exe" /s /f /b="$UpdaterPath" /p="$BiosPassword" /l="$LoggingPath" }
    'False' { & "$ToolsPath\Flash64W.exe" /s /f /b="$UpdaterPath" /l="$LoggingPath" }
}