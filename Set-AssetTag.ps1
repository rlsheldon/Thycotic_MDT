<#  
    Set-AssetTag.ps1

    Prompts for asset tag number and confirms entry.
    Once confirmed, applies settings via Dell CCTK tool.
#>

[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
Add-Type -AssemblyName PresentationFramework

$TSEnv      = New-Object -ComObject Microsoft.SMS.TSEnvironment
$Type       = $TSEnv.Value('IsLaptop')
$PropOwnTag = "My Organization Name"
$ToolsPath  = $TSEnv.Value('DeployRoot') + "\Tools\x64"
$BIOSPass   = $TSEnv.Value('CUSTOMBIOSPassword')
$OldPass    = $TSEnv.Value('CUSTOMBIOSOldPassword')
$Template   = $TSEnv.Value('DeployRoot') + "\Templates\Dell\BIOSSettings\MySettings.ini"
$LogPath1   = $TSEnv.Value('_SMSTSLogPath') + "\CCTK_AssetTag.log"
$LogPath2   = $TSEnv.Value('_SMSTSLogPath') + "\CCTK_Settings.log"
$LogPath3   = $TSEnv.Value('_SMSTSLogPath') + "\CCTK_PropOwnTag.log"
$LogPath4   = $TSEnv.Value('_SMSTSLogPath') + "\CCTK_BIOSPassword.log"
$success    = 0

switch ($Type) {
    'True' {
        while ($success -eq 0) {
            $title      = "Laptop Asset Tag"
            $msg        = "Please enter the affixed Asset Tag:"
            $assetTag   = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title, $null, 50, 50)

            if ($null -ne $assetTag) {
                $text       = "You entered:`n`n`"$assetTag`"`n`nIs this correct?"
                $caption    = "Asset Tag Confirmation"
                $confirm    = [System.Windows.MessageBox]::Show($text,$caption,'YesNo','Question')
    
                switch ($confirm) {
                    'Yes'   { $success = 1 }
                    'No'    { $success = 0 }
                }
            }
        }        
        
        if($null -eq $OldPass -or $OldPass -eq "" -or $OldPass -eq " ") { 
            & "$ToolsPath\cctk.exe" --Asset=$assetTag --logFile=$LogPath1
            & "$ToolsPath\cctk.exe" --inFile=$Template --logFile=$LogPath2
            & "$ToolsPath\cctk.exe" --propOwnTag=$PropOwnTag --UefiBootPathSecurity=AlwaysExceptInternalHdd --logFile=$LogPath3
            & "$ToolsPath\cctk.exe" --SetupPwd=$BIOSPass --logFile=$LogPath4 
        }
        else { 
            & "$ToolsPath\cctk.exe" --Asset=$assetTag --logFile=$LogPath1 --ValSetupPwd=$OldPass
            & "$ToolsPath\cctk.exe" --inFile=$Template --logFile=$LogPath2  --ValSetupPwd=$OldPass
            & "$ToolsPath\cctk.exe" --propOwnTag=$PropOwnTag --UefiBootPathSecurity=AlwaysExceptInternalHdd --logFile=$LogPath3 --ValSetupPwd=$OldPass
            & "$ToolsPath\cctk.exe" --SetupPwd=$BIOSPass --ValSetupPwd=$OldPass --logFile=$LogPath4 
        }
    }

    'False' {
        & "$ToolsPath\cctk.exe" --inFile=$Template --logFile=$LogPath2
        & "$ToolsPath\cctk.exe" --propOwnTag=$PropOwnTag --logFile=$LogPath3
    }
}

