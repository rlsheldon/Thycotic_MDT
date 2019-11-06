<#  Set-WindowsFeatures.ps1

    Enables:
         Windows Application Guard
         Windows TIFF IFilter
    Disables:
        Work Folders client

    Does not require restart, allowing other tasks to run.

#>

$LogPath = "C:\MININT\SMSOSD\OSDLOGS"
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard, TIFFIFilter `
    -All -NoRestart -LogPath "$LogPath\DISM_EnableFeatures.log"
Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart `
    -LogPath "$LogPath\DISM_RemoveFeature.log"