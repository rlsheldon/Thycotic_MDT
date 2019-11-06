<# Remove-PreInstalledApps.ps1

Removes pre-installed apps using the list specified in the parameter used 
to call the script.

#>
Param([Parameter(Mandatory=$true)][System.String[]]$ListName)

$TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment
$AppList = Get-Content ($TSEnv.Value('DeployRoot') + "\Templates\AppRemovalLists\" + "$ListName")

foreach ($app in $AppList) { 
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -Confirm:$false -ErrorAction SilentlyContinue 
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match $app } | `
        Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue
}