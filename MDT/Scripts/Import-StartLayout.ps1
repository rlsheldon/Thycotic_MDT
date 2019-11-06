<# Import-StartLayout.ps1

Imports start layout specified in passed paramter. Layouts can be found in 
%DEPLOYROOT%\Templates\StartLayouts.

#>
Param([Parameter(Mandatory=$true)][System.String[]]$LayoutName)

$TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment

Import-StartLayout -LayoutPath ($TSEnv.Value('DeployRoot') + "\Templates\StartLayouts\" + "$LayoutName") -MountPath C:\