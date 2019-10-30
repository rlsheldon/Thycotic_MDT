<#  
    Add-LocalAdministrator.ps1

    Creates local admin user with pre-set random password.
    Adds the user to the local Administrators group.
#>

$TSEnv          = New-Object -ComObject Microsoft.SMS.TSEnvironment
$userPassword   = ConvertTo-SecureString -String $TSEnv.Value('CUSTOMAdminPassword') -AsPlainText -Force
$userName       = "<UserName>"
$userFullName   = "<User Display Name>"
$groupName      = "Administrators"

New-LocalUser `
    -Name $userName `
    -FullName $userFullName `
    -Password $userPassword `
    -PasswordNeverExpires `
    -AccountNeverExpires `
    -UserMayNotChangePassword

Add-LocalGroupMember `
    -Group $groupName `
    -Member $userName `
    -Confirm:$false