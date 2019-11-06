<#  
    Remove-BitLockerKey.ps1

    Removes BitLocker key saved in the C:\ root folder after encryption is enabled.
#>

Get-ChildItem -Path C:\ -Filter *.txt | Remove-Item -Force -Confirm:$false
