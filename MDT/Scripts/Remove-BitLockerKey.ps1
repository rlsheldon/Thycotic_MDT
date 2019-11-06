<#  Remove-BitLockerKey.ps1

    Removes BitLocker key saved in the C:\ root folder after encryption completes

#>

#Remove-Item -Path C:\ -Filter *.txt -Force -Confirm:$false
#Get-ChildItem -Path C:\ -Filter *.txt -Exclude "ARCAOS.txt" | Remove-Item -Force -Confirm:$false
Get-ChildItem -Path C:\ -Filter *.txt | Remove-Item -Force -Confirm:$false
