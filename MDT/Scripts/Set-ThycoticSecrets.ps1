<# 
    Set-ThycoticSecrets.ps1

    Uses Thycotic Secret Server to pull domain admin credentials and
    applies those credentials to the appropriate values in the MDT
    task sequence. 

    Reference:
    https://thycotic.force.com/support/s/article/REST-API-PowerShell-Scripts-Getting-Started
    https://$SSDomain/Documents/restapi/OAuth/
    https://$SSDomain/Documents/restapi/TokenAuth/
#>

$TSEnv              = New-Object -ComObject Microsoft.SMS.TSEnvironment
$SSDomain           = "<Secret Server Domain>"      # e.g. my.secretservercloud.com
$ADDomain           = "<Active Directory Domain>"   # e.g. domain.local
$MachineFolder      = "<Machine Folder Number>"
$MachineTemplate    = 6003                          # Windows Account template
$BIOSFolder         = "<BIOS Folder Number>"
$BIOSTemplate       = "<BIOS Template ID>"
$AdminName          = "<Local Admin Name>"          # e.g. MyAdmin


$application        = "https://$SSDomain";
$api                = "$application/api/v1"
$tokenRoute         = "$application/oauth2/token"


Function Get-SecretValue {
    Param (
        $FieldName,
        $Secret
    )

    $FieldValue = $Secret.items | ?{ $_.FieldName -eq "$FieldName" }
    $FieldValue = $FieldValue.itemValue
    return $FieldValue
}

Function Get-Secret {
    Param(
        [Parameter(Mandatory=$true)]$Headers,
        [Parameter(Mandatory=$true)]$Api,
        [Parameter(Mandatory=$true)]$SecretId
    )

    $secret = Invoke-RestMethod $api"/secrets/$secretId/" -Headers $headers
    return $secret
}
Function Find-Secret {
    Param(
        [Parameter(Mandatory=$true)]$Headers,
        [Parameter(Mandatory=$true)]$Api,
        [Parameter(Mandatory=$true)]$SearchText
    )
    
    try
    {
        #$UrlSearchText = [System.Web.HttpUtility]::UrlEncode("$SearchText")
        #   Note: Method System.Web.HttpUtility is not availabe in WinPE-NetFX
        $UrlSearchText  = "$SearchText"
        $filters        = "?filter.searchtext=$UrlSearchText"
              
        $result = Invoke-RestMethod "$api/secrets$filters" -Headers $headers
    
        if($result.total -eq 0) { return $null }

        else { return $result.records[0] }
    }
    catch [System.Net.WebException]
    {
        Write-Host "----- Exception -----"
        Write-Host  $_.Exception
        Write-Host  $_.Exception.Response.StatusCode
        Write-Host  $_.Exception.Response.StatusDescription
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Host  $responseBody.errorCode " - " $responseBody.message
        foreach($modelState in $responseBody.modelState)
        {
            $modelState
        }
    }

}

Function New-Secret {
    Param(
        [Parameter(Mandatory=$true)]$Headers,
        [Parameter(Mandatory=$true)]$Api,
        [Parameter(Mandatory=$true)]$TemplateId,
        [Parameter(Mandatory=$true)]$SecretName,
        [Parameter(Mandatory=$true)]$SecretMachine,
        [Parameter(Mandatory=$false)]$SecretUsername,
        [Parameter(Mandatory=$true)]$SecretPassword,
        $SecretNotes                           = $null,
        $SecretFolderId                        = $null,
        $SecretLauncherConnectAsSecretId       = $null,
        $SecretAutoChangeEnabled               = $null,
        $SecretRequiresComment                 = $null,
        $SecretCheckoutEnabled                 = $null,
        $SecretCheckoutIntervalMinutes         = $null,
        $SecretCheckOutChangePasswordEnabled   = $null,
        $SecretProxyEnabled                    = $null,
        $SecretSessionRecordingEnabled         = $null,
        $SecretPasswordTypeWebScriptId         = $null,
        $SecretSiteId                          = 1,
        $SecretEnableInheritSecretPolicy       = $true,
        $SecretPolicyId                        = $null
    )
    
    try {
        #stub
        $secret = Invoke-RestMethod $api"/secrets/stub?filter.secrettemplateid=$templateId" -Headers $headers

        #modify
        $secret.name                = "$SecretName"
        $secret.secretTemplateId    = $templateId

        foreach($item in $secret.items) {
            if($item.fieldName -eq "Machine")  { $item.itemValue = "$SecretMachine" }
            if($item.fieldName -eq "Resource") { $item.itemValue = "$SecretMachine" }
            if($item.fieldName -eq "Username") { $item.itemValue = "$SecretUsername" }
            if($item.fieldName -eq "Password") { $item.itemValue = "$SecretPassword"}
            if($item.fieldName -eq "Notes")    { $item.itemValue = "$SecretNotes"}
        }

        if($null -ne $SecretFolderId)                       { $secret.folderId                      = $SecretFolderId }
        if($null -ne $SecretLauncherConnectAsSecretId)      { $secret.LauncherConnectAsSecretId     = $SecretLauncherConnectAsSecretId }
        if($null -ne $SecretAutoChangeEnabled)              { $secret.AutoChangeEnabled             = $SecretAutoChangeEnabled }
        if($null -ne $SecretRequiresComment)                { $secret.RequiresComment               = $SecretRequiresComment }
        if($null -ne $SecretCheckoutEnabled)                { $secret.CheckOutEnabled               = $SecretCheckoutEnabled }
        if($null -ne $SecretCheckoutIntervalMinutes)        { $secret.CheckOutIntervalMinutes       = $SecretCheckoutIntervalMinutes }
        if($null -ne $SecretCheckOutChangePasswordEnabled)  { $secret.CheckOutChangePasswordEnabled = $SecretCheckOutChangePasswordEnabled }
        if($null -ne $SecretProxyEnabled)                   { $secret.ProxyEnabled                  = $SecretProxyEnabled }
        if($null -ne $SecretSessionRecordingEnabled)        { $secret.SessionRecordingEnabled       = $SecretSessionRecordingEnabled }
        if($null -ne $SecretPasswordTypeWebScriptId)        { $secret.PasswordTypeWebScriptId       = $SecretPasswordTypeWebScriptId }
        if($null -ne $SecretSiteId)                         { $secret.SiteId                        = $SecretSiteId }
        if($null -ne $SecretEnableInheritSecretPolicy)      { $secret.EnableInheritSecretPolicy     = $SecretEnableInheritSecretPolicy }
        if($null -ne $SecretPolicyId)                       { $secret.SecretPolicyId                = $SecretPolicyId }

        $jsonSecret = $secret | ConvertTo-Json

        #create
        $secret = Invoke-RestMethod $api"/secrets/" -Method Post -Body $jsonSecret -Headers $headers -ContentType "application/json"
        return
    }
    catch [System.Net.WebException] {
        Write-Host "----- Exception -----"
        Write-Host  $_.Exception
        Write-Host  $_.Exception.Response.StatusCode
        Write-Host  $_.Exception.Response.StatusDescription
        $result                     = $_.Exception.Response.GetResponseStream()
        $reader                     = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody               = $reader.ReadToEnd()
    
        return $responseBody 
    }
}

Function Set-Secret {
    Param(
        [Parameter(Mandatory=$true)]$SecretId,
        [Parameter(Mandatory=$true)]$Headers,
        [Parameter(Mandatory=$true)]$Api,
        $SecretMachine                       = $null,
        $SecretName                          = $null,
        $SecretUsername                      = $null,
        $SecretPassword                      = $null,
        $SecretNotes                         = $null,
        $SecretFolderId                      = $null,
        $SecretLauncherConnectAsSecretId     = $null,
        $SecretAutoChangeEnabled             = $null,
        $SecretIsDoubleLock                  = $null,
        $SecretActive                        = $null,
        $SecretRequiresComment               = $null,
        $SecretCheckoutEnabled               = $null,
        $SecretCheckoutIntervalMinutes       = $null,
        $SecretCheckOutChangePasswordEnabled = $null,
        $SecretProxyEnabled                  = $null,
        $SecretSessionRecordingEnabled       = $null,
        $SecretPasswordTypeWebScriptId       = $null,
        $SecretSiteId                        = $null,
        #$SecretEnableInheritSecretPolicy     = $null,
        $SecretPolicyId                      = $null
        #$SecretAutoChangeNextPassword        = $null
    )
    
    try
    {  
        #get
        $secret = Invoke-RestMethod $api"/secrets/$secretId/" -Headers $headers
    
        #modify
        foreach($item in $secret.items) {
            if(($null -ne $SecretMachine)  -and ($item.fieldName -eq "Machine"))  { $item.itemValue = "$SecretMachine" }
            if(($null -ne $SecretMachine)  -and ($item.fieldName -eq "Resource")) { $item.itemValue = "$SecretMachine" }
            if(($null -ne $SecretUsername) -and ($item.fieldName -eq "Username")) { $item.itemValue = "$SecretUsername" }
            if(($null -ne $SecretPassword) -and ($item.fieldName -eq "Password")) { $item.itemValue = "$SecretPassword"}
            if(($null -ne $SecretNotes)    -and ($item.fieldName -eq "Notes"))    { $item.itemValue = "$SecretNotes"}
        }

        if($null -ne $SecretName)                           { $secret.Name                          = "$SecretName" }
        if($null -ne $SecretActive)                         { $secret.Active                        = $SecretActive }
        if($null -ne $SecretLauncherConnectAsSecretId)      { $secret.LauncherConnectAsSecretId     = $SecretLauncherConnectAsSecretId }
        if($null -ne $SecretAutoChangeEnabled)              { $secret.AutoChangeEnabled             = $SecretAutoChangeEnabled }
        if($null -ne $SecretRequiresComment)                { $secret.RequiresComment               = $SecretRequiresComment }
        if($null -ne $SecretCheckoutEnabled)                { $secret.CheckOutEnabled               = $SecretCheckoutEnabled }
        if($null -ne $SecretCheckoutIntervalMinutes)        { $secret.CheckOutIntervalMinutes       = $SecretCheckoutIntervalMinutes }
        if($null -ne $SecretCheckOutChangePasswordEnabled)  { $secret.CheckOutChangePasswordEnabled = $SecretCheckOutChangePasswordEnabled }
        if($null -ne $SecretProxyEnabled)                   { $secret.ProxyEnabled                  = $SecretProxyEnabled }
        if($null -ne $SecretSessionRecordingEnabled)        { $secret.SessionRecordingEnabled       = $SecretSessionRecordingEnabled }
        if($null -ne $SecretPasswordTypeWebScriptId)        { $secret.PasswordTypeWebScriptId       = $SecretPasswordTypeWebScriptId }
        if($null -ne $SecretSiteId)                         { $secret.SiteId                        = $SecretSiteId }
        #if($null -ne $SecretEnableInheritSecretPolicy)      { $secret.EnableInheritSecretPolicy     = $SecretEnableInheritSecretPolicy }
        if($null -ne $SecretPolicyId)                       { $secret.SecretPolicyId                = $SecretPolicyId }
        #if($null -ne $SecretAutoChangeNextPassword)         { $secret.AutoChangeNextPassword        = "$SecretAutoChangeNextPassword" }
        
        $SecretJson = $secret | ConvertTo-Json
       
        #update
        $secret = Invoke-RestMethod $api"/secrets/$secretId" -Method Put -Body $SecretJson -Headers $headers -ContentType "application/json"
    
        #$secretUpdate = $secret | ConvertTo-Json
        #Write-Host $secretUpdate
    }
    catch [System.Net.WebException]
    {
        Write-Host "----- Exception -----"
        Write-Host  $_.Exception
        Write-Host  $_.Exception.Response.StatusCode
        Write-Host  $_.Exception.Response.StatusDescription
        $result                     = $_.Exception.Response.GetResponseStream()
        $reader                     = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody               = $reader.ReadToEnd()
    
        Write-Host $responseBody 
    }

}

Function Get-SecretServerToken {
    Param(
    $UseTwoFactor   = $true,
    $Username       = 0,
    $Password       = 0,
    $Domain         = "<DOMAIN>",
    $TokenRoute     = "https://<DOMAIN>/oauth2/token"
    )

    $tokenSuccess = 0
    while ($tokenSuccess -eq 0) {
        if (($Username -eq 0) -or ($Password -eq 0)) {
            $ThycoticCredsMessage   = "Enter your Thycotic username and password for the $Domain domain:"
            if ($Username -eq 0) { $Username = $null }
            $ThycoticCreds          = Get-Credential -Message $ThycoticCredsMessage -UserName $Username
            $Username               = $ThycoticCreds.UserName
            $Password               = $ThycoticCreds.GetNetworkCredential().Password
        }

        $creds = @{
            username    = $Username
            password    = $Password
            domain      = $Domain
            grant_type  = "password"
        };

        $headers = $null
        If ($UseTwoFactor) {
            [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
            $title      = "Thycotic Secret Server"
            $msg        = "Please enter your OTP for 2FA:"
            $headers    = @{ "OTP" = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title, $null, 50, 50) }
        }

        try {
            $response       = Invoke-RestMethod "$TokenRoute" -Method Post -Body $creds -Headers $headers
            $token          = $response.access_token
            $tokenSuccess   = 1
            #break
        }
        catch {
            $result                     = $_.Exception.Response.GetResponseStream();
            $reader                     = New-Object System.IO.StreamReader($result);
            $reader.BaseStream.Position = 0;
            $reader.DiscardBufferedData();
            $responseBody               = $reader.ReadToEnd() | ConvertFrom-Json
            Write-Host "ERROR: $($responseBody.error)"
            $Username                   = 0
        }
    }

    return $token
}
    
Function New-RandomPassword {
    Param(
        [Parameter(Mandatory=$true)][ValidateRange(1,32767)]$Length,
        $Symbols      = $true,
        $Numbers      = $true,
        $UpperCase    = $true,
        $LowerCase    = $true,
        $AvoidSimilar = $true
    )

    # Symbols  !@#$%^&*()_-+=[]{};:<>./?
    $SymbolRange = $null
    if($Symbols) {
        $SymbolRange = (33..33) + (35..38) + (40..43) + (45..47) + (58..64) + (91..91) + `
            (93..95) + (123..123) + (125..125)
    }

    $NumberRange = $null
    if($Numbers){ 
        # Numbers 234679
        if($AvoidSimilar) { $NumberRange = (50..52) + (54..55) + (57..57) }
        # Numbers 1234567890
        else { $NumberRange = (48..57) }
    }

    $UpperCaseRange = $null
    if($UpperCase) {
        # Letters  ACDEFGHJKLMNPQRTWXYZ
        if($AvoidSimilar) { $UpperCaseRange = (65..65) + (67..72) + (74..78) + (80..82) + (84..84) + (87..90) }
        # Letters  ABCDEFGHIJKLMNOPQRSTUVWXYZ
        else { $UpperCaseRange = (65..90) }
    }

    $LowerCaseRange = $null
    if($LowerCase) { 
        # Letters  abcdefghijkmnpqrstwxyz
        if($AvoidSimilar) { $LowerCaseRange = (97..107) + (109..110) + (112..116) + (119..122) }
        # Letters  abcdefghijklmnopqrstuvwxyz
        else { $LowerCaseRange = (97..122) }
    }

    $Range = $SymbolRange + $NumberRange + $UpperCaseRange + $LowerCaseRange
    $Password = [string]::Join("",((1..$Length) | %{ $Range | Get-Random -ErrorAction SilentlyContinue } `
        | %{ [char]$_ }))
    
    return $Password
}

#   Retrieve API token from Thycotic
#   NOTE:   Following method use to call interactive logon as TS scripts are normally called from
#           a hidden window, preventing view from the console.

$scriptPath = $TSEnv.Value('DEPLOYROOT') + "\Scripts\Get-ThycoticToken.ps1"

$pinfo                          = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName                 = "cmd.exe"
$pinfo.RedirectStandardOutput   = $true
$pinfo.RedirectStandardError    = $true
$pinfo.UseShellExecute          = $false
$pinfo.Arguments                = "/C powershell -ExecutionPolicy Bypass -File $scriptpath"
$pinfo.WindowStyle              = "Minimized"

$p              = New-Object System.Diagnostics.Process
$p.StartInfo    = $pinfo
$p.Start()      | Out-Null
$p.WaitForExit()
$stdOut         = $p.StandardOutput.ReadToEnd()
$stdErr         = $p.StandardError.ReadToEnd()

$token          = $stdOut

$headers = New-Object "System.Collections.Generic.Dictionary[[string],[string]]"
$headers.Add("Authorization", "Bearer $token")

#   Create secret for local admin account
$MachineName    = $TSEnv.Value('OSDComputerName')
$SecretMachine  = $MachineName + ".$ADDomain"
$SecretName     = $SecretMachine + "\$AdminName"
$SecretUsername = "$AdminName"
$SecretPassword = New-RandomPassword -Length 24 -Symbols $false
$TSEnv.Value('CUSTOMAdminPassword') = $SecretPassword

$MachineSecret  = Find-Secret -Headers $headers -Api $api -SearchText "$SecretName"

if($null -eq $MachineSecret) {
#   No secret exists
    New-Secret `
        -Api $api `
        -Headers $headers `
        -TemplateId $MachineTemplate `
        -SecretName $SecretName `
        -SecretMachine $SecretMachine `
        -SecretUsername $SecretUsername `
        -SecretPassword $SecretPassword `
        -SecretFolderId $MachineFolder `
        -SecretAutoChangeEnabled $true
}
else{
#   Update existing secret
    Set-Secret `
        -Api $api `
        -Headers $headers `
        -SecretId $MachineSecret.Id `
        -SecretActive $true `
        -SecretAutoChangeEnabled $true `
        -SecretEnableInheritSecretPolicy $true `
        -SecretName $SecretName `
        -SecretMachine $SecretMachine `
        -SecretUsername $SecretUsername `
        -SecretPassword $SecretPassword
}

#   Create secret for laptop BIOS Password
if($TSEnv.Value('IsLaptop') -eq "True") {
    $BIOSSecretName     = $SecretMachine + "\BIOS"
    $BIOSSecretPassword = New-RandomPassword -Length 16 -Symbols $false
    $TSEnv.Value('CUSTOMBIOSPassword')  = "$BIOSSecretPassword"

    $BIOSMachineSecret = Find-Secret -Headers $headers -Api $api -SearchText "$BIOSSecretName"

    if($null -eq $BIOSMachineSecret) {
    #   No secret exists
        New-Secret `
            -Api $api `
            -Headers $headers `
            -TemplateId $BIOSTemplate `
            -SecretName "$BIOSSecretName" `
            -SecretMachine "$SecretMachine" `
            -SecretPassword "$BIOSSecretPassword" `
            -SecretFolderId $BIOSFolder `
    }
    else{
    #   Retrieve old password so we can change it    
        $OldPasswordSecret = Get-Secret -Headers $headers -Api $api -SecretId $BIOSMachineSecret.Id
        $OldPassword       = Get-SecretValue -Secret $OldPasswordSecret -FieldName "Password"
        $TSEnv.Value('CUSTOMBIOSOldPassword') = $OldPassword

    #   Update existing secret
        Set-Secret `
            -Api $api `
            -Headers $headers `
            -SecretId $BIOSMachineSecret.Id `
            -SecretPassword $BIOSSecretPassword
    }
}