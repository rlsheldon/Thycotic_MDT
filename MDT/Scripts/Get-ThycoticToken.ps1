<#
    Get-ThycoticToken.ps1

    Prompts for credentials and returns token for API access to Thycotic Secret Server.
#>

#   Assumes 2FA is enabled by default
Param(
    [Bool]$UseTwoFactor         = $true,
    [String]$ThycoticUsername   = 0,
    [String]$ThycoticPassword   = 0,
    [String]$ThycoticDomain     = "<DOMAIN>",
    [String]$ThycoticTokenRoute = "https://<DOMAIN>.secretservercloud.com/oauth2/token"
    )

# Credential prompt loop; restarts in case of bad credentials
$tokenSuccess = 0
while ($tokenSuccess -eq 0) {
    if (($ThycoticUsername -eq 0) -or ($ThycoticPassword -eq 0)) {
        $ThycoticCredsMessage = "Enter your Thycotic username and password for the $ThycoticDomain domain:"
        if ($ThycoticUsername -eq 0) { $ThycoticUsername = $null }
        $ThycoticCreds = Get-Credential -Message $ThycoticCredsMessage -UserName $ThycoticUsername
        $ThycoticUsername = $ThycoticCreds.UserName
        # Need to convert SecureString to String before sending via API
        $ThycoticPassword = $ThycoticCreds.GetNetworkCredential().Password
    }

    # Create array for credential call
    $creds = @{
        username    = $ThycoticUsername
        password    = $ThycoticPassword
        domain      = $ThycoticDomain
        grant_type  = "password"
    };

    # Create API header block
    $headers = $null
    If ($UseTwoFactor) {
        [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
        $title  = "Thycotic Secret Server"
        $msg    = "Please enter your OTP for 2FA:"
        $headers = @{
            "OTP" = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title, $null, 50, 50)
        }
    }

    try
    {
        # Specify TLS 1.2; failure to specify can cause connection errors
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response       = Invoke-RestMethod "$ThycoticTokenRoute" -Method Post -Body $creds -Headers $headers
        $token          = $response.access_token
        $tokenSuccess   = 1
    }
    catch
    {
        $result                         = $_.Exception.Response.GetResponseStream();
        $reader                         = New-Object System.IO.StreamReader($result);
        $reader.BaseStream.Position     = 0;
        $reader.DiscardBufferedData();
        $responseBody                   = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Host "ERROR: $($responseBody.error)"
        $ThycoticUsername               = 0
    }
}

return $token