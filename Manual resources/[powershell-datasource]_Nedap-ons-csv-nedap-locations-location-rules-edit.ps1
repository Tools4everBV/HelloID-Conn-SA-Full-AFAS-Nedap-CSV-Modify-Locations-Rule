$script:Uri = $NedapOnsConnectionURL
$script:CertificatePath = $NedapOnsCertificatePFX
$script:CertificatePassword = $NedapOnsCertificatePassword

function Get-ResponseStream {
    [cmdletbinding()]
    param(
        $Exception
    )
    $result = $Exception.Exception.Response.GetResponseStream()
    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
    $responseReader = $reader.ReadToEnd()
    $reader.Dispose()
    Write-Output  $responseReader
}

function Import-NedapCertificate {
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "The path to the pfx certificate, it must be accessible by the agent.")]
        $CertificatePath,

        [Parameter(Mandatory = $true)]
        $CertificatePassword
    )

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
    $cert.Import($CertificatePath, $CertificatePassword, 'UserKeySet')
    if ($cert.NotAfter -le (Get-Date)) {
        throw "Certificate has expired on $($cert.NotAfter)..."
    }
    $script:Certificate = $cert
}

function Get-NedapLocationList {
    [Cmdletbinding()]
    param()  # Two Script Parameters ([$script:uri] Nedap BaseUri [$script:Certificate] Nedap Certificate )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $webRequestSplatting = @{
        Uri             = "$($script:uri)/t/locations"
        Method          = "Get"
        Certificate     = $script:Certificate
        Headers         = (@{"accept" = "application/json" })
        ContentType     = "application/json; charset=utf-8"
        UseBasicParsing = $true
    }
    try {
        $response = Invoke-WebRequest @webRequestSplatting
        $locations = $response.Content | ConvertFrom-Json
        Write-Output  $locations.locations
    }
    catch {
        if ($_.ErrorDetails) {
            $errorReponse = $_.ErrorDetails
        }
        elseif ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $errorReponse = $reader.ReadToEnd()
            $reader.Dispose()
        }
        throw "Could not read Nedap locations from '$uri', message: $($_.exception.message), $($errorReponse.error)"
    }
}
Import-NedapCertificate -CertificatePath $script:CertificatePath  -CertificatePassword $script:CertificatePassword
$availablelocations = Get-NedapLocationList | Select-Object id, name, identificationNo

ForEach ($availablelocation in $availablelocations) {            
    $returnObject = @{ Id = $availablelocation.id; DisplayName = $availablelocation.name; identificatonNo = $availablelocation.identificationNo }
    Write-Output $returnObject                
}
