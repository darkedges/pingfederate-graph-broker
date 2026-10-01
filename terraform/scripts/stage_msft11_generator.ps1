$ErrorActionPreference = 'Stop'
$SourceAdminUrl = $env:PF_MSFT11_SOURCE_ADMIN_URL
$LocalAdminUrl = $env:PF_MSFT11_LOCAL_ADMIN_URL
$SigningKeyId = $env:PF_MSFT11_SIGNING_KEY_ID
if ([string]::IsNullOrWhiteSpace($SourceAdminUrl) -or
    [string]::IsNullOrWhiteSpace($LocalAdminUrl) -or
    [string]::IsNullOrWhiteSpace($SigningKeyId)) {
    throw 'Generator staging inputs must be supplied by Terraform.'
}
$username = $env:PINGFEDERATE_PROVIDER_USERNAME
$password = $env:PINGFEDERATE_PROVIDER_PASSWORD
if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
    throw 'PingFederate admin credentials must be present in the Terraform process environment.'
}
if ($LocalAdminUrl -notmatch '^https://(localhost|127\.0\.0\.1)(:\d+)?$') {
    throw 'Local admin URL must be an HTTPS loopback endpoint.'
}

$secret = ConvertTo-SecureString $password -AsPlainText -Force
$credential = [pscredential]::new($username, $secret)
$headers = @{ 'X-XSRF-Header' = 'PingFederate' }
$source = "$SourceAdminUrl/pf-admin-api/v1/sp/tokenGenerators/MSFT11"
$local = "$LocalAdminUrl/pf-admin-api/v1/sp/tokenGenerators"

try {
    $sourceGenerator = Invoke-RestMethod -Uri $source -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 20
    if ($sourceGenerator.pluginDescriptorRef.id -ne 'org.sourceid.wstrust.generator.saml.Saml11TokenGenerator') {
        throw 'The approved MSFT11 source is not a SAML 1.1 token generator.'
    }
    $signingFields = @($sourceGenerator.configuration.fields | Where-Object { $_.name -eq 'Signing Certificate' })
    if ($signingFields.Count -ne 1) {
        throw 'The source generator has no unique signing-certificate field.'
    }
    $fields = @($sourceGenerator.configuration.fields | ForEach-Object {
        @{ name = $_.name; value = if ($_.name -eq 'Signing Certificate') { $SigningKeyId } else { $_.value } }
    })
    $generatorId = 'brokerMsft11'
    try {
        $existing = Invoke-RestMethod -Uri "$local/$generatorId" -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 15
        $existingSigning = @($existing.configuration.fields | Where-Object { $_.name -eq 'Signing Certificate' })
        if ($existing.pluginDescriptorRef.id -ne 'org.sourceid.wstrust.generator.saml.Saml11TokenGenerator' -or
            $existingSigning.Count -ne 1 -or $existingSigning[0].value -ne $SigningKeyId) {
            throw 'Existing local generator differs from the reviewed signer; refusing to overwrite it.'
        }
        Write-Output "generator_id=$generatorId status=already_present signing_key_id=$SigningKeyId"
        exit 0
    } catch {
        if ([int]$_.Exception.Response.StatusCode -ne 404) {
            throw
        }
    }
    $body = @{
        id = $generatorId
        name = 'Directory broker MSFT11 (staged)'
        pluginDescriptorRef = @{ id = 'org.sourceid.wstrust.generator.saml.Saml11TokenGenerator' }
        attributeContract = $sourceGenerator.attributeContract
        configuration = @{ fields = $fields }
    } | ConvertTo-Json -Depth 12 -Compress
    $created = Invoke-RestMethod -Uri $local -Method Post -Authentication Basic -Credential $credential -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20
    $createdSigning = @($created.configuration.fields | Where-Object { $_.name -eq 'Signing Certificate' })
    if ($created.id -ne $generatorId -or $createdSigning.Count -ne 1 -or $createdSigning[0].value -ne $SigningKeyId) {
        throw 'The new local generator did not retain the reviewed signing-key reference.'
    }
    Write-Output "generator_id=$generatorId status=created signing_key_id=$SigningKeyId"
} catch {
    $status = [int]$_.Exception.Response.StatusCode
    if ($status -gt 0) {
        $details = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        $code = if ($details.resultId) { $details.resultId } else { 'unknown' }
        $fields = @($details.validationErrors | ForEach-Object { "$($_.fieldPath):$($_.errorId):$($_.message)" }) -join ','
        throw "SAML generator staging failed (HTTP $status, result=$code, fields=$fields); no configuration values were logged."
    }
    throw "SAML generator staging failed: $($_.Exception.Message)"
}
