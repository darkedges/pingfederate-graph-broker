$ErrorActionPreference = 'Stop'
$adminUrl = $env:PF_LOCAL_ADMIN_URL
if ($adminUrl -notmatch '^https://(localhost|127\.0\.0\.1)(:\d+)?$') {
    throw 'Generator-group setup is restricted to the HTTPS loopback PingFederate admin endpoint.'
}
$username = $env:PINGFEDERATE_PROVIDER_USERNAME
$password = $env:PINGFEDERATE_PROVIDER_PASSWORD
if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
    throw 'PingFederate admin credentials must be present in the Terraform process environment.'
}
$credential = [pscredential]::new($username, (ConvertTo-SecureString $password -AsPlainText -Force))
$headers = @{ 'X-XSRF-Header' = 'PingFederate' }
$base = "$adminUrl/pf-admin-api/v1/oauth/tokenExchange/generator"
$groupId = 'brokerSaml11Group'
$generatorId = 'brokerMsft11'
$samlType = 'urn:ietf:params:oauth:token-type:saml1'
try {
    $group = Invoke-RestMethod -Uri "$base/groups/$groupId" -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 20
} catch {
    if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
    $body = @{
        id = $groupId
        name = 'Directory broker SAML 1.1 generator group'
        resourceUris = @()
        generatorMappings = @(@{
            requestedTokenType = $samlType
            tokenGenerator = @{ id = $generatorId }
            defaultMapping = $true
        })
    } | ConvertTo-Json -Depth 8 -Compress
    $group = Invoke-RestMethod -Uri "$base/groups" -Method Post -Authentication Basic -Credential $credential -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20
}
$mappings = @($group.generatorMappings)
if ($group.id -ne $groupId -or $mappings.Count -ne 1 -or
    $mappings[0].requestedTokenType -ne $samlType -or
    $mappings[0].tokenGenerator.id -ne $generatorId -or
    $mappings[0].defaultMapping -ne $true) {
    throw 'Existing localhost generator group does not match the reviewed SAML 1.1-only mapping.'
}
$settings = Invoke-RestMethod -Uri "$base/settings" -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 20
if ($settings.defaultGeneratorGroupRef.id -and $settings.defaultGeneratorGroupRef.id -ne $groupId) {
    throw 'An unrelated default generator group is already configured; refusing to replace it.'
}
if ($settings.defaultGeneratorGroupRef.id -ne $groupId) {
    $body = @{ defaultGeneratorGroupRef = @{ id = $groupId } } | ConvertTo-Json -Depth 4 -Compress
    $settings = Invoke-RestMethod -Uri "$base/settings" -Method Put -Authentication Basic -Credential $credential -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20
}
if ($settings.defaultGeneratorGroupRef.id -ne $groupId) {
    throw 'PingFederate did not retain the localhost default SAML generator group.'
}
Write-Output "generator_group=$groupId default=true token_type=saml1 generator=$generatorId"
