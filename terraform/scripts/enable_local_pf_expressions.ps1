$ErrorActionPreference = 'Stop'
$adminUrl = $env:PF_LOCAL_ADMIN_URL
if ($adminUrl -notmatch '^https://(localhost|127\.0\.0\.1)(:\d+)?$') {
    throw 'Expression setup is restricted to the HTTPS loopback PingFederate admin endpoint.'
}
$username = $env:PINGFEDERATE_PROVIDER_USERNAME
$password = $env:PINGFEDERATE_PROVIDER_PASSWORD
if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
    throw 'PingFederate admin credentials must be present in the Terraform process environment.'
}
$credential = [pscredential]::new($username, (ConvertTo-SecureString $password -AsPlainText -Force))
$uri = "$adminUrl/pf-admin-api/v1/configStore/org.sourceid.common.ExpressionManager/evaluateExpressions"
$headers = @{ 'X-XSRF-Header' = 'PingFederate' }
$current = Invoke-RestMethod -Uri $uri -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 20
if ($current.stringValue -eq 'true') {
    Write-Output 'local_pf_expressions=enabled restart=not_needed'
    exit 0
}
$body = @{ id = 'evaluateExpressions'; type = 'STRING'; stringValue = 'true' } | ConvertTo-Json -Compress
$updated = Invoke-RestMethod -Uri $uri -Method Put -Authentication Basic -Credential $credential -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20
if ($updated.stringValue -ne 'true') {
    throw 'PingFederate did not accept the expression setting.'
}
docker compose -f ../compose.yaml --project-directory .. restart pingfederate | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Local PingFederate restart failed.' }
$healthy = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $status = docker inspect --format '{{.State.Health.Status}}' pingfederate-broker 2>$null
    if ($LASTEXITCODE -eq 0 -and $status -eq 'healthy') { $healthy = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $healthy) { throw 'Local PingFederate did not become healthy after enabling expressions.' }
$verified = Invoke-RestMethod -Uri $uri -Authentication Basic -Credential $credential -Headers $headers -TimeoutSec 20
if ($verified.stringValue -ne 'true') { throw 'Expression setting was not retained after restart.' }
# Broker and portal share PF's network namespace. A PF restart can leave
# already-running dependents attached to the previous namespace.
foreach ($service in @('broker', 'portal')) {
    $running = docker compose -f ../compose.yaml --project-directory .. --profile broker --profile portal ps --status running --quiet $service
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect local $service container." }
    if (-not [string]::IsNullOrWhiteSpace(($running -join ''))) {
        docker compose -f ../compose.yaml --project-directory .. --profile broker --profile portal restart $service | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restart local $service after PingFederate." }
    }
}
Write-Output 'local_pf_expressions=enabled restart=completed'
