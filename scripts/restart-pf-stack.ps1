$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $root 'compose.yaml'
docker compose -f $compose --project-directory $root restart pingfederate | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'PingFederate restart failed.' }
$healthy = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $status = docker inspect --format '{{.State.Health.Status}}' pingfederate-broker 2>$null
    if ($LASTEXITCODE -eq 0 -and $status -eq 'healthy') { $healthy = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $healthy) { throw 'PingFederate did not become healthy after restart.' }
foreach ($service in @('broker', 'portal')) {
    $running = docker compose -f $compose --project-directory $root --profile broker --profile portal ps --status running --quiet $service
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect local $service container." }
    if (-not [string]::IsNullOrWhiteSpace(($running -join ''))) {
        docker compose -f $compose --project-directory $root --profile broker --profile portal restart $service | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restart local $service after PingFederate." }
    }
}
Write-Output 'PingFederate and its running network-sharing services are ready.'
