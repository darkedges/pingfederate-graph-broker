$ErrorActionPreference = 'Stop'
$chart = Join-Path $PSScriptRoot '../helm/broker'
function Render-Chart([string[]] $Extra, [bool] $ShouldPass = $true) {
    $result = & helm template entraidbroker $chart --namespace entraidbroker @Extra 2>&1
    $ok = $LASTEXITCODE -eq 0
    if ($ok -ne $ShouldPass) { throw "Unexpected Helm rendering result: $result" }
    return ($result -join "`n")
}
$base = Render-Chart @()
if ($base -match 'kind: Ingress') { throw 'Ingress must default to disabled.' }
if ($base -notmatch 'command: \["/broker", "-healthcheck"\]') { throw 'Missing loopback exec probe.' }
$portal = @('--set','ingress.portal.enabled=true','--set','ingress.portal.className=test',
    '--set','ingress.portal.host=portal.example.com','--set','ingress.portal.tlsSecretName=edge-tls')
$rendered = Render-Chart $portal
if ($rendered -notmatch 'kind: Ingress' -or $rendered -notmatch 'number: 443') { throw 'Portal ingress missing HTTPS backend.' }
$both = $portal + @('--set','ingress.broker.enabled=true','--set','ingress.broker.className=test',
    '--set','ingress.broker.host=broker.example.com','--set','ingress.broker.tlsSecretName=edge-tls')
$null = Render-Chart $both $false
$null = Render-Chart ($both + @('--set','broker.service.enabled=true')) $false
$ready = Render-Chart ($both + @('--set','broker.service.enabled=true','--set','ingress.broker.allowHTTPUpstream=true'))
if ([regex]::Matches($ready, 'kind: Ingress').Count -ne 2 -or $ready -notmatch 'number: 8080') { throw 'Separate broker ingress missing.' }
$null = Render-Chart ($portal + @('--set','portal.publicURL=https://wrong.example.com')) $false
$null = Render-Chart @('--set','replicaCount=2') $false
Write-Output 'Helm rendering and fail-closed ingress checks passed.'
