param([ValidateSet('Plan','Apply','Configure')][string]$Mode = 'Plan', [switch]$EnableDevelopmentInspection)
$ErrorActionPreference = 'Stop'
$repoPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $repoPath

# Use apply_patch for updates, keeping generated credentials out of tool output.
function Set-LocalEnv([hashtable]$Updates) {
    $envPath = Join-Path $repoPath '.env'
    $oldText = [IO.File]::ReadAllText($envPath).Replace("`r`n", "`n").TrimEnd("`n")
    $newText = $oldText
    foreach ($name in $Updates.Keys) {
        $line = $name + '=' + $Updates[$name]
        if ($newText -match ('(?m)^' + [regex]::Escape($name) + '=')) {
            $replacement = [Text.RegularExpressions.MatchEvaluator]({ param($m) $line }.GetNewClosure())
            $newText = [regex]::Replace($newText, '(?m)^' + [regex]::Escape($name) + '=.*$', $replacement)
        } else { $newText += "`n" + $line }
    }
    if ($newText -eq $oldText) { return }
    $patch = "*** Begin Patch`n*** Update File: .env`n@@`n" + (($oldText.Split("`n") | ForEach-Object { '-' + $_ }) -join "`n") + "`n" + (($newText.Split("`n") | ForEach-Object { '+' + $_ }) -join "`n") + "`n*** End Patch"
    # Invoke the native runner directly: cmd.exe batch argument expansion can
    # corrupt multiline patches or dotenv values containing shell metacharacters.
    $shim = (Get-Command apply_patch -ErrorAction Stop).Source
    $shimText = [IO.File]::ReadAllText($shim)
    if ($shimText -notmatch '"([^"]+codex.exe)"') { throw 'Unsupported apply_patch shim' }
    $runner = [IO.Path]::GetFullPath($matches[1].Replace('%~dp0', ([IO.Path]::GetDirectoryName($shim) + '\')))
    $patchResult = & $runner --codex-run-as-apply-patch $patch 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Unable to update local environment using apply_patch' }
}
function Read-LocalEnv {
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $repoPath '.env'))) {
        if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $values[$matches[1]] = $matches[2].Trim('"') }
    }
    return $values
}
$settings = Read-LocalEnv
if ($Mode -ne 'Configure') {
    # Prefer freshly supplied local settings over credentials inherited when
    # the desktop app started. Never echo credentials or upstream bodies.
    foreach ($name in @('PINGFEDERATE_PROVIDER_USERNAME','PINGFEDERATE_PROVIDER_PASSWORD')) {
        if ($settings[$name]) { [Environment]::SetEnvironmentVariable($name, $settings[$name], 'Process') }
    }
    foreach ($tenant in @('4161be3f-bf2b-41d4-a02b-e6f82b529d53')) {
        $loginCheck = & az account get-access-token --tenant $tenant --resource-type ms-graph -o json 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Azure login requires refresh for tenant $tenant; Terraform was not invoked." }
        $loginCheck = $null
    }
    $pfUser = [Environment]::GetEnvironmentVariable('PINGFEDERATE_PROVIDER_USERNAME')
    $pfPassword = [Environment]::GetEnvironmentVariable('PINGFEDERATE_PROVIDER_PASSWORD')
    if (-not $pfUser -or -not $pfPassword) { throw 'Local PF admin credentials are missing.' }
    $basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pfUser + ':' + $pfPassword))
    $preflight = Invoke-WebRequest -Uri 'https://localhost:9999/pf-admin-api/v1/version' -Headers @{Authorization='Basic '+$basic; 'X-XSRF-Header'='PingFederate'} -SkipHttpErrorCheck
    if ($preflight.StatusCode -ne 200) {
        throw "Local PF credential preflight failed (HTTP $($preflight.StatusCode)); stopping after one request. Terraform was not invoked."
    }
    $preflight = $null; $basic = $null; $pfPassword = $null
}
$generated = @{}
foreach ($name in @('INBOUND_PF_CLIENT_SECRET','INBOUND_FIRST_PF_CLIENT_SECRET','INBOUND_WORKLOAD_SECRET')) {
    if (-not $settings[$name]) { $generated[$name] = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) }
}
if ($generated.Count) { Set-LocalEnv $generated; $settings = Read-LocalEnv }
$env:TF_VAR_inbound_pf_client_secret = $settings.INBOUND_PF_CLIENT_SECRET
$env:TF_VAR_inbound_first_pf_client_secret = $settings.INBOUND_FIRST_PF_CLIENT_SECRET
# Preserve the imported TLS key password; do not rotate a live certificate.
$stateRaw = & terraform -chdir=terraform show -json
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect Terraform state' }
$state = $stateRaw | ConvertFrom-Json
$ssl = $state.values.root_module.resources | Where-Object address -eq 'pingfederate_keypairs_ssl_server_key.local_mkcert[0]'
if ($ssl.values.password) { $env:TF_VAR_pf_local_tls_keystore_password = $ssl.values.password }
$env:PINGFEDERATE_PROVIDER_INSECURE_TRUST_ALL_TLS = 'false'

if ($Mode -eq 'Plan') {
    # Intentionally scoped commissioning plan: do not refresh or change the
    # existing tenant's Entra applications as part of an inbound-only rollout.
    $targets = @(
        'azuread_application_registration.inbound_exchange',
        'azuread_service_principal.inbound_exchange',
        'azuread_application_api_access.inbound_exchange',
        'azuread_application_redirect_uris.inbound_exchange',
        'azuread_application_password.inbound_exchange',
        'pingfederate_idp_token_processor.inbound_microsoft',
        'pingfederate_idp_token_processor.inbound_portal_actor',
        'pingfederate_oauth_token_exchange_processor_policy.inbound_entra',
        'pingfederate_oauth_client.inbound_exchange',
        'pingfederate_oauth_access_token_manager.inbound_exchange',
        'pingfederate_oauth_access_token_mapping.inbound_exchange',
        'pingfederate_oauth_token_exchange_processor_policy.inbound_first',
        'pingfederate_oauth_client.inbound_first',
        'pingfederate_oauth_access_token_manager.inbound_first',
        'pingfederate_oauth_access_token_mapping.inbound_first'
        'pingfederate_keypairs_signing_key.inbound_jwt'
        'pingfederate_oauth_access_token_manager.inbound_jwt'
        'pingfederate_oauth_access_token_mapping.inbound_jwt'
        'pingfederate_openid_connect_policy.inbound_jwt'
        'pingfederate_virtual_host_names.public_issuer'
        'pingfederate_oauth_issuer.inbound'
    ) | ForEach-Object { '-target=' + $_ }
    & terraform '-chdir=terraform' plan '-input=false' -no-color '-out=entra-first-local.tfplan' @targets
    if ($LASTEXITCODE -ne 0) { throw 'Terraform plan failed; no apply performed' }
} elseif ($Mode -eq 'Apply') {
    & terraform -chdir=terraform apply -input=false -no-color entra-first-local.tfplan
    if ($LASTEXITCODE -ne 0) { throw 'Terraform apply failed; runtime flags unchanged' }
} else {
    if ($EnableDevelopmentInspection) {
        $client = $state.values.root_module.resources | Where-Object address -eq 'pingfederate_oauth_client.inbound_first[0]'
        $policy = $state.values.root_module.resources | Where-Object address -eq 'pingfederate_openid_connect_policy.inbound_jwt[0]'
        if ($client.values.default_access_token_manager_ref.id -ne 'brokerEntraJWT' -or -not $policy.values.return_id_token_on_token_exchange_grant) {
            throw 'Provision and activate the dedicated JWT/OIDC policy before enabling development inspection.'
        }
    }
    $outputsRaw = & terraform -chdir=terraform output -json
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Terraform outputs' }
    $outputs = $outputsRaw | ConvertFrom-Json
    if (-not $outputs.inbound_entra_client_id.value -or -not $outputs.inbound_entra_client_secret.value) { throw 'Inbound app outputs missing' }
    Set-LocalEnv @{
        INBOUND_FIRST_ENABLED='true'; PORTAL_INBOUND_FIRST_ENABLED='true'
        INBOUND_DEV_TOKEN_INSPECTION=$EnableDevelopmentInspection.IsPresent.ToString().ToLowerInvariant()
        PORTAL_DEV_TOKEN_INSPECTION=$EnableDevelopmentInspection.IsPresent.ToString().ToLowerInvariant()
        INBOUND_FIRST_PF_ISSUER='https://ping.entraid.darkedges.com'
        INBOUND_FIRST_PF_TOKEN_URL='https://ping.entraid.darkedges.com/as/token.oauth2'
        INBOUND_ENABLED='false'; PORTAL_INBOUND_ENABLED='false'
        INBOUND_ENTRA_TENANT_ID='4161be3f-bf2b-41d4-a02b-e6f82b529d53'
        PORTAL_INBOUND_TENANT_ID='4161be3f-bf2b-41d4-a02b-e6f82b529d53'
        INBOUND_ENTRA_CLIENT_ID=$outputs.inbound_entra_client_id.value
        PORTAL_INBOUND_CLIENT_ID=$outputs.inbound_entra_client_id.value
        INBOUND_ENTRA_CLIENT_SECRET=$outputs.inbound_entra_client_secret.value
        INBOUND_REDIRECT_URI='https://portal.entraid.darkedges.com/auth/entra/callback'
        INBOUND_PF_CLIENT_ID='directory-entra-exchange'; INBOUND_FIRST_PF_CLIENT_ID='directory-entra-first'
        INBOUND_PF_SUBJECT='nirving@ping.darkedges.com'; PORTAL_INBOUND_SUBJECT='nirving@ping.darkedges.com'
        INBOUND_ENTRA_OBJECT_ID='4576e3b2-c5dc-4f1c-af69-1c5042eb538d'
    }
    Write-Output 'Local inbound runtime settings configured; credentials were not printed.'
}
