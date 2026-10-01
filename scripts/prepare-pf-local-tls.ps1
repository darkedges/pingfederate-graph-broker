param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$certsDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) 'certs'
$certificatePath = Join-Path $certsDirectory 'portal.pem'
$privateKeyPath = Join-Path $certsDirectory 'portal-key.pem'
$bundlePath = Join-Path $certsDirectory 'pingfederate-local.p12'
$password = [Environment]::GetEnvironmentVariable('TF_VAR_pf_local_tls_keystore_password')

if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $privateKeyPath -PathType Leaf)) {
    throw 'Generate certs/portal.pem and certs/portal-key.pem with mkcert first.'
}
if ([string]::IsNullOrEmpty($password) -or $password.Length -lt 8) {
    throw 'Set TF_VAR_pf_local_tls_keystore_password to a private password of at least 8 characters.'
}
if ((Test-Path -LiteralPath $bundlePath) -and -not $Force) {
    throw 'certs/pingfederate-local.p12 already exists. Use -Force only when deliberately replacing it.'
}

$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
    $certificatePath, $privateKeyPath
)
try {
    if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
        throw 'The mkcert certificate is not currently valid. Regenerate the pair first.'
    }

    $bundle = $certificate.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,
        $password
    )
    $imported = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $bundle,
        $password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    )
    try {
        if (-not $imported.HasPrivateKey -or $imported.Thumbprint -ne $certificate.Thumbprint) {
            throw 'PKCS#12 verification failed: the bundle does not contain the expected certificate and private key.'
        }
    }
    finally {
        $imported.Dispose()
    }

    [System.IO.File]::WriteAllBytes($bundlePath, $bundle)
    Write-Output 'Created certs/pingfederate-local.p12 from the mkcert certificate and key.'
}
finally {
    $certificate.Dispose()
}
