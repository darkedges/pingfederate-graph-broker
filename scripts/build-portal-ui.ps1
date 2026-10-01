$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$source = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'web\out'))
$target = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'cmd\portal\ui'))
$expectedTarget = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'cmd\portal\ui'))

if ($target -ne $expectedTarget -or -not $target.StartsWith($repoRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to update a portal UI directory outside this repository.'
}
if (-not (Test-Path -LiteralPath (Join-Path $source 'index.html') -PathType Leaf) -or -not (Test-Path -LiteralPath (Join-Path $source '_next\static') -PathType Container)) {
    throw 'Build the Next.js static export before copying portal assets.'
}

if (Test-Path -LiteralPath $target) {
    $resolvedTarget = (Resolve-Path -LiteralPath $target).Path
    if ($resolvedTarget -ne $expectedTarget) {
        throw 'Refusing to replace an unexpected portal UI directory.'
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $target '_next') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'index.html') -Destination (Join-Path $target 'index.html')
Copy-Item -LiteralPath (Join-Path $source '_next\static') -Destination (Join-Path $target '_next\static') -Recurse
Write-Output 'Copied the generated Next.js portal assets into cmd/portal/ui.'
