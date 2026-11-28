[CmdletBinding()]
param(
    [string]$OutputDirectory = "bin"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$frontendDirectory = Join-Path $repositoryRoot "internal/web/frontend"
$outputPath = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputDirectory))
}

foreach ($tool in @("go", "pnpm")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' was not found in PATH."
    }
}

Push-Location $frontendDirectory
try {
    & pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw "pnpm install failed with exit code $LASTEXITCODE" }

    & pnpm build
    if ($LASTEXITCODE -ne 0) { throw "pnpm build failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

New-Item -ItemType Directory -Force $outputPath | Out-Null

$previousCgo = $env:CGO_ENABLED
$previousGoos = $env:GOOS
$previousGoarch = $env:GOARCH

try {
    $env:CGO_ENABLED = "0"
    $env:GOARCH = "amd64"

    Push-Location $repositoryRoot
    try {
        $env:GOOS = "windows"
        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-proxy-windows-amd64.exe") ./cmd/audit-proxy
        if ($LASTEXITCODE -ne 0) { throw "Windows build failed with exit code $LASTEXITCODE" }

        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-import-windows-amd64.exe") ./cmd/audit-import
        if ($LASTEXITCODE -ne 0) { throw "Windows importer build failed" }

        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-archive-windows-amd64.exe") ./cmd/audit-archive
        if ($LASTEXITCODE -ne 0) { throw "Windows archive reader build failed" }

        $env:GOOS = "linux"
        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-proxy-linux-amd64") ./cmd/audit-proxy
        if ($LASTEXITCODE -ne 0) { throw "Linux build failed with exit code $LASTEXITCODE" }
        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-import-linux-amd64") ./cmd/audit-import
        if ($LASTEXITCODE -ne 0) { throw "Linux importer build failed" }
        & go build -trimpath -ldflags "-s -w" -o (Join-Path $outputPath "audit-archive-linux-amd64") ./cmd/audit-archive
        if ($LASTEXITCODE -ne 0) { throw "Linux archive reader build failed" }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -eq $previousCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $previousCgo }
    if ($null -eq $previousGoos) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $previousGoos }
    if ($null -eq $previousGoarch) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $previousGoarch }
}

# Agent access Skill packages: cross-compiles llmaudit for every platform and
# writes the archives and manifest.json to agent-packages next to the server
# binaries, where audit-proxy looks for them. Runs with the host GOOS/GOARCH
# restored above, because go run executes the packer on this machine.
$agentPackages = Join-Path $outputPath "agent-packages"
Push-Location $repositoryRoot
try {
    & go run ./internal/agentdist/cmd/agentpack -skill skill/llmapi-audit -out $agentPackages
    if ($LASTEXITCODE -ne 0) { throw "Agent package build failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

Write-Host "Built:"
Write-Host "  $(Join-Path $outputPath 'audit-proxy-windows-amd64.exe')"
Write-Host "  $(Join-Path $outputPath 'audit-proxy-linux-amd64')"

Write-Host "  $(Join-Path $outputPath 'audit-import-windows-amd64.exe')"
Write-Host "  $(Join-Path $outputPath 'audit-import-linux-amd64')"
Write-Host "  $(Join-Path $outputPath 'audit-archive-windows-amd64.exe')"
Write-Host "  $(Join-Path $outputPath 'audit-archive-linux-amd64')"
Write-Host "  $agentPackages"
