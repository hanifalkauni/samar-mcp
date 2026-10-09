# build-release.ps1 — build rilis multi-platform Samar.
# Pemakaian: pwsh scripts/build-release.ps1
# Output di dist/ : samar-<os>-<arch>[.exe] + SHA256SUMS.txt

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$version = (Select-String -Path "cmd\samar\main.go" -Pattern 'const version = "([^"]+)"').Matches[0].Groups[1].Value
Write-Host "Building Samar $version"

$dist = "dist"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Force $dist | Out-Null

# Jalankan test & vet sebagai gate rilis.
Write-Host "== vet =="; go vet ./...
Write-Host "== test =="; go test ./...

# Gate canary: build binary native, jalankan harness, batalkan rilis bila bocor.
Write-Host "== canary harness =="
$nativeExt = ""; if ($IsWindows -or $env:OS -eq "Windows_NT") { $nativeExt = ".exe" }
$nativeBin = Join-Path "bin" ("samar" + $nativeExt)
New-Item -ItemType Directory -Force "bin" | Out-Null
$env:CGO_ENABLED = "0"
go build -o $nativeBin ./cmd/samar
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
go run ./test/canary
if ($LASTEXITCODE -ne 0) {
  Write-Error "canary harness GAGAL (ada kebocoran tak terduga) - rilis dibatalkan."
  exit 1
}

$targets = @(
  @{os="linux";   arch="amd64"; ext=""},
  @{os="linux";   arch="arm64"; ext=""},
  @{os="darwin";  arch="amd64"; ext=""},
  @{os="darwin";  arch="arm64"; ext=""},
  @{os="windows"; arch="amd64"; ext=".exe"}
)

foreach ($t in $targets) {
  $out = Join-Path $dist ("samar-{0}-{1}{2}" -f $t.os, $t.arch, $t.ext)
  Write-Host ("building {0}/{1} -> {2}" -f $t.os, $t.arch, $out)
  $env:GOOS = $t.os; $env:GOARCH = $t.arch; $env:CGO_ENABLED = "0"
  go build -trimpath -ldflags "-s -w" -o $out ./cmd/samar
}
Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

# Checksums.
$lines = @()
foreach ($f in (Get-ChildItem $dist -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' })) {
  $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
  $lines += ("{0}  {1}" -f $h, $f.Name)
}
$sums = Join-Path (Resolve-Path $dist) "SHA256SUMS.txt"
[System.IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"))

Write-Host "`nRilis siap di $dist/:"
Get-ChildItem $dist | Select-Object Name, Length
