param(
  [string]$ExamplePath = "cpa/config.example.yaml",
  [string]$OutputPath = "cpa/config.yaml"
)

$content = Get-Content -Raw -LiteralPath $ExamplePath

if (-not $env:CPA_API_KEY) {
  throw "CPA_API_KEY is required"
}

if (-not $env:CPA_MANAGEMENT_SECRET_HASH) {
  throw "CPA_MANAGEMENT_SECRET_HASH is required"
}

$content = $content.Replace("sk-change-me-cpa-api-key", $env:CPA_API_KEY)
$content = $content.Replace("change-me-bcrypt-hash", $env:CPA_MANAGEMENT_SECRET_HASH)
Set-Content -LiteralPath $OutputPath -Value $content -Encoding UTF8NoBOM
Write-Host "Rendered $OutputPath"
