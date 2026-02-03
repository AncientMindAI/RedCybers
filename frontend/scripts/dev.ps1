$portPath = Join-Path $PSScriptRoot "..\..\.netwatch-port"
$env:VITE_API_PORT = "8787"

if (Test-Path $portPath) {
  try {
    $port = (Get-Content -Path $portPath -ErrorAction Stop | Select-Object -First 1).Trim()
    if ($port) { $env:VITE_API_PORT = $port }
  } catch {}
} else {
  $inputPort = Read-Host "Port file missing. Enter backend port (default 8787)"
  if ($inputPort) { $env:VITE_API_PORT = $inputPort }
}

npm run dev
