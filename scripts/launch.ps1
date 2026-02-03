$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

$backendScript = {
  param($backendPath)
  Set-Location $backendPath
  .\.venv\Scripts\python -m app.main --auto-port
}

$job = Start-Job -ScriptBlock $backendScript -ArgumentList $backend
Write-Host "Backend started in job $($job.Id). Use 'Stop-Job $($job.Id); Remove-Job $($job.Id)' to stop." -ForegroundColor Cyan

Set-Location $frontend
.\scripts\dev.ps1
