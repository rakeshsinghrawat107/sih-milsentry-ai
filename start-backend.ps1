# MailSentry AI — National Cyber Defense Server Launcher (PowerShell)
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " 🛡️  MailSentry AI — National Production Cyber Defense Server" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan

$serverDir = Join-Path $PSScriptRoot "server"
Set-Location -Path $serverDir

if (-not (Test-Path "node_modules")) {
    Write-Host "[Setup] Installing server dependencies..." -ForegroundColor Yellow
    & "C:\Program Files\nodejs\npm.cmd" install
}

Write-Host "[Launch] Starting server on http://localhost:3000 ..." -ForegroundColor Cyan
& "C:\Program Files\nodejs\node.exe" server.js
