$ErrorActionPreference = "Stop"

Write-Host "Verificando entorno..." -ForegroundColor Cyan

python --version
& ".\.venv\Scripts\python.exe" --version

openssl version -a
tshark --version

Write-Host ""
Write-Host "Entorno OK." -ForegroundColor Green
