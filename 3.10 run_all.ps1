$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    throw "No existe el entorno virtual. Ejecuta primero .\setup_windows.ps1"
}

$py = ".\.venv\Scripts\python.exe"

Write-Host "==== FULL RUN ====" -ForegroundColor Cyan
Write-Host "Esto puede tardar varios minutos." -ForegroundColor Yellow

& $py .\scripts\gen_matrix.py
& $py .\scripts\bench_verify.py
& $py .\scripts\bench_tls_latency.py
& $py .\scripts\bench_tls_throughput.py
& $py .\scripts\analyze_results.py

Write-Host "Benchmark completo terminado." -ForegroundColor Green
Write-Host "CSV:   artifacts\csv"
Write-Host "Plots: artifacts\plots"
