$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    throw "No existe el entorno virtual. Ejecuta primero .\setup_windows.ps1"
}

$py = ".\.venv\Scripts\python.exe"

Write-Host "==== DEMO RUN ====" -ForegroundColor Cyan

& $py .\scripts\gen_certs.py rsa2048 1
& $py .\scripts\gen_certs.py ecdsa_p256 3

& $py .\scripts\bench_verify.py --algs rsa2048,ecdsa_p256 --chains 1,3 --repeats 20 --warmup 3
& $py .\scripts\bench_tls_latency.py --algs rsa2048,ecdsa_p256 --chains 1,3 --repeats 20 --warmup 3
& $py .\scripts\bench_tls_throughput.py --algs rsa2048,ecdsa_p256 --chains 1,3 --duration 5 --concurrency 1,4
& $py .\scripts\analyze_results.py

Write-Host "Demo terminada." -ForegroundColor Green
Write-Host "Revisa artifacts\csv y artifacts\plots"
