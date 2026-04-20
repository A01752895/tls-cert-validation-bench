Write-Host "==== TLS Certificate Validation Benchmark: Windows Setup ====" -ForegroundColor Cyan

# 1. Verificar Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python no está instalado o no está en PATH."
    exit 1
}

python --version

# 2. Crear entorno virtual si no existe
if (-not (Test-Path ".venv")) {
    Write-Host "Creando entorno virtual .venv..."
    python -m venv .venv
} else {
    Write-Host "Entorno virtual .venv ya existe."
}

# 3. Activar entorno virtual
Write-Host "Activando entorno virtual..."
& ".\.venv\Scripts\Activate.ps1"

# 4. Actualizar pip
Write-Host "Actualizando pip..."
python -m pip install --upgrade pip

# 5. Instalar dependencias
Write-Host "Instalando dependencias desde requirements.txt..."
pip install -r requirements.txt

# 6. Verificar OpenSSL
Write-Host "Verificando OpenSSL..."
if (Get-Command openssl -ErrorAction SilentlyContinue) {
    openssl version
} else {
    Write-Warning "OpenSSL no está en PATH. Asegúrate de tenerlo instalado."
}

# 7. Verificar TShark
Write-Host "Verificando TShark..."
if (Get-Command tshark -ErrorAction SilentlyContinue) {
    tshark --version
} else {
    Write-Warning "TShark no está en PATH. Instala Wireshark si necesitas capturas."
}

Write-Host ""
Write-Host "==== Setup completado correctamente ====" -ForegroundColor Green
Write-Host "Ahora puedes ejecutar:"
Write-Host "  .\run_demo.ps1"
Write-Host "o"
Write-Host "  .\run_all.ps1"
