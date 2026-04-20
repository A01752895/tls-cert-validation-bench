import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs"
ARTIFACTS = ROOT / "artifacts"
PKI_ROOT = ARTIFACTS / "pki"
CSV_ROOT = ARTIFACTS / "csv"
PLOTS_ROOT = ARTIFACTS / "plots"
PCAP_ROOT = ARTIFACTS / "pcaps"

def ensure_dirs():
    for p in [PKI_ROOT, CSV_ROOT, PLOTS_ROOT, PCAP_ROOT]:
        p.mkdir(parents=True, exist_ok=True)

def _first_existing(paths):
    for p in paths:
        if p and Path(p).exists():
            return str(Path(p))
    return None

def find_openssl():
    candidates = [
        os.environ.get("OPENSSL_EXE"),
        shutil.which("openssl"),
        str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "FireDaemon OpenSSL 3" / "bin" / "openssl.exe"),
        str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin" / "openssl.exe"),
    ]
    result = _first_existing(candidates)
    if not result:
        raise FileNotFoundError("No se encontró openssl.exe. Ejecuta setup_windows.ps1 o configura OPENSSL_EXE.")
    return result

def find_tshark():
    candidates = [
        os.environ.get("TSHARK_EXE"),
        shutil.which("tshark"),
        str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe"),
    ]
    result = _first_existing(candidates)
    if not result:
        raise FileNotFoundError("No se encontró tshark.exe. Ejecuta setup_windows.ps1 o configura TSHARK_EXE.")
    return result

def run(cmd, cwd=None, capture=False):
    print(">", " ".join(map(str, cmd)))
    if capture:
        return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    return subprocess.run(cmd, cwd=cwd, check=True)

def find_free_port(host="127.0.0.1", start=44330, end=44600):
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError("No se encontró puerto libre")

def wait_for_server(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Servidor no levantó en {host}:{port}")

def read_chain_bytes(cert_dir: Path) -> int:
    txt = cert_dir / "chain_bytes.txt"
    if not txt.exists():
        return -1
    total = -1
    for line in txt.read_text(encoding="utf-8").splitlines():
        if line.startswith("chain_der_total_bytes="):
            total = int(line.split("=", 1)[1].strip())
    return total

def parse_csv_list(value, cast=str):
    if value is None:
        return None
    return [cast(v.strip()) for v in value.split(",") if v.strip()]
