import argparse
import csv
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import PKI_ROOT, CSV_ROOT, ensure_dirs, find_free_port, find_openssl, parse_csv_list, wait_for_server

OPENSSL = find_openssl()
HOST = "127.0.0.1"

def start_server(cert_dir: Path, port: int):
    leaf_pem = cert_dir / "leaf.pem"
    leaf_key = cert_dir / "leaf.key"
    inters_pem = cert_dir / "intermediates.pem"

    cmd = [
        OPENSSL, "s_server",
        "-accept", str(port),
        "-tls1_3",
        "-cert", str(leaf_pem),
        "-key", str(leaf_key),
        "-quiet"
    ]
    if inters_pem.exists() and inters_pem.stat().st_size > 0:
        cmd += ["-cert_chain", str(inters_pem)]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for_server(HOST, port)
    return proc

def stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

def make_ctx_verify(root_pem: Path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(root_pem))
    return ctx

def make_ctx_noverify():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def do_one_handshake(ctx, host, port):
    with socket.create_connection((host, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost", do_handshake_on_connect=False) as ssock:
            ssock.do_handshake()

def run_load(ctx, host, port, concurrency, duration_sec):
    stop_at = time.time() + duration_sec
    counter = 0
    lock = threading.Lock()

    def worker():
        nonlocal counter
        local_count = 0
        while time.time() < stop_at:
            try:
                do_one_handshake(ctx, host, port)
                local_count += 1
            except Exception:
                pass
        with lock:
            counter += local_count

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(worker) for _ in range(concurrency)]
        for fut in futures:
            fut.result()

    return counter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--algs", default=None)
    parser.add_argument("--chains", default=None)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--concurrency", default="1,4,8,16,32")
    args = parser.parse_args()

    ensure_dirs()
    allowed_algs = parse_csv_list(args.algs, str)
    allowed_chains = parse_csv_list(args.chains, int)
    concurrencies = parse_csv_list(args.concurrency, int)

    csv_out = CSV_ROOT / "tls_throughput_results.csv"
    rows = []

    for alg_dir in sorted(PKI_ROOT.iterdir()):
        if not alg_dir.is_dir():
            continue
        alg = alg_dir.name
        if allowed_algs and alg not in allowed_algs:
            continue

        for chain_dir in sorted(alg_dir.iterdir()):
            if not chain_dir.is_dir():
                continue
            chain_len = int(chain_dir.name.split("_")[1])
            if allowed_chains and chain_len not in allowed_chains:
                continue

            root_pem = chain_dir / "root.pem"
            port = find_free_port()

            proc = start_server(chain_dir, port)
            try:
                for mode, ctx in [
                    ("tls_noverify", make_ctx_noverify()),
                    ("tls_verify", make_ctx_verify(root_pem)),
                ]:
                    for conc in concurrencies:
                        count = run_load(ctx, HOST, port, conc, args.duration)
                        rows.append({
                            "alg": alg,
                            "chain_len": chain_len,
                            "mode": mode,
                            "concurrency": conc,
                            "duration_sec": args.duration,
                            "completed_handshakes": count,
                            "handshakes_per_sec": count / args.duration
                        })
            finally:
                stop_server(proc)

    with csv_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"OK -> {csv_out}")

if __name__ == "__main__":
    main()
