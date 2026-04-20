import argparse
import csv
import socket
import ssl
import subprocess
import time
from pathlib import Path

from common import PKI_ROOT, CSV_ROOT, ensure_dirs, find_free_port, find_openssl, parse_csv_list, read_chain_bytes, wait_for_server

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

def make_context_verify(root_pem: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(root_pem))
    return ctx

def make_context_noverify() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def measure_handshake_ms(ctx: ssl.SSLContext, host: str, port: int) -> float:
    with socket.create_connection((host, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost", do_handshake_on_connect=False) as ssock:
            t0 = time.perf_counter_ns()
            ssock.do_handshake()
            t1 = time.perf_counter_ns()
            return (t1 - t0) / 1_000_000

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--algs", default=None)
    parser.add_argument("--chains", default=None)
    parser.add_argument("--repeats", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    args = parser.parse_args()

    ensure_dirs()
    allowed_algs = parse_csv_list(args.algs, str)
    allowed_chains = parse_csv_list(args.chains, int)

    csv_out = CSV_ROOT / "tls_latency_results.csv"
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
                ctx_noverify = make_context_noverify()
                ctx_verify = make_context_verify(root_pem)

                for _ in range(args.warmup):
                    measure_handshake_ms(ctx_noverify, HOST, port)

                for rep in range(args.repeats):
                    ms = measure_handshake_ms(ctx_noverify, HOST, port)
                    rows.append({
                        "alg": alg,
                        "chain_len": chain_len,
                        "mode": "tls_noverify",
                        "rep": rep,
                        "latency_ms": ms,
                        "chain_der_total_bytes": read_chain_bytes(chain_dir)
                    })

                for _ in range(args.warmup):
                    measure_handshake_ms(ctx_verify, HOST, port)

                for rep in range(args.repeats):
                    ms = measure_handshake_ms(ctx_verify, HOST, port)
                    rows.append({
                        "alg": alg,
                        "chain_len": chain_len,
                        "mode": "tls_verify",
                        "rep": rep,
                        "latency_ms": ms,
                        "chain_der_total_bytes": read_chain_bytes(chain_dir)
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
