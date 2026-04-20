import argparse
import csv
import subprocess
import time
from pathlib import Path

from common import PKI_ROOT, CSV_ROOT, ensure_dirs, find_openssl, parse_csv_list, read_chain_bytes

OPENSSL = find_openssl()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--algs", default=None, help="Lista separada por comas, e.g. rsa2048,ecdsa_p256")
    parser.add_argument("--chains", default=None, help="Lista separada por comas, e.g. 1,3,5")
    parser.add_argument("--repeats", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=5)
    args = parser.parse_args()

    ensure_dirs()
    repeats = args.repeats
    warmup = args.warmup

    allowed_algs = parse_csv_list(args.algs, str)
    allowed_chains = parse_csv_list(args.chains, int)

    csv_out = CSV_ROOT / "verify_results.csv"
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
            leaf_pem = chain_dir / "leaf.pem"
            inters_pem = chain_dir / "intermediates.pem"

            cmd = [OPENSSL, "verify", "-CAfile", str(root_pem)]
            if inters_pem.exists() and inters_pem.stat().st_size > 0:
                cmd += ["-untrusted", str(inters_pem)]
            cmd += [str(leaf_pem)]

            for _ in range(warmup):
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode != 0:
                    raise RuntimeError(f"Fallo verify en warmup: {alg} chain={chain_len}\n{r.stderr}\n{r.stdout}")

            for rep in range(repeats):
                t0 = time.perf_counter_ns()
                r = subprocess.run(cmd, capture_output=True, text=True)
                t1 = time.perf_counter_ns()

                if r.returncode != 0:
                    raise RuntimeError(f"Fallo verify: {alg} chain={chain_len}\n{r.stderr}\n{r.stdout}")

                rows.append({
                    "alg": alg,
                    "chain_len": chain_len,
                    "mode": "verify_pure",
                    "rep": rep,
                    "latency_ms": (t1 - t0) / 1_000_000,
                    "chain_der_total_bytes": read_chain_bytes(chain_dir)
                })

    with csv_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"OK -> {csv_out}")

if __name__ == "__main__":
    main()
