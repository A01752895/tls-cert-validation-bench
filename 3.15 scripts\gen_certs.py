import argparse
from pathlib import Path
from common import ROOT, CONFIGS, PKI_ROOT, ensure_dirs, find_openssl, run

OPENSSL = find_openssl()

def gen_key(alg: str, out: Path):
    if alg == "rsa2048":
        run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(out)])
    elif alg == "rsa3072":
        run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(out)])
    elif alg == "ecdsa_p256":
        run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(out)])
    elif alg == "ecdsa_p384":
        run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", str(out)])
    else:
        raise ValueError(f"Algoritmo no soportado: {alg}")

def sign_cert(csr: Path, issuer_cert: Path, issuer_key: Path, out_cert: Path,
              extfile: Path, extsection: str, serial: int):
    run([
        OPENSSL, "x509", "-req",
        "-in", str(csr),
        "-CA", str(issuer_cert),
        "-CAkey", str(issuer_key),
        "-out", str(out_cert),
        "-days", "3650",
        "-sha256",
        "-set_serial", str(serial),
        "-extfile", str(extfile),
        "-extensions", extsection
    ])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("alg", choices=["rsa2048", "rsa3072", "ecdsa_p256", "ecdsa_p384"])
    parser.add_argument("chain_len", type=int)
    args = parser.parse_args()

    ensure_dirs()
    alg = args.alg
    chain_len = args.chain_len

    base_dir = PKI_ROOT / alg / f"chain_{chain_len}"
    base_dir.mkdir(parents=True, exist_ok=True)

    root_key = base_dir / "root.key"
    root_csr = base_dir / "root.csr"
    root_pem = base_dir / "root.pem"

    gen_key(alg, root_key)
    run([OPENSSL, "req", "-new", "-key", str(root_key), "-subj", f"/CN=Root CA {alg}", "-out", str(root_csr)])
    run([
        OPENSSL, "x509", "-req",
        "-in", str(root_csr),
        "-signkey", str(root_key),
        "-out", str(root_pem),
        "-days", "3650",
        "-sha256",
        "-set_serial", "1",
        "-extfile", str(CONFIGS / "ext_root.cnf"),
        "-extensions", "v3_ca"
    ])

    num_intermediates = chain_len - 1
    prev_cert = root_pem
    prev_key = root_key
    intermediates = []

    for i in range(1, num_intermediates + 1):
        ikey = base_dir / f"intermediate_{i}.key"
        icsr = base_dir / f"intermediate_{i}.csr"
        ipem = base_dir / f"intermediate_{i}.pem"

        gen_key(alg, ikey)
        run([OPENSSL, "req", "-new", "-key", str(ikey), "-subj", f"/CN=Intermediate {i} {alg}", "-out", str(icsr)])
        sign_cert(icsr, prev_cert, prev_key, ipem, CONFIGS / "ext_intermediate.cnf", "v3_intermediate_ca", serial=1000 + i)
        intermediates.append(ipem)
        prev_cert = ipem
        prev_key = ikey

    leaf_key = base_dir / "leaf.key"
    leaf_csr = base_dir / "leaf.csr"
    leaf_pem = base_dir / "leaf.pem"

    gen_key(alg, leaf_key)
    run([OPENSSL, "req", "-new", "-key", str(leaf_key), "-subj", f"/CN=localhost {alg}", "-out", str(leaf_csr)])
    sign_cert(leaf_csr, prev_cert, prev_key, leaf_pem, CONFIGS / "ext_leaf.cnf", "v3_leaf", serial=2000)

    intermediates_pem = base_dir / "intermediates.pem"
    intermediates_pem.write_text("", encoding="utf-8")
    for pem in reversed(intermediates):
        with intermediates_pem.open("ab") as f_out:
            f_out.write(pem.read_bytes())

    fullchain_pem = base_dir / "fullchain.pem"
    with fullchain_pem.open("wb") as f_out:
        f_out.write(leaf_pem.read_bytes())
        if intermediates_pem.exists():
            f_out.write(intermediates_pem.read_bytes())

    total_bytes = 0
    lines = []

    leaf_der = base_dir / "leaf.der"
    run([OPENSSL, "x509", "-in", str(leaf_pem), "-outform", "DER", "-out", str(leaf_der)])
    leaf_bytes = leaf_der.stat().st_size
    total_bytes += leaf_bytes
    lines.append(f"leaf_der_bytes={leaf_bytes}")

    for i in range(1, num_intermediates + 1):
        ipem = base_dir / f"intermediate_{i}.pem"
        ider = base_dir / f"intermediate_{i}.der"
        run([OPENSSL, "x509", "-in", str(ipem), "-outform", "DER", "-out", str(ider)])
        b = ider.stat().st_size
        total_bytes += b
        lines.append(f"intermediate_{i}_der_bytes={b}")

    lines.append(f"chain_der_total_bytes={total_bytes}")
    (base_dir / "chain_bytes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"OK -> {base_dir}")

if __name__ == "__main__":
    main()
