import subprocess
from common import ensure_dirs

ALGS = ["rsa2048", "rsa3072", "ecdsa_p256", "ecdsa_p384"]
CHAINS = [1, 2, 3, 4, 5]

def main():
    ensure_dirs()
    for alg in ALGS:
        for chain_len in CHAINS:
            subprocess.run(["python", "scripts\\gen_certs.py", alg, str(chain_len)], check=True)
    print("Matriz completa generada.")

if __name__ == "__main__":
    main()
