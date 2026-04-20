import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from common import CSV_ROOT, PLOTS_ROOT, ensure_dirs

def main():
    ensure_dirs()
    verify_csv = CSV_ROOT / "verify_results.csv"
    lat_csv = CSV_ROOT / "tls_latency_results.csv"
    thr_csv = CSV_ROOT / "tls_throughput_results.csv"

    dfv = pd.read_csv(verify_csv)
    summary_v = (
        dfv.groupby(["alg", "chain_len"])["latency_ms"]
           .agg(["median", "mean", "std"])
           .reset_index()
    )

    plt.figure(figsize=(10, 6))
    for alg, sub in summary_v.groupby("alg"):
        plt.plot(sub["chain_len"], sub["median"], marker="o", label=alg)
    plt.title("Validación pura X.509 (mediana)")
    plt.xlabel("Longitud de cadena enviada por el servidor")
    plt.ylabel("Latencia (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS_ROOT / "verify_pure_median.png")
    plt.close()

    dft = pd.read_csv(lat_csv)
    summary_t = (
        dft.groupby(["alg", "chain_len", "mode"])["latency_ms"]
           .agg(["median", "mean", "std"])
           .reset_index()
    )

    for mode in ["tls_noverify", "tls_verify"]:
        plt.figure(figsize=(10, 6))
        tmp = summary_t[summary_t["mode"] == mode]
        for alg, sub in tmp.groupby("alg"):
            plt.plot(sub["chain_len"], sub["median"], marker="o", label=alg)
        plt.title(f"Handshake TLS 1.3 ({mode}) - mediana")
        plt.xlabel("Longitud de cadena enviada por el servidor")
        plt.ylabel("Latencia de handshake (ms)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(PLOTS_ROOT / f"{mode}_median.png")
        plt.close()

    pivot = (
        summary_t.pivot_table(
            index=["alg", "chain_len"],
            columns="mode",
            values="median"
        )
        .reset_index()
    )

    pivot["delta_verify_ms"] = pivot["tls_verify"] - pivot["tls_noverify"]

    plt.figure(figsize=(10, 6))
    for alg, sub in pivot.groupby("alg"):
        plt.plot(sub["chain_len"], sub["delta_verify_ms"], marker="o", label=alg)
    plt.title("Costo adicional estimado de validación dentro del handshake")
    plt.xlabel("Longitud de cadena enviada por el servidor")
    plt.ylabel("Delta mediano (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS_ROOT / "tls_verify_delta_median.png")
    plt.close()

    dftp = pd.read_csv(thr_csv)
    for mode in ["tls_noverify", "tls_verify"]:
        for alg, sub_alg in dftp[dftp["mode"] == mode].groupby("alg"):
            plt.figure(figsize=(10, 6))
            for chain_len, sub in sub_alg.groupby("chain_len"):
                plt.plot(sub["concurrency"], sub["handshakes_per_sec"], marker="o", label=f"chain={chain_len}")
            plt.title(f"Throughput {alg} ({mode})")
            plt.xlabel("Concurrencia")
            plt.ylabel("Handshakes/seg")
            plt.legend()
            plt.tight_layout()
            plt.savefig(PLOTS_ROOT / f"throughput_{alg}_{mode}.png")
            plt.close()

    bytes_df = (
        dft[["alg", "chain_len", "chain_der_total_bytes"]]
        .drop_duplicates()
        .sort_values(["alg", "chain_len"])
    )

    plt.figure(figsize=(10, 6))
    for alg, sub in bytes_df.groupby("alg"):
        plt.plot(sub["chain_len"], sub["chain_der_total_bytes"], marker="o", label=alg)
    plt.title("Tamaño total DER de la cadena enviada")
    plt.xlabel("Longitud de cadena enviada por el servidor")
    plt.ylabel("Bytes DER")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS_ROOT / "chain_der_total_bytes.png")
    plt.close()

    print(f"Gráficas guardadas en: {PLOTS_ROOT}")

if __name__ == "__main__":
    main()
