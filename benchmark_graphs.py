# benchmark_graphs.py
"""
Automated performance benchmarking:
- Sequential vs Parallel AES-256-GCM encryption
- Classical RSA-3072 vs Hybrid X25519+ML-KEM-768 key setup
Generates CSV + 3 PNG charts.
"""
import os
import sys
import time
import csv
import hashlib

# Ensure multiprocessing works on Windows
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.parallel_engine import (
    fragment_bytes,
    sequential_encrypt_fragments,
    parallel_encrypt_fragments,
)
from core.hybrid_crypto import sender_establish_hybrid_key
from core.kms_vault import generate_receiver_keys


def benchmark_encryption():
    """Benchmark sequential vs parallel AES-256-GCM across payload sizes."""
    sizes_mb = [1, 10, 50, 100]
    aes_key = os.urandom(32)
    file_id = "bench_file"
    results = []

    for sz in sizes_mb:
        print(f"  Benchmarking {sz} MB...")
        data = os.urandom(sz * 1024 * 1024)
        frags = fragment_bytes(data)

        # Sequential
        t0 = time.perf_counter()
        sequential_encrypt_fragments(frags, aes_key, file_id, version=1)
        seq_t = time.perf_counter() - t0

        # Parallel
        t0 = time.perf_counter()
        parallel_encrypt_fragments(frags, aes_key, file_id, version=1)
        par_t = time.perf_counter() - t0

        results.append({
            "size_mb": sz,
            "seq_time_s": round(seq_t, 4),
            "par_time_s": round(par_t, 4),
            "seq_throughput_mbps": round(sz / seq_t, 2) if seq_t > 0 else 0,
            "par_throughput_mbps": round(sz / par_t, 2) if par_t > 0 else 0,
            "speedup": round(seq_t / par_t, 2) if par_t > 0 else 0,
        })
        del data

    return results


def benchmark_key_setup():
    """Benchmark RSA-3072 key gen vs Hybrid X25519+ML-KEM-768 key establishment."""
    iterations = 10
    results = {"rsa_ms": [], "hybrid_ms": []}

    for _ in range(iterations):
        # RSA-3072 keygen
        t0 = time.perf_counter()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        _ = rsa_priv.public_key()
        results["rsa_ms"].append((time.perf_counter() - t0) * 1000)

        # Hybrid X25519 + ML-KEM-768 key establishment
        receiver_email = "bench_receiver@demo.local"
        pub = generate_receiver_keys(receiver_email)
        t0 = time.perf_counter()
        sender_establish_hybrid_key(pub)
        results["hybrid_ms"].append((time.perf_counter() - t0) * 1000)

    return {
        "rsa_avg_ms": round(sum(results["rsa_ms"]) / iterations, 3),
        "hybrid_avg_ms": round(sum(results["hybrid_ms"]) / iterations, 3),
        "rsa_all": results["rsa_ms"],
        "hybrid_all": results["hybrid_ms"],
    }


def save_csv(enc_results, key_results, path="benchmark_results.csv"):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Payload (MB)", "Sequential (s)", "Parallel (s)", "Seq Throughput (MB/s)", "Par Throughput (MB/s)", "Speedup"])
        for r in enc_results:
            w.writerow([r["size_mb"], r["seq_time_s"], r["par_time_s"], r["seq_throughput_mbps"], r["par_throughput_mbps"], r["speedup"]])
        w.writerow([])
        w.writerow(["Key Setup", "RSA-3072 Avg (ms)", "Hybrid X25519+ML-KEM-768 Avg (ms)"])
        w.writerow(["", key_results["rsa_avg_ms"], key_results["hybrid_avg_ms"]])
    print(f"  Saved: {path}")


def print_table(enc_results, key_results):
    print("\n### Encryption Time Comparison\n")
    print("| Payload | Sequential (s) | Parallel (s) | Seq MB/s | Par MB/s | Speedup |")
    print("|---------|---------------|-------------|---------|---------|---------|")
    for r in enc_results:
        print(f"| {r['size_mb']} MB | {r['seq_time_s']} | {r['par_time_s']} | {r['seq_throughput_mbps']} | {r['par_throughput_mbps']} | {r['speedup']}x |")
    print(f"\n### Key Setup Latency\n")
    print(f"| Method | Avg Latency (ms) |")
    print(f"|--------|-----------------|")
    print(f"| RSA-3072 | {key_results['rsa_avg_ms']} |")
    print(f"| Hybrid X25519+ML-KEM-768 | {key_results['hybrid_avg_ms']} |")


def generate_charts(enc_results, key_results):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sizes = [r["size_mb"] for r in enc_results]
    seq_t = [r["seq_time_s"] for r in enc_results]
    par_t = [r["par_time_s"] for r in enc_results]
    seq_tp = [r["seq_throughput_mbps"] for r in enc_results]
    par_tp = [r["par_throughput_mbps"] for r in enc_results]

    # Chart style
    plt.rcParams.update({
        "figure.facecolor": "#0b0e17",
        "axes.facecolor": "#121829",
        "axes.edgecolor": "#1e2a45",
        "text.color": "#e2e8f0",
        "axes.labelcolor": "#e2e8f0",
        "xtick.color": "#94a3b8",
        "ytick.color": "#94a3b8",
        "grid.color": "#1e2a45",
        "font.family": "sans-serif",
    })

    # 1. Encryption Time Comparison
    fig, ax = plt.subplots(figsize=(8, 5))
    x = range(len(sizes))
    w = 0.35
    ax.bar([i - w/2 for i in x], seq_t, w, label="Sequential AES-256-GCM", color="#ef4444")
    ax.bar([i + w/2 for i in x], par_t, w, label="Parallel AES-256-GCM", color="#3b82f6")
    ax.set_xlabel("Payload Size (MB)")
    ax.set_ylabel("Encryption Time (seconds)")
    ax.set_title("Sequential vs Parallel AES-256-GCM Encryption Time", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{s} MB" for s in sizes])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig("encryption_time_comparison.png", dpi=200)
    plt.close()
    print("  Saved: encryption_time_comparison.png")

    # 2. Throughput
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(sizes, seq_tp, "o-", label="Sequential", color="#ef4444", linewidth=2, markersize=8)
    ax.plot(sizes, par_tp, "s-", label="Parallel", color="#3b82f6", linewidth=2, markersize=8)
    ax.set_xlabel("Payload Size (MB)")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Encryption Throughput: Sequential vs Parallel", fontweight="bold")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig("throughput_mbps.png", dpi=200)
    plt.close()
    print("  Saved: throughput_mbps.png")

    # 3. Key Setup Latency
    fig, ax = plt.subplots(figsize=(6, 5))
    methods = ["RSA-3072", "Hybrid\nX25519+ML-KEM-768"]
    avgs = [key_results["rsa_avg_ms"], key_results["hybrid_avg_ms"]]
    colors = ["#ef4444", "#22c55e"]
    bars = ax.bar(methods, avgs, color=colors, width=0.5)
    for bar, val in zip(bars, avgs):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, f"{val:.1f} ms",
                ha="center", va="bottom", fontweight="bold", fontsize=10, color="#e2e8f0")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Key Establishment Latency Comparison", fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig("key_setup_latency.png", dpi=200)
    plt.close()
    print("  Saved: key_setup_latency.png")


if __name__ == "__main__":
    print("=" * 60)
    print("HECC Phase 2 — Performance Benchmark Suite")
    print("=" * 60)

    print("\n[1/3] Benchmarking AES-256-GCM Encryption (1, 10, 50, 100 MB)...")
    enc_results = benchmark_encryption()

    print("\n[2/3] Benchmarking Key Setup (RSA-3072 vs Hybrid)...")
    key_results = benchmark_key_setup()

    print("\n[3/3] Generating Charts & CSV...")
    save_csv(enc_results, key_results)
    generate_charts(enc_results, key_results)

    print_table(enc_results, key_results)
    print("\n✓ Benchmark complete.")
