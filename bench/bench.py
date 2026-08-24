"""Benchmark the CryptoLayer send/receive transform pipeline.

Measures every stage that touches a message on its way out and back in,
excluding threading/polling overhead, so the pure CPU cost is visible.

Run: python3 bench/bench.py
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import brotli
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from levels.packet import ApplicationPacket, DataTypes, PackTypes, TextMessagePacket, TransportPacket
from wordcoder import WordCoder

# 256 distinct <=10-char words, same shape as the real dictionary repo.
SYLL_A = ["ba", "ve", "gi", "do", "zhu", "ki", "la", "mo", "ne", "pu", "ra", "so", "tu", "fi", "ha", "che"]
SYLL_B = ["lom", "ves", "gor", "dym", "zhar", "kit", "lug", "mox", "nos", "puh", "rov", "sud", "tir", "fon", "hor", "chan"]
WORDCODER_DICT = {
    f"{a * 16 + b:02x}": SYLL_A[a] + SYLL_B[b]
    for a in range(16)
    for b in range(16)
}

PAYLOADS = {
    "short (32B)": b"x" * 32,
    "chat (256B)": ("Wake me up when september ends. " * 8).encode(),
    "long (4KB)": (os.urandom(16).hex() * 256).encode()[:4096],
}


def timeit(fn, *, min_rounds=50, min_seconds=0.25):
    """Return (median_seconds, rounds). Warms up, then loops until stable."""
    for _ in range(3):
        fn()
    samples = []
    deadline = time.perf_counter() + min_seconds
    while len(samples) < min_rounds or time.perf_counter() < deadline:
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples), len(samples)


def fmt(seconds):
    if seconds >= 1:
        return f"{seconds:8.3f} s "
    if seconds >= 1e-3:
        return f"{seconds * 1e3:8.3f} ms"
    return f"{seconds * 1e6:8.3f} us"


def main():
    wc = WordCoder(WORDCODER_DICT)
    aes_key = os.urandom(32)
    aesgcm = AESGCM(aes_key)
    sign_key = ec.generate_private_key(ec.SECP256R1())
    verify_key = sign_key.public_key()
    chunk_size = config.CHUNK_SIZE

    print(f"CHUNK_SIZE={chunk_size}  COMPRESS_QUALITY={config.COMPRESS_QUALITY}")

    for name, raw in PAYLOADS.items():
        # --- stage inputs, mirroring the real pipeline ---
        app_bytes = ApplicationPacket(
            PackTypes.COMMUNIC.value,
            DataTypes.TEXT.value,
            TextMessagePacket(int(time.time()), raw).to_bytes(),
        ).to_bytes()

        compressed = brotli.compress(app_bytes, quality=config.COMPRESS_QUALITY)
        nonce = os.urandom(12)
        encrypted = nonce + aesgcm.encrypt(nonce, compressed, associated_data=None)
        chunks = [encrypted[i:i + chunk_size] for i in range(0, len(encrypted), chunk_size)]
        n_chunks = len(chunks)
        transport_packets = [
            TransportPacket(0x0, 0, n_chunks, i, int(time.time()), c).to_bytes()
            for i, c in enumerate(chunks)
        ]
        signature = sign_key.sign(transport_packets[0], ec.ECDSA(hashes.SHA256()))
        signed = len(signature).to_bytes(1, "big") + signature + transport_packets[0]
        wire = " ".join(wc.encode(signed))

        print(f"\n=== {name} ===")
        print(f"  app packet {len(app_bytes)}B -> brotli {len(compressed)}B "
              f"-> +aesgcm {len(encrypted)}B -> {n_chunks} chunk(s) "
              f"-> wire {len(wire)} chars ({len(wire) / len(raw):.1f}x expansion)")

        stages = [
            # (label, callable, how many times it runs per message)
            ("brotli.compress", lambda: brotli.compress(app_bytes, quality=config.COMPRESS_QUALITY), 1),
            ("brotli.decompress", lambda: brotli.decompress(compressed), 1),
            ("aesgcm.encrypt", lambda: aesgcm.encrypt(nonce, compressed, associated_data=None), 1),
            ("aesgcm.decrypt", lambda: aesgcm.decrypt(nonce, encrypted[12:], associated_data=None), 1),
            ("ecdsa.sign", lambda: sign_key.sign(transport_packets[0], ec.ECDSA(hashes.SHA256())), n_chunks),
            ("ecdsa.verify", lambda: verify_key.verify(signature, transport_packets[0], ec.ECDSA(hashes.SHA256())), n_chunks),
            ("wordcoder.encode", lambda: " ".join(wc.encode(signed)), n_chunks),
            ("wordcoder.decode", lambda: wc.decode(wire.split(" ")), n_chunks),
        ]

        total_send = 0.0
        total_recv = 0.0
        print(f"  {'stage':<20} {'median':>12}  {'xN':>4}  {'per message':>13}")
        for label, fn, times in stages:
            median, _ = timeit(fn)
            per_msg = median * times
            if "compress" in label and "de" not in label or label in ("aesgcm.encrypt", "ecdsa.sign", "wordcoder.encode"):
                total_send += per_msg
            else:
                total_recv += per_msg
            print(f"  {label:<20} {fmt(median)}  x{times:<3}  {fmt(per_msg)}")
        print(f"  {'TOTAL send':<20} {'':>12}        {fmt(total_send)}")
        print(f"  {'TOTAL recv':<20} {'':>12}        {fmt(total_recv)}")
        print(f"  {'THROUGHPUT send':<20} {'':>12}        {len(raw) / total_send / 1024:8.1f} KiB/s")


if __name__ == "__main__":
    main()
