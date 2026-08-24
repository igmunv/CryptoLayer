"""End-to-end CryptoLayer benchmark: two real peers over an in-memory channel.

Measures handshake time, per-message latency and sustained throughput
through the full stack (brotli + AES-GCM + chunking + ACK + ECDSA + WordCoder).

Run: python3 bench/e2e.py [--latency MS] [--messages N] [--size BYTES]
"""
import argparse
import logging
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from loopback import Loopback  # noqa: E402  (needs sys.path above)

import config  # noqa: E402
from UIProvider import UIProvider  # noqa: E402

SYLL_A = ["ba", "ve", "gi", "do", "zhu", "ki", "la", "mo", "ne", "pu", "ra", "so", "tu", "fi", "ha", "che"]
SYLL_B = ["lom", "ves", "gor", "dym", "zhar", "kit", "lug", "mox", "nos", "puh", "rov", "sud", "tir", "fon", "hor", "chan"]
WORDCODER_DICT = {
    f"{a * 16 + b:02x}": SYLL_A[a] + SYLL_B[b]
    for a in range(16)
    for b in range(16)
}

TEXT = ("Slushay, ya zapushil fiks v main, CI zelyonyy. Proverь pozhaluysta "
        "handshake na svoey storone, u menya ne vosproizvoditsya nikak. ")


class SilentUI(UIProvider):
    """Auto-trusting UI so the handshake runs unattended."""

    def __init__(self, name):
        self.name = name
        self.ready = threading.Event()
        self.received = []
        self.recv_lock = threading.Lock()

    def request_data(self, prompt, data_type):
        return ""

    def update_status(self, stage, message, status_type="in_progress"):
        pass

    def on_text_received(self, timestamp, text):
        with self.recv_lock:
            self.received.append((time.perf_counter(), text))

    def check_signatures(self, my_sign, companion_sign):
        return True

    def on_ready(self):
        self.ready.set()

    def on_ping_timeout(self):
        pass

    def on_disconnect(self):
        pass


def build_pair(latency_s, data_root):
    """Return (peer_a, peer_b, ui_a, ui_b) with the handshake already done."""
    from crypto_layer import CryptoLayer

    mod_a = Loopback(latency_s, "A")
    mod_b = Loopback(latency_s, "B")
    mod_a.peer_inbox = mod_b.inbox
    mod_b.peer_inbox = mod_a.inbox

    ui_a, ui_b = SilentUI("A"), SilentUI("B")
    peer_a = CryptoLayer(ui_a, os.path.join(data_root, "a"), mod_a, "hunter2", WORDCODER_DICT)
    peer_b = CryptoLayer(ui_b, os.path.join(data_root, "b"), mod_b, "hunter2", WORDCODER_DICT)

    errors = []

    def run(peer):
        try:
            peer.init()
        except Exception as exc:  # surfaced by the caller, never swallowed
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(p,), daemon=True) for p in (peer_a, peer_b)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    handshake = time.perf_counter() - t0

    if errors:
        raise errors[0]
    if not (ui_a.ready.is_set() and ui_b.ready.is_set()):
        raise RuntimeError("handshake did not complete within 120s")

    return peer_a, peer_b, ui_a, ui_b, handshake, (mod_a, mod_b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--latency", type=float, default=0.0, help="one-way channel latency, ms")
    ap.add_argument("--messages", type=int, default=20)
    ap.add_argument("--size", type=int, default=256, help="plaintext bytes per message")
    ap.add_argument("--incompressible", action="store_true",
                    help="use high-entropy payloads (hashes, links, base64) so brotli cannot\ncollapse them into a single chunk")
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)
    latency_s = args.latency / 1000.0
    if args.incompressible:
        import random
        payload = "".join(random.Random(7).choices("0123456789abcdef", k=args.size))
    else:
        payload = (TEXT * ((args.size // len(TEXT)) + 1))[:args.size]

    data_root = tempfile.mkdtemp(prefix="cl-bench-")
    try:
        print(f"config: CHUNK_SIZE={config.CHUNK_SIZE} (transport hardcodes its own) "
              f"COMPRESS_QUALITY={config.COMPRESS_QUALITY}")
        print(f"run:    {args.messages} msg x {args.size}B, one-way latency {args.latency}ms\n")

        peer_a, peer_b, ui_a, ui_b, handshake, mods = build_pair(latency_s, data_root)
        print(f"handshake:        {handshake:7.3f} s")

        chunk_size = peer_a.TRANSPORT_LEVEL.CHUNK_SIZE
        print(f"transport chunk:  {chunk_size} B")

        base_sent = sum(m.sent_messages for m in mods)
        base_chars = sum(m.sent_chars for m in mods)

        latencies = []
        t_start = time.perf_counter()
        for i in range(args.messages):
            sent_at = time.perf_counter()
            want = i + 1
            peer_a.send(payload)
            while len(ui_b.received) < want:
                if time.perf_counter() - sent_at > 120:
                    raise RuntimeError(f"message {i} never arrived")
                time.sleep(0.001)
            latencies.append(ui_b.received[want - 1][0] - sent_at)
        wall = time.perf_counter() - t_start

        assert all(text == payload for _, text in ui_b.received), "payload corrupted in transit"

        wire_msgs = sum(m.sent_messages for m in mods) - base_sent
        wire_chars = sum(m.sent_chars for m in mods) - base_chars

        print(f"\nlatency per message ({args.messages} samples)")
        print(f"  min             {min(latencies) * 1e3:7.1f} ms")
        print(f"  median          {statistics.median(latencies) * 1e3:7.1f} ms")
        print(f"  max             {max(latencies) * 1e3:7.1f} ms")
        print(f"\nthroughput")
        print(f"  wall            {wall:7.3f} s")
        print(f"  messages/s      {args.messages / wall:7.2f}")
        print(f"  goodput         {args.messages * args.size / wall / 1024:7.2f} KiB/s")
        print(f"\nchannel cost (both directions, incl. ACKs)")
        print(f"  channel msgs    {wire_msgs:7d}  ({wire_msgs / args.messages:.1f} per user message)")
        print(f"  channel chars   {wire_chars:7d}  ({wire_chars / (args.messages * args.size):.1f}x plaintext)")

        peer_a.stop(send_disconnect=False)
    finally:
        shutil.rmtree(data_root, ignore_errors=True)


if __name__ == "__main__":
    main()
