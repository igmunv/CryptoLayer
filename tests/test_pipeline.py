"""Correctness proof for the CryptoLayer stack.

Runs two real peers over an in-memory channel and asserts the messages that
come out are exactly the messages that went in -- across sizes, unicode,
multi-chunk streams, packet loss and stream-id wraparound. Also asserts the
plaintext never reaches the channel.

Run: python3 tests/test_pipeline.py
"""
import logging
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "bench"))

from levels.transport import Transport  # noqa: E402
from loopback import Loopback  # noqa: E402
from UIProvider import UIProvider  # noqa: E402
from wordcoder import WordCoder  # noqa: E402

SYLL_A = ["ba", "ve", "gi", "do", "zhu", "ki", "la", "mo", "ne", "pu", "ra", "so", "tu", "fi", "ha", "che"]
SYLL_B = ["lom", "ves", "gor", "dym", "zhar", "kit", "lug", "mox", "nos", "puh", "rov", "sud", "tir", "fon", "hor", "chan"]
WORDCODER_DICT = {
    f"{a * 16 + b:02x}": SYLL_A[a] + SYLL_B[b]
    for a in range(16)
    for b in range(16)
}

# Канал в памяти отвечает мгновенно, ждать продакшновые 5 секунд нечего
Transport.ACK_TIMEOUT = 0.4


class CollectingUI(UIProvider):
    def __init__(self):
        self.ready = threading.Event()
        self.received = []
        self.lock = threading.Lock()

    def request_data(self, prompt, data_type):
        return ""

    def update_status(self, stage, message, status_type="in_progress"):
        pass

    def on_text_received(self, timestamp, text):
        with self.lock:
            self.received.append(text)

    def check_signatures(self, my_sign, companion_sign):
        return True

    def on_ready(self):
        self.ready.set()

    def on_ping_timeout(self):
        pass

    def on_disconnect(self):
        pass


class Peers:
    """Two handshaken CryptoLayer peers sharing an in-memory channel."""

    def __init__(self, loss=0.0, record=False):
        from crypto_layer import CryptoLayer

        self.root = tempfile.mkdtemp(prefix="cl-test-")
        self.mod_a = Loopback(loss=loss, seed=1, record=record, label="A")
        self.mod_b = Loopback(loss=loss, seed=2, record=record, label="B")
        self.mod_a.peer_inbox = self.mod_b.inbox
        self.mod_b.peer_inbox = self.mod_a.inbox

        self.ui_a, self.ui_b = CollectingUI(), CollectingUI()
        self.a = CryptoLayer(self.ui_a, os.path.join(self.root, "a"), self.mod_a, "pw", WORDCODER_DICT)
        self.b = CryptoLayer(self.ui_b, os.path.join(self.root, "b"), self.mod_b, "pw", WORDCODER_DICT)

        errors = []

        def run(peer):
            try:
                peer.init()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(p,), daemon=True) for p in (self.a, self.b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        if errors:
            raise errors[0]
        assert self.ui_a.ready.is_set() and self.ui_b.ready.is_set(), "handshake did not finish"

    def exchange(self, messages, timeout=120):
        """Send every message A->B and return what B actually received."""
        for text in messages:
            self.a.send(text)
        deadline = time.time() + timeout
        while len(self.ui_b.received) < len(messages) and time.time() < deadline:
            time.sleep(0.002)
        return list(self.ui_b.received)

    def close(self):
        from levels.base import Base
        from base_module import BaseModule

        Base.stop_event.set()
        BaseModule.stop_event.set()
        time.sleep(0.3)
        Base.stop_event.clear()
        BaseModule.stop_event.clear()
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------- tests

def test_wordcoder_roundtrip():
    wc = WordCoder(WORDCODER_DICT)
    blob = bytes(range(256)) + os.urandom(500)
    assert wc.decode(" ".join(wc.encode(blob)).split(" ")) == blob


def test_roundtrip_varied_sizes():
    """Every payload shape survives the full stack byte for byte."""
    messages = [
        "a",
        "ok",
        "Привет, как дела?",
        "emoji and rtl: ok 123",
        "x" * 99,      # just under one chunk
        "y" * 100,     # exactly one chunk boundary
        "z" * 101,     # just over
        "многочанковое " * 200,
        "".join(chr(c) for c in range(32, 500)),
    ]
    peers = Peers()
    try:
        got = peers.exchange(messages)
        assert got == messages, (
            f"payload mismatch: sent {len(messages)}, got {len(got)}; "
            f"first diff at {next((i for i, (a, b) in enumerate(zip(messages, got)) if a != b), 'n/a')}"
        )
    finally:
        peers.close()


def test_multichunk_large_message():
    """A message spanning many transport chunks reassembles in order."""
    big = "".join(f"[{i:05d}]" for i in range(2000))  # ~14 KB, incompressible-ish counter
    peers = Peers()
    try:
        got = peers.exchange([big])
        assert len(got) == 1, f"expected 1 message, got {len(got)}"
        assert got[0] == big, "large message corrupted or reordered"
    finally:
        peers.close()


def test_survives_packet_loss():
    """With 30% of channel messages dropped, retransmission still delivers intact."""
    messages = [f"message number {i} " + "padding " * (i % 7) for i in range(15)]
    peers = Peers(loss=0.30)
    try:
        got = peers.exchange(messages, timeout=180)
        assert peers.mod_a.dropped + peers.mod_b.dropped > 0, "loss injection did not fire"
        assert got == messages, f"loss corrupted the stream: got {len(got)}/{len(messages)}"
    finally:
        peers.close()


def test_stream_id_wraparound():
    """stream_id is one byte; more than 256 streams must not collide."""
    messages = [f"wrap {i}" for i in range(300)]
    peers = Peers()
    try:
        got = peers.exchange(messages, timeout=180)
        assert got == messages, (
            f"wraparound corrupted the stream at index "
            f"{next((i for i, (a, b) in enumerate(zip(messages, got)) if a != b), len(got))}"
        )
    finally:
        peers.close()


def test_plaintext_never_hits_the_channel():
    """What the messenger sees must be words, and must not contain the secret."""
    secret = "SUPERSECRETCANARY9182"
    peers = Peers(record=True)
    try:
        got = peers.exchange([secret])
        assert got == [secret]
        wire = " ".join(peers.mod_a.wire)
        assert wire, "nothing was recorded on the channel"
        assert secret not in wire, "plaintext leaked onto the channel"
        vocabulary = set(WORDCODER_DICT.values())
        tokens = set(wire.split(" "))
        assert tokens <= vocabulary, f"channel carried non-dictionary tokens: {tokens - vocabulary}"
    finally:
        peers.close()


TESTS = [
    test_wordcoder_roundtrip,
    test_roundtrip_varied_sizes,
    test_multichunk_large_message,
    test_survives_packet_loss,
    test_stream_id_wraparound,
    test_plaintext_never_hits_the_channel,
]


def main():
    logging.disable(logging.CRITICAL)
    failures = 0
    for test in TESTS:
        name = test.__name__
        start = time.perf_counter()
        try:
            test()
        except Exception as exc:
            failures += 1
            print(f"FAIL  {name}  ({time.perf_counter() - start:.2f}s)\n      {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {name}  ({time.perf_counter() - start:.2f}s)")
    print(f"\n{len(TESTS) - failures}/{len(TESTS)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
