"""In-memory BaseModule that wires two CryptoLayer peers together.

Stands in for a real messenger module so the whole stack can be exercised
without a network. One-way latency is configurable to model a real channel.
"""
import queue
import random
import threading
import time

try:
    from base_module import BaseModule, Credential
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "base_module is missing. It is declared in pyproject.toml; install the "
        "project dependencies first, e.g. `pip install -e .`"
    ) from exc


class Loopback(BaseModule):
    """A module whose channel is a queue owned by its peer.

    Set `peer_inbox` after construction; whatever `send` writes lands there
    and the peer's listener thread feeds it into its transitional level.
    """

    name = "Loopback"
    description = "In-memory channel for benchmarking"
    unique_id = "bench.loopback_0001"
    expected_credentials = [Credential("None", "unused")]

    def __init__(self, latency_s=0.0, label="?", loss=0.0, seed=0, record=False):
        super().__init__()
        self.inbox = queue.Queue()
        self.peer_inbox = None
        self.latency_s = latency_s
        self.label = label
        self.loss = loss
        self.record = record
        self.sent_messages = 0
        self.sent_chars = 0
        self.dropped = 0
        self.wire = []
        self._rng = random.Random(seed)
        self._rng_lock = threading.Lock()

    def create_session(self, ingester):
        module = self

        class Sender(BaseModule.Sender):
            def send(self, text: str):
                module.sent_messages += 1
                module.sent_chars += len(text)
                if module.record:
                    module.wire.append(text)
                if module.loss:
                    with module._rng_lock:
                        drop = module._rng.random() < module.loss
                    if drop:
                        module.dropped += 1
                        return
                if module.latency_s:
                    time.sleep(module.latency_s)
                module.peer_inbox.put(text)

        class Listener(BaseModule.Listener):
            def listen(self):
                while not self.stop_event.is_set():
                    try:
                        text = module.inbox.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    self.ingester(text)

        self.sender = Sender([], None)
        self.listener = Listener([], ingester, None, self.stop_event)
        threading.Thread(target=self.listener.listen, daemon=True).start()
