import logging
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from levels.base import Base  # noqa: E402
from levels.packet import TransportPacket  # noqa: E402
from levels.transport import Transport  # noqa: E402

DATA_FLAG = 0x0
ACK_FLAG = 0x1


class CollectingUpper:
    """Stands in for the presentation level: keeps whatever got reassembled."""

    def __init__(self):
        self.received = []

    def receive(self, data):
        self.received.append(data)


class RecordingLower:
    """Stands in for the transitional level: keeps whatever hit the channel."""

    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data)

    def send_without_encrypt(self, data):
        self.sent.append(data)


def make_transport():
    transport = Transport()
    upper, lower = CollectingUpper(), RecordingLower()
    transport.update_levels(upper, lower)
    return transport, upper, lower


def stop(transport):
    Base.stop_event.set()
    time.sleep(1.2)
    Base.stop_event.clear()


def chunk(payload, stream_id=0, chunk_count=1, chunk_id=0, age=0):
    packet = TransportPacket(DATA_FLAG, stream_id, chunk_count, chunk_id, int(time.time()) - age, payload)
    return packet.to_bytes()


def acknowledgments(lower):
    return [raw for raw in lower.sent if TransportPacket.from_bytes(raw).flags == ACK_FLAG]


# ---------------------------------------------------------------- tests

def test_whole_stream_reassembles():
    transport, upper, lower = make_transport()
    try:
        for chunk_id, payload in enumerate((b"one", b"two", b"three")):
            transport.rworker(chunk(payload, stream_id=5, chunk_count=3, chunk_id=chunk_id))

        assert upper.received == [b"onetwothree"], f"unexpected payload: {upper.received}"
        assert transport.WAITING_STREAMS == {}, "completed stream was left behind"
        assert len(acknowledgments(lower)) == 3, "every data packet must be acknowledged"
    finally:
        stop(transport)


def test_bogus_chunk_count_is_refused():
    transport, upper, lower = make_transport()
    try:
        bogus = [
            ("zero chunks", chunk(b"x", stream_id=1, chunk_count=0, chunk_id=0)),
            ("over the cap", chunk(b"x", stream_id=2, chunk_count=Transport.MAX_STREAM_CHUNKS + 1, chunk_id=0)),
            ("id out of range", chunk(b"x", stream_id=3, chunk_count=2, chunk_id=7)),
        ]
        for label, raw in bogus:
            transport.rworker(raw)
            assert transport.WAITING_STREAMS == {}, f"{label}: reserved memory for a bogus header"

        assert upper.received == [], f"bogus headers delivered data: {upper.received}"
        assert acknowledgments(lower) == [], "a packet we refuse must not be acknowledged"
    finally:
        stop(transport)


def test_abandoned_stream_is_forgotten():
    transport, upper, lower = make_transport()
    try:
        transport.STREAM_TIMEOUT = 0.2

        transport.rworker(chunk(b"OLD", stream_id=9, chunk_count=3, chunk_id=0))
        assert 9 in transport.WAITING_STREAMS, "first chunk did not open a stream"

        time.sleep(0.4)

        # Любой следующий пакет запускает уборку просроченных потоков
        transport.rworker(chunk(b"UNRELATED", stream_id=1, chunk_count=1, chunk_id=0))
        assert 9 not in transport.WAITING_STREAMS, "abandoned stream survived its deadline"

        # Тот же stream_id после оборота: данные не должны склеиться со старым огрызком
        transport.rworker(chunk(b"NEW", stream_id=9, chunk_count=1, chunk_id=0))
        assert upper.received == [b"UNRELATED", b"NEW"], f"stale chunk leaked into a new stream: {upper.received}"
    finally:
        stop(transport)


def test_stream_id_reuse_does_not_merge():
    transport, upper, lower = make_transport()
    try:
        transport.rworker(chunk(b"OLD", stream_id=9, chunk_count=3, chunk_id=0))
        transport.rworker(chunk(b"NEW", stream_id=9, chunk_count=1, chunk_id=0))

        assert upper.received == [b"NEW"], f"streams were merged: {upper.received}"
        assert transport.WAITING_STREAMS == {}, "stale stream was left behind"
    finally:
        stop(transport)


def test_stream_table_stays_bounded():
    transport, upper, lower = make_transport()
    try:
        opened = Transport.MAX_WAITING_STREAMS + 8
        for stream_id in range(opened):
            transport.rworker(chunk(b"x", stream_id=stream_id, chunk_count=2, chunk_id=0))

        assert len(transport.WAITING_STREAMS) <= Transport.MAX_WAITING_STREAMS, (
            f"table grew to {len(transport.WAITING_STREAMS)} streams, cap is {Transport.MAX_WAITING_STREAMS}"
        )
        assert opened - 1 in transport.WAITING_STREAMS, "the newest stream was the one evicted"
        assert upper.received == [], "nothing was complete, yet something was delivered"
    finally:
        stop(transport)


def test_stream_byte_budget_is_enforced():
    transport, upper, lower = make_transport()
    try:
        transport.MAX_STREAM_BYTES = 300

        for chunk_id in range(4):
            transport.rworker(chunk(b"p" * 100, stream_id=4, chunk_count=5, chunk_id=chunk_id))

        assert 4 not in transport.WAITING_STREAMS, "oversized stream stayed in memory"
        assert upper.received == [], "oversized stream was delivered"
    finally:
        stop(transport)


def test_timestamp_window_is_symmetric():
    transport, upper, lower = make_transport()
    try:
        transport.rworker(chunk(b"future", stream_id=10, age=-3600))
        transport.rworker(chunk(b"ancient", stream_id=11, age=Transport.PACKET_MAX_AGE + 10))

        assert upper.received == [], f"packet outside the window was accepted: {upper.received}"
        assert acknowledgments(lower) == [], "a packet outside the window must not be acknowledged"
        assert transport.WAITING_STREAMS == {}, "packet outside the window reserved memory"

        # Расхождение часов в пределах допуска и свежий пакет из прошлого проходят
        transport.rworker(chunk(b"skewed", stream_id=12, age=-(Transport.CLOCK_SKEW_TOLERANCE - 10)))
        transport.rworker(chunk(b"recent", stream_id=13, age=30))

        assert upper.received == [b"skewed", b"recent"], f"legitimate packets were dropped: {upper.received}"
    finally:
        stop(transport)


TESTS = [
    test_whole_stream_reassembles,
    test_bogus_chunk_count_is_refused,
    test_abandoned_stream_is_forgotten,
    test_stream_id_reuse_does_not_merge,
    test_stream_table_stays_bounded,
    test_stream_byte_budget_is_enforced,
    test_timestamp_window_is_symmetric,
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
