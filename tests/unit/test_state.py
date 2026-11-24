"""StateResolver read-through, diff spans, and activation planning."""

from dejadump.core.model import Epoch, Range
from dejadump.core.state import BytesBase, StateResolver


def _resolver():
    base = BytesBase([(0x1000, b"\x00" * 8)])
    epochs = [
        Epoch(seq=1, ranges=[Range(0x1000, b"\x11\x11")]),
        Epoch(seq=2, ranges=[Range(0x2000, b"\x22")]),
        Epoch(seq=3, ranges=[Range(0x1000, b"\x33\x33\x33")]),
    ]
    return StateResolver(epochs, base=base)


def test_read_through_picks_most_recent_epoch_le_k():
    r = _resolver()
    assert r.state(1, 0x1000, 4) == b"\x11\x11\x00\x00"
    assert r.state(2, 0x1000, 4) == b"\x11\x11\x00\x00"   # t2 didn't touch 0x1000
    assert r.state(3, 0x1000, 4) == b"\x33\x33\x33\x00"   # t3 overwrote
    assert r.state(0, 0x1000, 4) == b"\x00\x00\x00\x00"   # base only


def test_volatile_set_union():
    r = _resolver()
    assert r.volatile_set() == [(0x1000, 0x1003), (0x2000, 0x2001)]


def test_code_ranges_at_excludes_data():
    epochs = [
        Epoch(seq=1, ranges=[Range(0x200000, b"\xaa" * 12, entry_pcs=(0x200000,), is_code_hint=True)]),
        Epoch(seq=4, ranges=[Range(0x300000, b"plaintext_______")]),  # data, not code
    ]
    r = StateResolver(epochs)
    code3 = r.code_ranges_at(3)
    assert code3 == [(0x200000, 0x20000C, (0x200000,))]
    # At t4 the data region exists but must NOT be reported as code.
    assert all(start == 0x200000 for start, _e, _pc in r.code_ranges_at(4))


def test_diff_spans_minimal():
    spans = StateResolver.diff_spans(b"\xAA\xAA\xAA\xAA", b"\xAA\xBB\xBB\xAA")
    assert spans == [(1, b"\xBB\xBB")]
    assert StateResolver.diff_spans(b"\x00\x00", b"\x00\x00") == []
    assert StateResolver.coalesced_diff_spans(
        b"\x00\x00\x00\x00", b"\x01\x00\x00\x02", gap=4
    ) == [(0, b"\x01\x00\x00\x02")]


def test_activation_changes_only_touches_differences():
    r = _resolver()
    # Pretend the database currently holds epoch 1.
    current = {s: r.state(1, s, e - s) for s, e in r.volatile_set()}

    def old_reader(addr, size):
        for s, buf in current.items():
            if s <= addr and addr + size <= s + len(buf):
                return buf[addr - s:addr - s + size]
        return b"\x00" * size

    # t1 -> t2: only 0x2000 changes (0x2000 is written by t2); 0x1000 is identical.
    changes_12 = r.activation_changes(2, old_reader)
    assert any(addr == 0x2000 for addr, _ in changes_12)
    assert all(addr != 0x1000 for addr, _ in changes_12)

    # t1 -> t3: both regions change (t2 wrote 0x2000, t3 rewrote 0x1000).
    changes_13 = r.activation_changes(3, old_reader)
    assert dict(changes_13)[0x1000].startswith(b"\x33\x33\x33")
    assert dict(changes_13)[0x2000] == b"\x22"

    # Activating the epoch already loaded is a no-op.
    assert r.activation_changes(1, old_reader) == []
