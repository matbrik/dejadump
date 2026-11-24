"""idalib worker client protocol, exercised with a fake worker (no IDA needed):
replies are matched by id, noisy stderr cannot block the worker, cancellation
and early exits surface as errors."""

import os
import stat
import sys
import textwrap

import pytest

from dejadump.ghost import GhostWorkerClient

FAKE = textwrap.dedent('''
    import json, sys, time
    for raw in sys.stdin:
        req = json.loads(raw)
        sys.stderr.write("x" * 70000 + "\\n")       # more than a pipe buffer
        sys.stderr.flush()
        if req["op"] == "capabilities":
            out = {"ok": True, "hexrays": False}
        elif req["op"] == "prepare_epoch":
            out = {"ok": True, "epoch": req["epoch"]}
        elif req["op"] == "render_assembly":
            if req["start"] == 0xdead:
                time.sleep(30)
            out = {"ok": True, "lines": ["nop"], "addresses": [req["start"]]}
        elif req["op"] == "crash":
            sys.exit(3)
        else:
            out = {"ok": True}
        out["id"] = req["id"]
        print(json.dumps(out), flush=True)
        if req["op"] == "shutdown":
            break
''')


@pytest.fixture
def client(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX wrapper script")
    fake = tmp_path / "fake_worker.py"
    fake.write_text(FAKE)
    wrapper = tmp_path / "python"
    wrapper.write_text('#!/bin/sh\nexec "%s" "%s"\n' % (sys.executable, fake))
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    idb, sidecar = tmp_path / "t.i64", tmp_path / "t.db"
    idb.write_bytes(b"")
    sidecar.write_bytes(b"")
    worker = GhostWorkerClient(None, str(wrapper), template_idb=str(idb),
                               template_sidecar=str(sidecar))
    yield worker
    worker.close()


def test_requests_round_trip_despite_noisy_stderr(client):
    assert client.capabilities["ok"] is True
    reply = client.render(2, "assembly", 0x1000, 0x1004)
    assert reply["lines"] == ["nop"] and reply["addresses"] == [0x1000]


def test_cancellation_terminates_the_request(client):
    calls = []

    def cancelled():
        calls.append(1)
        return len(calls) > 3

    with pytest.raises(InterruptedError):
        client.render(1, "assembly", 0xdead, 0xdeae, cancelled=cancelled)


def test_worker_exit_is_reported(client):
    with pytest.raises(RuntimeError):
        client.request("crash", timeout=10)
