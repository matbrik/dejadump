"""The generator is deterministic and matches the committed fixture.

Requires Unicorn; skipped automatically where it is not installed (e.g. the
pure-Python CI lane), so this never gates CI but guards against fixture drift
on a dev machine.
"""

import os
import subprocess
import sys

import pytest

unicorn = pytest.importorskip("unicorn")
pytestmark = pytest.mark.skipif(
    sys.version_info >= (3, 14),
    reason="Unicorn is not supported reliably on the Python 3.14 development runtime",
)

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "arm64_smc.tenet")


def _generated_hashes():
    """Run Unicorn out of process: a native crash must not kill pytest/IDA."""
    code = (
        "import hashlib; from tools.mkcorpus.generate import build_trace; "
        "a,_=build_trace(); b,_=build_trace(); "
        "print(hashlib.sha256(a.encode()).hexdigest()); "
        "print(hashlib.sha256(b.encode()).hexdigest())"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=os.path.dirname(FIXTURE) + "/../..",
            text=True, capture_output=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        pytest.skip("Unicorn hung on this Python/CPU combination")
    if proc.returncode != 0:
        pytest.skip("Unicorn is not executable on this Python/CPU combination")
    return proc.stdout.strip().splitlines()


def test_build_is_deterministic():
    a, b = _generated_hashes()
    assert a == b


def test_matches_committed_fixture():
    generated, _ = _generated_hashes()
    with open(FIXTURE, "r", encoding="utf-8") as fh:
        committed = fh.read()
    import hashlib
    assert generated == hashlib.sha256(committed.encode()).hexdigest(), (
        "fixture drift: re-run `python -m tools.mkcorpus --outdir tests/fixtures`"
    )
