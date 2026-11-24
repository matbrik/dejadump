"""Corpus generator for the DejaDump test/demo fixtures.

Uses offline Unicorn to run a self-built self-modifying stub and emit a
deterministic Tenet-format trace (plus a manifest), which is committed under
``tests/fixtures/`` so the core test suite needs no binary dependencies.
"""

from .generate import build_trace, generate

__all__ = ["build_trace", "generate"]
