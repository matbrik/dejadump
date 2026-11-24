"""Netnode index shim.

The IDB-resident index ``$ dejadump`` ties an IDB to its sidecar (schema
version, relative sidecar path, active epoch, shadow params, a content hash to
detect a mismatched sidecar).  Small scalars live in the netnode's string-keyed
hash values (<1024 B); anything larger uses ``setblob``/``getblob``.

Behind a shim so the engine tests headless: when the IDA SDK is unavailable the
in-memory backend stands in.
"""

from __future__ import annotations

import json
import zlib
from typing import Optional

NETNODE_NAME = "$ dejadump"
#: Netnode written by builds released under the earlier name; read as a fallback.
LEGACY_NETNODE_NAME = "$ palimpsest"
_TAG = "H"
_BLOB_TAG = "B"


class _InMemoryBackend:
    def __init__(self):
        self._vals: dict[str, str] = {}
        self._blobs: dict[str, bytes] = {}

    def set_val(self, key, value):
        self._vals[key] = value

    def get_val(self, key):
        return self._vals.get(key)

    def set_blob(self, key, data):
        self._blobs[key] = data

    def get_blob(self, key):
        return self._blobs.get(key)


class _IdaNetnodeBackend:  # pragma: no cover - requires IDA
    """String-keyed storage in the ``$ dejadump`` netnode.

    Uses the netnode *hash* API, keyed by the key string itself.  (An integer
    slot derived from Python's ``hash()`` would change every IDA session, since
    string hashing is randomised per process.)
    """

    def __init__(self, ida_netnode):
        self._nn = ida_netnode.netnode(NETNODE_NAME, 0, True)
        self._mod = ida_netnode
        self._legacy = None
        try:
            legacy = ida_netnode.netnode(LEGACY_NETNODE_NAME, 0, False)
            if legacy.index() != ida_netnode.BADNODE:
                self._legacy = legacy
        except Exception:
            pass

    def set_val(self, key, value):
        self._nn.hashset_buf(key, value.encode("utf-8"), ord(_TAG))

    def get_val(self, key):
        raw = self._nn.hashstr_buf(key, ord(_TAG))
        if not raw and self._legacy is not None:
            raw = self._legacy.hashstr_buf(key, ord(_TAG))
        if not raw:
            return None
        return raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)

    def set_blob(self, key, data):
        self._nn.setblob(data, _blob_slot(key), ord(_BLOB_TAG))

    def get_blob(self, key):
        return self._nn.getblob(_blob_slot(key), ord(_BLOB_TAG))


def _blob_slot(key: str) -> int:
    """Stable (process-independent) blob slot for a key."""
    return zlib.crc32(key.encode("utf-8")) & 0x7FFFFFFF


class NetnodeIndex:
    """Key/value + blob index with a JSON-friendly scalar interface."""

    def __init__(self, backend=None):
        self._b = backend or _InMemoryBackend()

    def set(self, key: str, value) -> None:
        self._b.set_val(key, json.dumps(value))

    def get(self, key: str, default=None):
        raw = self._b.get_val(key)
        return json.loads(raw) if raw is not None else default

    def set_blob(self, key: str, data: bytes) -> None:
        self._b.set_blob(key, data)

    def get_blob(self, key: str) -> Optional[bytes]:
        return self._b.get_blob(key)


def open_index() -> NetnodeIndex:
    """Return an index bound to the open IDB when in IDA, else an in-memory stand-in.

    Call this only while a database is open (the controller opens it lazily).
    """
    try:  # pragma: no cover - only in IDA
        import ida_netnode

        return NetnodeIndex(_IdaNetnodeBackend(ida_netnode))
    except Exception:
        return NetnodeIndex()
