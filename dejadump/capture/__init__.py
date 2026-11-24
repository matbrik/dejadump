"""Capture adapters that turn external evidence into epochs.

Tenet/Frinet trace import lives in :mod:`dejadump.core.tenet`; this subpackage
adds the dump-based path (two or more memory images of the same module diffed into
epochs), used for before/after captures such as an encrypted → decrypted library.
Pure Python, no IDA.
"""

from .rawdump import import_elf_pair, import_image_pair

__all__ = ["import_elf_pair", "import_image_pair"]
