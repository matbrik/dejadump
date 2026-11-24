"""DejaDump — a time axis for the IDA database.

Versioned code and versioned data in a single IDB: every observed version of a
memory region (an *epoch* / execution "wave") is kept, deduplicated, with
provenance, and made analysable with unmodified IDA machinery.

This package is split so that the engine (``dejadump.core``) is pure Python and
unit-testable without IDA, while anything that touches the IDA SDK lives in
``dejadump.modes`` / ``dejadump.ui`` / ``dejadump.hexrays`` and is only
imported inside IDA.
"""

__version__ = "0.4.0"
