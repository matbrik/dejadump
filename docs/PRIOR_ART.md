# Prior-art scan — 24 November 2026

This is a dated search note for the 2026 IDA Plugin Contest. The search used HCLI
0.29.0 against the public `community` index on macOS with IDA 9.5. The separate
`hexrays` repository was unavailable without login. Search terms were `dejadump`,
`self-modifying`, `epoch`, `time-travel`, `tenet`, `trace`, and `snapshot`.

No `dejadump` entry appeared in that index on this date. The `trace` query returned
these adjacent projects:

- [ida-ttd](https://github.com/HullaBrian/ida-ttd) turns Microsoft TTD and Sogen
  recordings into an IDA debugger session.
- [memlens](https://github.com/nightshift-labs-ai/memlens) appeared in the trace
  search. Its feature overlap was not assessed in this scan.
- [Unicorn-Trace](https://github.com/chenxvb/Unicorn-Trace) produces ARM64 traces,
  including Tenet logs, from Unicorn emulation.

Earlier contest entries include [ttddbg](https://plugins.hex-rays.com/airbus-cert/ttddbg),
a time-travel debugging plugin. These are related areas; the scan does not establish
that no similar plugin exists. Recheck the public index before submitting because
it changes as new releases are indexed.
