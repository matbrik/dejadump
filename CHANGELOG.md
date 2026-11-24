# Changelog

All notable changes to DéjàDump are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses [SemVer](https://semver.org/).

## [0.4.0] - 2026-11-24

### Fixed
- Re-enabled the DejaDump toolbar on macOS for IDA 9.5, retaining PNG icon
  conversion and guarded registration for restored toolbars.
- **One session per database.** The plugin no longer keeps one controller for the
  whole IDA process: a session is created when a database opens and closed with it,
  so a second IDB can never reuse the first one's sidecar, netnode or epoch state.
- **Netnode index is readable across restarts.** Keys were stored at slots derived
  from Python's per-process randomised `hash()`; they now use the netnode's
  string-keyed hash values. *Locate sidecar…* is remembered (relative to the IDB).
- **Multiple sources keep a correct t0.** A later source covering new addresses gets
  its own t0 snapshot (it previously read as zeros, so *Revert to t0* could write
  zeros), and importing or selecting a source first reverts the current one to t0.
- **Per-epoch annotations no longer leak.** Names, comments, extra lines, colours,
  types, operand formats and Hex-Rays variable settings of the outgoing epoch are
  removed (an annotation *delta*) instead of persisting under the next epoch.
- Write History, temporal xrefs and Memory Timeline tooltips no longer fail on
  image/dump records, which have no writer instruction.
- Undo/redo after a switch is detected: the loaded bytes are verified before every
  switch, so annotations are never saved into the wrong epoch.
- The Epoch Timeline slider switches on keyboard and track clicks (debounced) and
  always resynchronises after a failed switch.
- Traces are filtered to the IDB's segments (stack/heap writes used to make every
  switch fail) and malformed lines are skipped and counted instead of aborting.
- *Materialize write provenance* aggregates per writer (one comment line per epoch,
  capped xrefs, one decompilation per function); removal now also strips the
  comments and pseudocode notes and never deletes pre-existing xrefs.
- The "auto-analysis still running" guard now works, and a switch (or pin/unpin)
  finishes the analysis it queued itself — including after restoring annotations
  and after a rollback — so consecutive switches are not refused.
- Ranges a trace wrote but never executed are no longer treated as data when they
  lie in an executable segment (a trace often ends before decrypted code runs);
  they are analysed from safe seeds. Verified on a real 7 MB runtime-decrypted
  library with idalib 9.4 and 9.5 (`tools/smoke_real_pair.py`).
- Settings never saved read as *off* inside IDA (its registry returns an empty
  string, not nothing, for a missing value), which silently disabled the trace
  filter and changed-line highlighting. Defaults now apply until you save.
- A rebase from a manifest, `slide=` header or `.modules` file is checked against
  the executed addresses; when detection fits the IDB better you are asked first.
  The demo corpus traces no longer start with a misleading `slide=0x0`, which in
  the GUI shifted every address by the image base.
- A switch whose bytes fall outside every segment is refused before anything is
  written, with the likely cause, instead of failing mid-swap ("byte swap failed").
- Annotation deltas test whether the *item* at an address changed, not only its
  first byte (an x86 rewrite of just an immediate).
- Pins use sparse shadow segments mirroring the canonical segment's bitness and
  permissions; `StateResolver` no longer keeps every resolver alive through a
  module-level cache; actions are disabled when they cannot run and no longer
  create empty sidecars.

### Performance
- Dirty intervals use bisect insertion: 200,000 scattered writes import in ~1.5 s
  (40,000 previously took ~90 s).
- Switching re-captures only annotation pages edited since the last switch (IDB and
  Hex-Rays hooks), with flag pre-checks before per-operand queries.
- Content hashes and panel statistics come from SQL aggregates (no blob reads);
  startup identification reads the volatile set once; write lookups are bounded
  index scans; Write History follows the cursor via `screen_ea_changed`.
- Imports, provenance and worker rendering show cancellable progress; pseudocode
  line mapping parses ctree anchors instead of probing every character; the
  renderers are shared by the live path and the idalib worker.
- Sidecar hygiene: stale cached renderings are replaced, the journal is capped,
  duplicate imports are detected, and *Compact sidecar* collects and VACUUMs.

### Added
- **Import memory dump(s)…** for memory-layout dumps (GDB, LLDB, Frida, pe-sieve,
  `/proc/<pid>/mem`), **Capture epoch from debugger** / **Import debugger
  snapshots…**, and ELF32 support for image pairs.
- **Bring-your-own trace:** rebasing from manifests, Frinet `slide=` headers and
  `.modules` maps, or auto-detection from executed PCs; observed reads (`mr=`) are
  folded into the data views.
- **Wave summary**, **changed-line highlighting** (line-rendering hook, no IDB
  colours), **Search all epochs…**, **Export epoch as file…**, **Go to epoch…**.
- Native epoch picker, **Manage sources…** (select/rename/delete), **Settings…**
  (stored in IDA's registry, with an idalib interpreter test), aligned and coloured
  side-by-side diffs, an active-epoch column and observed-value styling in the
  Memory Timeline, and a *Follow cursor* Write History.
- Headless CLI: `python -m dejadump import|dumps|info|export|compact`.
- Docs: a complete [User Guide](docs/USER_GUIDE.md) and a rewritten
  [demo](docs/DEMO.md) covering every main feature; `tools/make_demo_dumps.py` and
  the generic `tools/verify_image_pair.py`.
- Packaging/CI: the idalib worker ships inside the package, every plugin module is
  import-tested against stubbed IDA modules, CI covers Python 3.10–3.14 plus a lint
  lane, and `tools/check_package.py` rejects oversized or out-of-place binaries,
  vendor-specific material and imports of untracked files.

### Changed
- **Renamed from Palimpsest to DéjàDump.** Identifiers use the ASCII spelling
  `DejaDump` / `dejadump`: package `dejadump`, entry point `dejadump_plugin.py`,
  `python -m dejadump`, menu *Edit → DejaDump*, `DEJADUMP_*` environment variables,
  `<idb>.dejadump.db` sidecars and the `$ dejadump` netnode. Sidecars, comment
  banners, pinned segments and netnode values written under the old name are still
  recognised. The demo corpus now decrypts to `DEJADUMP_OK!!!!`.
- Sidecar schema v3 (`sources.signature`, `observed`, new write indexes); v2
  sidecars migrate in place.
- Menu actions are grouped into Import / Navigate / Views / Compare / Pins /
  Annotations / Sidecar submenus; *Select capture source…* became *Manage sources…*.
- Target-specific capture tooling was removed from the repository; the docs link
  to established third-party tracers and dumpers instead.

### Earlier unreleased changes
- When loaded IDB bytes do not match a stored epoch, offer to capture the current
  differences from the on-disk/base image as a new manual epoch instead of only
  disabling epoch switching.
- Added a native DejaDump toolbar for opening the timeline, switching to the
  previous/next epoch, context-aware assembly/pseudocode comparison, and
  temporal xrefs at the cursor.

## [0.3.0] - 2026-10-26

### Reliability and epoch comparison
- Sidecar schema v2 adds stable `(source, epoch)` identities, automatic v1 backup
  and migration, annotation revisions, activation journals, cached analysis
  artifacts, owned-xref tracking, and persistent pin metadata.
- Mode A now reconciles loaded bytes at startup, plans hash-bounded transitions,
  skips analysis for data-only changes, uses ranged auto-analysis, records timing,
  caches recent transition plans, verifies writes, and rolls back from
  content-addressed preimages on failure. Stage-aware journals recover annotations
  after an interrupted process.
- Added cached normalized assembly, pseudocode, and byte diffs, with navigable line
  mappings, assembly fallback, transactional live-IDB capture, and a bounded,
  cancellable, crash-recovering JSON-RPC idalib worker pool.
- Added AArch64/x86-64 sparse shadow pinning, stable-target xref stitching, exact
  owned-object cleanup, and previewable opt-in rebasing for typed pointers only.
- Annotation round-tripping now includes function flags/comments/frame sizes, operand
  representations, manual
  instructions, extra comments, forced operands, function tails, name attributes,
  and Hex-Rays lvar settings; annotations can be promoted or copied between epochs,
  promoted annotations use a distinct source-scoped shared overlay, and volatile
  banners no longer hide user colors.
- Memory Timeline selections now support 4 KiB with changed-row/A-B filtering,
  address search, and filtered Markdown export; temporal xrefs are recorded as
  plugin-owned and can be removed cleanly.
- Side-by-side assembly artifacts retain line-to-address navigation; IDB identity
  now incorporates image base, processor, bitness, input hash, and segment layout.
- Epoch browsing adds favorites, filtering, source selection, history navigation,
  cached non-mutating previews, artifact timing/status, sidecar location/health,
  selected/current/all analysis actions, pin controls, block-change summaries,
  and disassembly/pseudocode context-menu actions.
- Unicorn corpus generation is isolated from pytest and skipped on the unsupported
  Python 3.14 development runtime instead of crashing the entire test process.
- The licensed idalib smoke harness is repeatable (temporary IDBs), checks data-only
  activation and pin cleanup, and passes against both IDA 9.4 and 9.5; its optional
  fault matrix verifies rollback at every activation-journal stage.
- Real encrypted/decrypted ELF testing no longer treats coalesced diff starts as
  code entries. Large executable islands use loader exports and saved target
  functions, and switching refuses to inherit unfinished global auto-analysis
  queues. Added an isolated `smoke_real_pair.py` recovery/activation harness.

### Added
- **Engine (pure Python, headless-tested):** epoch/wave model; byte-granular
  `WaveDetector`; content-addressed SQLite sidecar + netnode index; streaming
  Tenet/Frinet importer (`mr`/`mw`/`mrw`, multi-token lines, writer-PC lag,
  `slide=` header); read-through `StateResolver` with minimal activation diffs;
  `MemoryTimeline` model (per-epoch values, change flags, first-plaintext).
- **Mode A time-slider:** swap an epoch into the canonical address space, re-run
  analysis over changed code ranges (ARM `T` set before `AU_CODE`), restore
  per-epoch annotations, invalidate the Hex-Rays cache; deterministic *Revert to t0*.
- **Panels (PySide6):** Epoch Timeline (slider, `Alt+[` / `Alt+]`), Memory Timeline
  (per-epoch columns, changed-cell highlight, CSV export, double-click → writer),
  Write History.
- **Temporal cross-references:** attribute writes to the real writer instruction and
  materialise `dr_W` xrefs + comments; "Temporal xrefs for this address" shows every
  epoch a location was written.
- **Asm-view decoration:** volatile regions carry an anterior banner
  showing the active epoch and available versions.
- **Dump-pair capture:** import a before/after pair of a module (encrypted → decrypted)
  as epochs, mapping ELF file offsets to virtual addresses; new "Import decrypted image
  pair…" action. Validated out-of-tree on a real ~7 MB runtime-decrypted native
  library (`.text` entropy 8.00 → 6.8; arm64 prologues 1 → 1600+).
- **Corpus:** self-built ARM64 **and** x86-64 self-modifying stubs generated with
  offline Unicorn, shipped as AArch64 / x86-64 ELFs + Tenet traces + dumps.
- **Tooling:** `tools/mkcorpus` (corpus generator), `tools/smoke_mode_a.py` (idalib
  smoke), `tools/setup_demo_idb.py` (in-IDA demo scene), `tools/bench_import.py`
  (import benchmark), `tools/bench_transitions.py` (planning/cache benchmark),
  `tools/check_package.py` (publish-readiness check).
- **Docs:** README, `docs/DESIGN.md`, `docs/FORMATS.md`, `docs/DEMO.md`.

### Performance
- Tenet import ≈ 1.1 M lines/s; a 5 M-line trace imports in ~5 s (target < 3 min).

### Notes
- Primary targets are IDA 9.4 / 9.5. idalib and Hex-Rays features degrade to
  live assembly switching when those capabilities are unavailable.
