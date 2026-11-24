# DejaDump — Formats

## 1. Tenet / Frinet trace (the subset DéjàDump reads)

One line per executed instruction, comma-separated `key=value` deltas:

| token | meaning | used |
|---|---|---|
| `<reg>=<hex>` | register value after the instruction (e.g. `pc=`, `rip=`) | only the PC register |
| `mr=<addr>:<hexbytes>` | memory read | **yes** — reads of never-written bytes form the *observed* layer (data views only) |
| `mw=<addr>:<hexbytes>` | memory write | **yes** |
| `mrw=<addr>:<hexbytes>` | read **and** write (e.g. `inc [rax]`) | **yes** — routed to both paths |
| `slide=<hex>` | Frinet header: runtime base of the traced module | **yes** — see rebasing below |

A line may carry **several** memory tokens; all are parsed. A line whose memory
token cannot be parsed is skipped and counted (the import reports the first one).

**Writer-PC lag (important).** On a Tenet line the PC is the *current*,
not-yet-executed instruction, while the deltas belong to the *previous* one, and a
store's bytes appear on the line *after* the store. So the writer of an `mw=` read
on line *N* is the PC of line *N-1*. DéjàDump applies each line's writes
attributed to the previous PC, then runs the wave check for the current PC
(`WRITE_PC_LAG = 1` in `dejadump/core/tenet.py`). The written bytes are the
*post-write* value; original bytes are not in the trace.

**Architecture.** Tenet ships arch files for x86/amd64 only (32-register cap).
DéjàDump defines its own mapping and only needs the PC + writes, so it is not
bound by that cap. PC token: `pc` (arm64), `rip` (amd64), `eip` (x86).

**Frinet extensions.** Frinet writes one trace per thread,
`<proc>_<epoch>_<tid>.tenet`, with absolute runtime addresses. When tracing one
module the first line is `slide=0x…` — that module's runtime base. With `-t '*'`
it also writes `<proc>_<epoch>.modules`, one `<name> <start> <end>` line per module.

**Rebasing.** Stored addresses are canonical (IDB) addresses:
`canonical = runtime − runtime_base + idb_base`. The runtime base comes from, in
order: a manifest, the `slide=` header, the IDB module's line in a `.modules` file,
auto-detection from executed PCs (confirmed by the user), or a prompt.

**Filtering.** Writes are kept only inside the IDB's segments (or a manifest
`keep` list); others are counted as dropped. A write straddling an edge is clipped.

### Optional manifest (`<trace>.dejadump.json` or `<trace>.json`)

```json
{"arch": "arm64", "slide": "0x7e000000", "image_base": "0x0",
 "module": "libtarget.so", "keep": [["0x0", "0x6f0000"]]}
```
All keys are optional; numbers may be JSON integers or `"0x…"` strings. `arch` is
one of `arm64`, `amd64`, `x86`.

## 2. Corpus manifest (`manifest.json`)

```json
{
  "arch": "arm64",
  "page": 4096,
  "regions": { "code": {"base": ..., "size": ...}, "buf": {...}, "data": {...} },
  "key": 90, "markers": [170,187,204], "plaintext": "DEJADUMP_OK!!!!\u0000",
  "dumps": { "code": {"base": ..., "path": "dumps/arm64_smc_code_t0.bin"}, ... },
  "elf": "arm64_smc.elf",
  "x64": { ...same shape for the x86-64 bundle... }
}
```

## 2b. Image and dump inputs

* **File-layout pair** (*Import decrypted image pair…*): the original input file
  (t0) and a same-layout modified file. ELF32/ELF64 (either endianness) offsets are
  mapped through `PT_LOAD` program headers; other files are flat images at the IDB
  image base.
* **Memory-layout dumps** (*Import memory dump(s)…*, `python -m dejadump dumps
  FILE@ADDR …`): raw bytes starting at a given IDB address. Dump *i* is diffed
  against dump *i−1* (the first against the IDB) and becomes epoch *i*; only bytes
  inside the IDB's segments are used.
* **Debugger snapshots**: the program's segments read from the suspended process,
  converted to IDB addresses, diffed in capture order like memory dumps.

Changed bytes are coalesced across unchanged gaps of ≤ 64 bytes. These records
have no writer instruction (`writer_pc` is NULL; shown as `dump`).

## 3. Sidecar database (`<idb>.dejadump.db`, SQLite)

```
meta(key, value)                         -- schema_version, active source/epoch, fingerprints
sources(id, kind, label, created, params, signature)   -- signature: content hash (duplicate detection)
epochs(id, source_id, seq, label, boundary_kind, boundary_pc, trace_index, created, note, repeat_count)
                                         -- UNIQUE(source_id, seq)
ranges(id, epoch_id, start, size, sha256, is_code_hint, entry_pcs, blob_id) -- 1 code, 0 data, -1 unknown
blobs(id, sha256 UNIQUE, data)           -- content-addressed: identical stages stored once
writes(id, epoch_id, seq, writer_pc, addr, size, new_bytes, old_bytes)
                                         -- indexes: addr; addr WHERE size>64; (writer_pc, epoch_id)
annots(epoch_id, range_start, payload, revision) -- versioned analyst state (JSON; revision added by ALTER)
shared_annots(source_id, range_start, payload, revision) -- promoted annotation overlay
pins(epoch_id, shadow_base, stride, segments)   -- owned sparse shadow segments
base(start, size, blob_id)               -- t0 bytes of every volatile range (gaps filled per source)
observed(source_id, start, size, blob_id) -- bytes read but never written (data views only)
analysis_artifacts(id, epoch_id, kind, start, end, version_key, payload, duration_ms)
                                         -- a new version_key replaces older ones for the same view
activation_journal(id, source_epoch_id, target_epoch_id, source_seq, target_seq, status, payload, created)
                                         -- last 200 finished entries are kept
owned_xrefs(epoch_id, src, dst, kind)     -- only xrefs DéjàDump may remove
```
`boundary_kind` ∈ `wave | end | dump | snapshot | manual` (`bpt` / `mprotect` are
reserved). The implicit t0 of source *s* is stored under epoch id `−s` in `annots`
and `analysis_artifacts`. Bulk import uses
`executemany` + WAL + temporary `synchronous=OFF`; normal durability is restored
and WAL is checkpointed after the load. Opening a v1 sidecar creates a recoverable
`.v1.bak` and migrates annotations from sequence numbers to stable epoch IDs; v2 → v3
adds `sources.signature` and the `observed` table in place. *Compact sidecar*
deletes unreferenced blobs (keeping preimages of a pending switch) and VACUUMs.

## 4. Netnode index (`$ dejadump`, inside the IDB)

Ties the IDB to its sidecar: `active_epoch`, `content_hash`, and an
`idb_fingerprint` (input hash, image base, processor, bitness, and segment layout)
so a sidecar opened against a different database is detected and refused, plus
`sidecar_path` (relative to the IDB) when the sidecar was located elsewhere.
Values live in the netnode's string-keyed hash values (stable across sessions);
larger objects use `setblob`/`getblob` at a CRC32-derived slot. Everything needed to reconstruct epoch 0 is intrinsic to the
IDB, so a lost sidecar never corrupts the database — it only loses history.
