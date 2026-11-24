"""Pre-publish sanity check for the plugin package (R4 publish dry-run proxy).

Validates ida-plugin.json against the known required shape and checks that the
files a plugins.hex-rays.com publish needs are present.  `hcli plugin lint` is the
authoritative check at publish time; this catches the common mistakes offline.

    python tools/check_package.py          # publish mode: placeholders are errors
    python tools/check_package.py --ci     # CI mode: placeholders only warn

Beyond the manifest it also guards the repository itself: no tracked file over
1 MiB, no binary/trace material outside ``tests/fixtures``, no vendor-specific
material, and no plugin import that resolves to a file git does not track (the
plugin would load locally and break for everyone else).
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_VALID_CATEGORIES = {
    "disassembly-and-processor-modules", "file-parsers-and-loaders", "decompilation",
    "debugging-and-tracing", "deobfuscation", "collaboration-and-productivity",
    "integration-with-third-parties-interoperability", "api-scripting-and-automation",
    "ui-ux-and-visualization", "malware-analysis",
    "vulnerability-research-and-exploit-development", "other",
}
_VALID_IDA = {"10.0", "9.5", "9.4", "9.3", "9.2", "9.1", "9.0sp1", "9.0"}
_MAX_TRACKED = 1 << 20
_BINARY_SUFFIXES = (".so", ".dll", ".dylib", ".exe", ".bin", ".elf", ".tenet", ".i64",
                    ".idb", ".db")
# Real-target material must never be published (see .gitignore).  Kept as a
# pattern so this file does not trip its own check.
_DENYLIST = re.compile(r"lib[x]{5}\d+|native[c]rypt|\bs[h]ield\b", re.IGNORECASE)


def _git(*args):
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                             check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout


def _module_file(module: str):
    base = os.path.join(ROOT, *module.split("."))
    for candidate in (base + ".py", os.path.join(base, "__init__.py")):
        if os.path.exists(candidate):
            return os.path.relpath(candidate, ROOT).replace(os.sep, "/")
    return None


def _plugin_imports(path: str):
    rel = os.path.relpath(path, ROOT)
    package = os.path.dirname(rel).replace(os.sep, ".")
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                parts = parts[: len(parts) - node.level + 1]
                base = ".".join(parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            yield base
            for alias in node.names:
                yield base + "." + alias.name


def _repository_checks(errors, warnings):
    listing = _git("ls-files")
    if listing is None:
        warnings.append("git unavailable — repository checks skipped")
        return
    tracked = set(listing.split())
    for rel in sorted(tracked):
        full = os.path.join(ROOT, rel)
        if not os.path.exists(full):
            continue
        if os.path.getsize(full) > _MAX_TRACKED:
            errors.append("tracked file larger than 1 MiB: %s" % rel)
        if rel.endswith(_BINARY_SUFFIXES) and not rel.startswith("tests/fixtures/"):
            errors.append("binary/trace material outside tests/fixtures: %s" % rel)
        if rel.endswith((".py", ".md", ".json", ".toml", ".yml", ".txt")) and \
                rel != "tools/check_package.py":
            text = open(full, encoding="utf-8", errors="replace").read()
            if _DENYLIST.search(text):
                errors.append("vendor-specific material referenced in %s" % rel)

    sources = [os.path.join(ROOT, "dejadump_plugin.py")]
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "dejadump")):
        sources += [os.path.join(dirpath, f) for f in files if f.endswith(".py")]
    for path in sources:
        for module in _plugin_imports(path):
            if not module.startswith("dejadump"):
                continue
            target = _module_file(module)
            if target and target not in tracked:
                errors.append("%s imports %s, which git does not track (%s)" %
                              (os.path.relpath(path, ROOT), module, target))


def main(argv=None) -> int:
    ci = "--ci" in (sys.argv[1:] if argv is None else argv)
    errors: list[str] = []
    warnings: list[str] = []

    jp = os.path.join(ROOT, "ida-plugin.json")
    try:
        with open(jp) as fh:
            doc = json.load(fh)
    except Exception as exc:
        print("FAIL: ida-plugin.json is not valid JSON:", exc)
        return 1

    if doc.get("IDAMetadataDescriptorVersion") != 1:
        errors.append("IDAMetadataDescriptorVersion must be the integer 1")
    p = doc.get("plugin", {})
    for field in ("name", "version", "entryPoint", "urls"):
        if field not in p:
            errors.append("plugin.%s is required" % field)
    if "repository" not in p.get("urls", {}):
        errors.append("plugin.urls.repository is required")
    authors = p.get("authors") or p.get("maintainers")
    if not authors or not all(a.get("email") for a in authors):
        errors.append("plugin.authors/maintainers need at least one entry with an email")

    idav = p.get("idaVersions")
    if isinstance(idav, str):
        bounds = re.fullmatch(r">=([0-9]+\.[0-9]+),<=([0-9]+\.[0-9]+)", idav)
        if not bounds or any(v not in _VALID_IDA for v in bounds.groups()):
            errors.append("plugin.idaVersions must use supported version bounds")
    elif isinstance(idav, list) and idav:
        bad = [v for v in idav if v not in _VALID_IDA]
        if bad:
            errors.append("idaVersions has non-enum values: %s" % bad)
    else:
        errors.append("plugin.idaVersions must be a supported version spec or non-empty array")
    bad_cat = [c for c in p.get("categories", []) if c not in _VALID_CATEGORIES]
    if bad_cat:
        errors.append("categories has non-enum values: %s" % bad_cat)

    entry = p.get("entryPoint", "")
    if entry and not os.path.exists(os.path.join(ROOT, entry)):
        errors.append("entryPoint file missing: %s" % entry)
    for needed in ("dejadump", "LICENSE", "README.md"):
        if not os.path.exists(os.path.join(ROOT, needed)):
            errors.append("missing: %s" % needed)

    if "YOURUSER" in json.dumps(doc):
        (warnings if ci else errors).append(
            "urls.repository still contains the 'YOURUSER' placeholder — set the real "
            "repo before publishing")

    _repository_checks(errors, warnings)

    for w in warnings:
        print("WARN:", w)
    for e in errors:
        print("FAIL:", e)
    if not errors:
        print("OK: ida-plugin.json and package layout look publish-ready (run `hcli plugin lint` to confirm).")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
