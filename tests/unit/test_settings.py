"""Settings: environment variables override stored values; outside IDA an
in-memory store stands in for the registry."""

from dejadump.util import fmt, settings


def test_env_overrides_and_memory_store(monkeypatch):
    monkeypatch.delenv("DEJADUMP_WORKERS", raising=False)
    monkeypatch.setattr(settings, "_memory", {})
    assert settings.get("workers") == "2"
    settings.set("workers", "3")
    assert settings.get_int("workers", 2, 1, 4) == 3
    monkeypatch.setenv("DEJADUMP_WORKERS", "9")
    assert settings.get_int("workers", 2, 1, 4) == 4          # clamped
    assert settings.env_override("workers") == "DEJADUMP_WORKERS"


def test_unwritten_registry_values_fall_back_to_defaults(monkeypatch):
    class Registry:                       # IDA's reg_read_string: "" when unset
        values = {"workers": "3"}

        @classmethod
        def reg_read_string(cls, name, subkey):
            return cls.values.get(name, "")

    monkeypatch.delenv("DEJADUMP_FILTER_TRACES", raising=False)
    monkeypatch.delenv("DEJADUMP_WORKERS", raising=False)
    monkeypatch.setattr(settings, "_registry", lambda: Registry)
    assert settings.get_bool("filter_traces") and settings.get_bool("highlight")
    assert settings.get("workers") == "3"


def test_writer_formatting_handles_dump_records():
    assert fmt.writer(None) == "dump"
    assert fmt.writer(0x1000) == "0x1000"
    assert fmt.size(512) == "512 B" and fmt.size(4096) == "4.0 KiB"


def test_comment_lines_from_the_old_plugin_name_are_still_owned():
    assert fmt.owned_line("[DejaDump] t2: wrote 4 byte(s) @ 0x1000")
    assert fmt.owned_line("[Palimpsest] volatile 0x1000–0x2000")   # pre-rename IDBs
    assert not fmt.owned_line("user note")
    assert ".pal.t1.0".startswith(fmt.SHADOW_PREFIXES)
