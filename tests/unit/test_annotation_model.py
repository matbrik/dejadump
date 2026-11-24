"""Annotation deltas: what an epoch switch removes and re-applies (no IDA needed)."""

from dejadump.core.annotation_model import empty_payload, plan_delta, replace_window


def _payload(**kinds):
    p = empty_payload()
    p.update(kinds)
    return p


def test_visited_target_removes_outgoing_only_entries():
    out = _payload(names=[{"off": 0, "name": "stub_v1", "flags": 0}],
                   cmts=[{"off": 4, "rpt": False, "text": "keep"}])
    tgt = _payload(cmts=[{"off": 4, "rpt": False, "text": "keep"}])
    remove, apply = plan_delta(out, tgt)
    assert remove["names"] == out["names"]          # the t1 name must not leak into t3
    assert remove["cmts"] == [] and apply["cmts"] == []


def test_changed_spans_force_reapply_of_identical_entries():
    entry = {"off": 8, "rpt": False, "text": "same"}
    out, tgt = _payload(cmts=[entry]), _payload(cmts=[entry])
    _remove, apply = plan_delta(out, tgt, changed=lambda off: off == 8)
    assert apply["cmts"] == [entry]


def test_first_visit_carries_unchanged_and_clears_changed():
    out = _payload(names=[{"off": 0, "name": "a"}, {"off": 0x40, "name": "b"}])
    remove, apply = plan_delta(out, None, changed=lambda off: off < 0x10)
    assert remove["names"] == [{"off": 0, "name": "a"}]
    assert all(not entries for entries in apply.values())


def test_functions_are_never_removed():
    out = _payload(funcs=[{"off": 0, "end": 8}])
    remove, apply = plan_delta(out, _payload(), changed=lambda off: True)
    assert remove["funcs"] == [] and apply["funcs"] == []
    remove, apply = plan_delta(_payload(), _payload(funcs=[{"off": 0, "end": 8}]))
    assert apply["funcs"] == [{"off": 0, "end": 8}]


def test_keys_distinguish_repeatable_and_extra_lines():
    out = _payload(cmts=[{"off": 0, "rpt": True, "text": "r"}],
                   extra=[{"off": 0, "where": 1000, "text": "x"}])
    tgt = _payload(cmts=[{"off": 0, "rpt": False, "text": "r"}],
                   extra=[{"off": 0, "where": 1001, "text": "x"}])
    remove, apply = plan_delta(out, tgt)
    assert len(remove["cmts"]) == 1 and len(apply["cmts"]) == 1
    assert len(remove["extra"]) == 1 and len(apply["extra"]) == 1


def test_replace_window_merges_a_recaptured_window():
    stored = _payload(names=[{"off": 0, "name": "a"}, {"off": 0x1000, "name": "b"}],
                      hexrays=[{"func_off": 0x1000, "lvars": []}])
    window = _payload(names=[{"off": 0x1004, "name": "c"}])
    merged = replace_window(stored, 0x1000, 0x2000, window)
    assert merged["names"] == [{"off": 0, "name": "a"}, {"off": 0x1004, "name": "c"}]
    assert merged["hexrays"] == []


def test_merge_payloads_keeps_base_entries_the_overlay_lacks():
    from dejadump.core.annotation_model import merge_payloads

    base = _payload(names=[{"off": 0, "name": "kept"}, {"off": 4, "name": "old"}])
    overlay = _payload(names=[{"off": 4, "name": "new"}], cmts=[{"off": 8, "rpt": False,
                                                                 "text": "c"}])
    merged = merge_payloads(base, overlay)
    assert sorted(n["name"] for n in merged["names"]) == ["kept", "new"]
    assert merged["cmts"] == overlay["cmts"]
