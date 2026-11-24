"""The user guide documents every registered action (label and hotkey), so the
menu and the documentation cannot drift apart."""

import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _specs():
    tree = ast.parse(open(os.path.join(ROOT, "dejadump_plugin.py"), encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "SPECS" for t in node.targets):
            for row in node.value.elts:
                yield (row.elts[0].value, row.elts[2].value, row.elts[4].value)
            return
    raise AssertionError("SPECS not found in dejadump_plugin.py")


def test_user_guide_documents_every_action_and_hotkey():
    guide = open(os.path.join(ROOT, "docs", "USER_GUIDE.md"), encoding="utf-8").read()
    specs = list(_specs())
    assert len(specs) > 30
    missing = [label for _aid, label, _hk in specs if label not in guide]
    assert not missing, "undocumented actions: %s" % missing
    hotkeys = [hk for _aid, _label, hk in specs if hk and "`%s`" % hk not in guide]
    assert not hotkeys, "undocumented hotkeys: %s" % hotkeys


def test_documented_tools_exist():
    for doc in ("USER_GUIDE.md", "DEMO.md"):
        text = open(os.path.join(ROOT, "docs", doc), encoding="utf-8").read()
        for token in text.split():
            token = token.strip("`(),.;:")
            if token.startswith("tools/") and token.endswith(".py"):
                assert os.path.exists(os.path.join(ROOT, token)), "%s references %s" % (doc, token)
