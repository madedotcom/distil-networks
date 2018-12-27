from distil import *

PERMIT_OFFICE = RuleSpec("ip", "whitelist", "office ip", "172.31.0.1", None)
PERMIT_DEBUG = RuleSpec("header", "whitelist", "x-debug", "1", None)

DENY_DEBUG = RuleSpec("header", "blacklist", "x-debug", "1", None)

def as_rule(rule_id, spec):
    return AccessRule(rule_id, rule_id, "tomorrow", spec.list, spec.type, spec.name, spec.value, spec.expires, "", False, None, "yesterday")


def test_new_rules():
    existing = []
    desired = [PERMIT_OFFICE, PERMIT_DEBUG]

    changes = identify_rule_changes(existing, desired)

    assert not changes["to_delete"]
    assert not changes["to_update"]
    assert changes["to_create"] == desired


def test_delete_old_rules():
    existing = [as_rule("aa", PERMIT_OFFICE), as_rule("bb", PERMIT_DEBUG)]
    desired = []

    changes = identify_rule_changes(existing, desired)

    assert changes["to_delete"] == ["aa", "bb"]
    assert not changes["to_create"]
    assert not changes["to_update"]


def test_rules_matching():
    existing = [as_rule("aa", PERMIT_OFFICE), as_rule("bb", PERMIT_DEBUG)]
    desired = [PERMIT_OFFICE, PERMIT_DEBUG]

    changes = identify_rule_changes(existing, desired)

    assert not changes["to_create"]
    assert not changes["to_delete"]
    assert not changes["to_update"]


def test_rules_change_list():
    existing = [as_rule("id-1", PERMIT_DEBUG)]
    desired = [DENY_DEBUG]

    changes = identify_rule_changes(existing, desired)

    assert changes["to_delete"] == []
    assert changes["to_create"] == []
    assert changes["to_update"] == {
            "id-1": DENY_DEBUG
    }
