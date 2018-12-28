#!/usr/bin/python

DOCUMENTATION = '''
---
module: distil_acl

short_description: Manages access-control lists for Distil Networks

options:
    token:
        description:
            - API token for Distil API
        required: true
    account:
        description:
            - UUID account id, required when creating ACLs.
    name:
        description:
            - Name of the ACL
        required: true
    state:
        description:
            - Create or delete an ACL
        required: false
        default: 'present'
        choices: [ "present", "absent" ]
    rules:
        description:
            - List of rules to enforce with this ACL (see example).
            - If no rules are provided, we'll create an empty ACL.
    scope:
        description:
            - List of scopes where this ACL applies (see examples).
            - ACLs aren't enforced unless applied to at least one scope.

author:
    - Bob Gregory (bob@made.com)
'''

EXAMPLES = '''
# Create an ACL with a single ip rule
- name: Allow office ip to all paths
  distil_acl:
    name: Allow office IP
    token: abc-123
    account: abc-123
    rules:
        - type: ip
          description: office
          value: 172.31.0.1
    scope:
        # By default scopes apply to an entire domain
        - domain: example.com

# Create a temporary exemption for an IP range to hit a path
- distil_acl:
      token: abc-123
      account: abc-123
      name: Allow temporary access for $PARTNER
      expires: "2019-02-01"
      description: "Need to have access for the next couple of weeks so they can ransack our data and break our website."
      rules:
          - type: ip
            description: $PARTNER
            value: 172.17.0.0/24
      scope:
          - domain: example.org
            # Scopes can be limited to a path. This scope matches any path
            # containing the substring "api"
            path: api

# Whitelist all traffic from an IP range matching a path pattern
- distil_acl:
      token: abc-123
      account: abc-123
      name: Allow temporary access for $PARTNER
      expires: "2019-02-01"
      description: "Need to have access for the next couple of weeks so they can ransack our data and break our website."
      rules:
          - type: ip
            description: $PARTNER
            value: 172.17.0.0/24
      scope:
          - domain: example.org
            # Scopes can use a lua pattern instead of a contains match.
            pattern: "^/api/"

# Delete an ACL
- name: Remove old office
    token: abc-123
    account: abc-123
    name: Allow office IP
    state: absent

# Whitelist a header value
- distil_acl:
    token: abc-123
    account: abc-123
    name: Whitelist developers
    description: "Allow developers to access the site by passing magic header"
    rules:
        - type: header
          name: x-magic
          value: 1
    scope:
        - domain: example.com
        - domain: example.org

# Blacklist a user agent
- distil_acl:
    token: abc-123
    account: abc-123
    name: Blacklist FROOTPOT
    blacklist: yes
    description: Crazy frootpot people keep DOSing the website
    rules:
        - type: user_agent
          value: FROOTPOT
        - type: ip
          value: 172.17.0.128/30
'''

import distil
from ansible.module_utils.basic import AnsibleModule


def extract_spec(rule):
    """
    Extracts a RuleSpec from an AccessRule
    """
    return distil.RuleSpec(rule.type, rule.list, rule.name, rule.value, rule.expires,
                    rule.note)


def identify_rule_changes(existing, desired):
    """
    Given a set of existing AccessRules and a set of desired RuleSpecs
    work out what changes we need to make to an acl.
    """
    ids = {extract_spec(r): r.id for r in existing}
    existing = set(ids.keys())
    desired = set(desired)

    missing = desired - existing
    outdated = existing - desired

    return {
        "to_delete": [ids[r] for r in outdated],
        "to_create": list(missing),
    }


def identify_scope_changes(existing, desired, acl_id):
    """
    Given a ScopeCollection of all the rule scopes active on an account, plus
    a desired list of ScopeSpecs, calculate the changes we need to make.
    """
    create_scope = []
    add_rule = []
    remove_rule = []
    destroy_scope = []

    # Start off by assuming that all of the existing rules for this ACL
    # are no longer needed. If we find them in the desired specs, we'll
    # remove them from this list.
    orphaned_scopes = existing.find_by_acl(acl_id)

    for spec in desired:
        scope = existing.find(spec)

        if not scope:
            create_scope.append(spec)

            continue

        if acl_id in scope.access_control_list_ids:
            orphaned_scopes.remove(scope)

            continue

        add_rule.append(scope.id)

    # What's remaining in orphans is now unused associations.
    # IF the scope has several rules attached, we need to keep it
    # but if this is the only rule attached, we can delete the scope
    # UNLESS it's the magic 'all paths' scope.

    for scope in orphaned_scopes:
        if len(scope.access_control_list_ids) > 1:
            remove_rule.append(scope.id)
        elif scope.type == 'default':
            remove_rule.append(scope.id)
        else:
            destroy_scope.append(scope.id)

    return {
        'to_create': create_scope,
        'to_destroy': destroy_scope,
        'add_to': add_rule,
        'remove_from': remove_rule
    }


def remove_acl(module):
    """
    Delete an ACL from the API.
    """
    client = distil.Client(module.params["token"])
    acl = client.get_acl_by_name(module.params["name"])

    if acl:
        [acl] = acl
        client.delete_acl(acl.id)
        module.exit_json(changed=True, changes={"deleted": acl})
    else:
        module.exit_json(changed=False)


def create_acl(module, result):
    """
    Create a new ACL
    """
    client = distil.Client(module.params["token"], module.params["account"])
    acl = client.create_acl(module.params["name"])
    acl_id = acl["access_control_list"]["id"]
    result['created_acl'] = acl_id


def parse_rules(module):
    """
    Convert from the published yaml format into a list of RuleSpec instances.
    """
    raw = module.params["rules"] or []
    parsed = []

    for rule in raw:
        parsed.append(
            distil.RuleSpec(
                type=rule.get("type"),
                list="blacklist" if
                (rule.get("deny") == True) else "whitelist",
                name=rule.get("name"),
                value=rule.get("value"),
                expires=rule.get("expires"),
                note=rule.get("description")))

    return parsed


def parse_scopes(module):
    raw = module.params["scope"] or []
    parsed = []
    for scope in raw:
        match = "all"
        if "domain" not in scope:
            module.fail_json(msg="No domain found for scope")
        else:
            if "pattern" in scope:
                match = ("pattern", scope["pattern"])
            elif "path" in scope:
                match = ("path", scope["path"])
            parsed.append(distil.ScopeSpec(scope["domain"], match))

    return parsed


def apply_scope_changes(module, acl_id, result):
    client = distil.Client(module.params["token"], module.params["account"])
    existing = client.get_scopes()
    desired = parse_scopes(module)

    changes = identify_scope_changes(existing, desired, acl_id)

    for scope in changes["to_create"]:
        client.create_scope(scope, acl_id)

    client.associate_acl_to_scopes(acl_id, changes["add_to"])
    client.disassociate_acl_from_scopes(acl_id, changes["remove_from"])

    for scope in changes["to_destroy"]:
        client.delete_scope(scope)

    result["scope_changes"] = changes
    if changes["to_create"] or changes["to_destroy"] or changes["add_to"] or changes["remove_from"]:
        result["changed"] = True


def apply_rule_changes(module, acl_id, result):
    """
    Given an AclRecord, fetch the set of rule changes that need to be made.
    """
    client = distil.Client(module.params["token"], module.params["account"])
    existing = client.get_rules(acl_id)
    desired = parse_rules(module)

    changes = identify_rule_changes(existing, desired)
    client.delete_rules(acl_id, changes["to_delete"])
    client.create_rules(acl_id, changes["to_create"])
    result["rule_changes"] = changes

    if changes["to_delete"] or changes["to_create"]:
        result["changed"] = True


def main():
    argument_spec = dict(
        name=dict(required=True, type='str'),
        account=dict(),
        token=dict(required=True, type='str'),
        rules=dict(type='list'),
        scope=dict(type='list'),
        state=dict(
            default='present', type='str', choices=['present', 'absent']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True)

    if module.params["state"] == 'absent':
        return remove_acl(module)

    result = dict()
    client = distil.Client(module.params["token"])
    acl = client.get_acl_by_name(module.params["name"])
    if acl:
        acl_id = acl[0].id
    else:
        create_acl(module, result)
        acl_id = result['created_acl']

    apply_rule_changes(module, acl_id, result)
    apply_scope_changes(module, acl_id, result)

    module.exit_json(changed=("changed" in result), changes=result)


if __name__ == '__main__':
    main()
