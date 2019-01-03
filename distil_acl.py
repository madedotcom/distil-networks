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

from ansible.module_utils.basic import AnsibleModule
from collections import namedtuple
import requests

API_ROOT = "https://api.distilnetworks.com/api/v1/"

AclRecord = namedtuple(
    '_acl_record',
    ["id", "name", "global_link", "global_access_control_list_id"])

AccessRule = namedtuple('_acl_rule', [
    "id", "access_control_list_id", "updated_at", "list", "type", "name",
    "value", "expires", "note", "global_link", "global_rule_id", "created_at"
])

RuleSpec = namedtuple('_acl_rule_spec',
                      ["type", "list", "name", "value", "expires", "note"])

RuleScope = namedtuple('_rule_scope', [
    'id', 'type', 'match', 'lua_pattern_enabled', 'domain',
    'access_control_list_ids'
])

ScopeSpec = namedtuple('_rule_scope_spec', ['domain', 'match'])


def matches(spec, scope):
    """
    Compare a ScopeSpec to a RuleScope to see if they match.
    """

    if spec.match == 'all':
        return (scope.match == 'default' and scope.type == 'default'
                and scope.domain == spec.domain)

    match_type, match = spec.match

    if match_type == 'path':
        return (scope.match == match and scope.type == 'path'
                and scope.lua_pattern_enabled == False)

    if match_type == 'pattern':
        return (scope.match == match and scope.type == 'path'
                and scope.lua_pattern_enabled == True)


class ScopeCollection(list):
    def find(self, spec):
        for scope in self:
            if matches(spec, scope):
                return scope

    def find_by_acl(self, acl_id):
        return [
            scope for scope in self if acl_id in scope.access_control_list_ids
        ]


class Client:
    def __init__(self, token, account=None):
        self.token = token
        self.account = account

    def _req_uri(self, method, resource, body, *args, **kwargs):
        if "auth_token" not in kwargs:
            kwargs["auth_token"] = self.token

        if self.account and not "account_id" in kwargs:
            kwargs["account_id"] = self.account
        kw = {"params": kwargs}

        if body:
            import json
            kw["json"] = body

        resp = requests.request(method, API_ROOT + resource.format(*args),
                                **kw)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            pass

    def _get_uri(self, resource, *args, **kwargs):
        return self._req_uri("GET", resource, None, *args, **kwargs)

    def _get_list(self, resource, *args, **kwargs):
        page = 1
        page_size = 30
        is_last_page = False
        result = []

        while not is_last_page:
            kwargs["page"] = page
            kwargs["page_size"] = page_size

            resp = self._get_uri(resource, *args, **kwargs)
            items = list(resp.items())
            assert len(items) in [1, 2]

            meta = None
            data = []

            for key, value in items:
                if key == "meta":
                    meta = value
                else:
                    data = value

            result.extend(data)

            if not meta:
                break

            returned_page = meta.get("page")
            total_pages = meta.get("total_pages")

            if not returned_page or total_pages == 0:
                break

            is_last_page = returned_page == total_pages
            page += 1

        return result

    def _post_uri(self, resource, body, *args, **kwargs):
        return self._req_uri("POST", resource, body, *args, **kwargs)

    def _delete_uri(self, resource, *args, **kwargs):
        return self._req_uri("DELETE", resource, None, *args, **kwargs)

    def get_acls(self, **kwargs):
        resp = self._get_list("access_control_lists", **kwargs)

        return [AclRecord(**json) for json in resp]

    def get_acl_by_name(self, name):
        return list(
            filter(lambda x: x.name == name, self.get_acls(search=name)))

    def get_rules(self, acl_id):
        resp = self._get_list("access_control_lists/{0}/rules", acl_id)

        return list(AccessRule(**json) for json in resp)

    def delete_acl(self, acl_id):
        resp = self._delete_uri("access_control_lists/{0}", acl_id)

    def create_acl(self, name):
        return self._post_uri("access_control_lists",
                              {"access_control_list": {
                                  "name": name
                              }})

    def create_rules(self, acl_id, rules):
        if not rules:
            return

        return self._post_uri("access_control_lists/{0}/rules/batch_create",
                              {"rules": [rule._asdict() for rule in rules]},
                              acl_id)

    def delete_rules(self, acl_id, rules):
        if not rules:
            return

        return self._req_uri("DELETE",
                             "access_control_lists/{0}/rules/batch_destroy",
                             {"ids": rules}, acl_id)

    def get_domains(self):
        resp = self._get_list("platform/domains")

        return {domain['name']: domain['id'] for domain in resp}

    def get_scopes(self):
        resp = self._get_list("rule_scopes")

        return ScopeCollection((RuleScope(
            id=scope['id'],
            type=scope['type'],
            match=scope['match'],
            lua_pattern_enabled=scope['lua_pattern_enabled'],
            domain=scope['domain'],
            access_control_list_ids=scope['access_control_list_ids'])
                                for scope in resp))

    def create_scope(self, spec, acl_id):
        domains = self.get_domains()

        if spec.domain not in domains:
            raise KeyError(
                "Unrecognised domain {}. Domains must be configured in the portal."
                % spec.domain)

        return self._post_uri(
            "rule_scopes", {
                "type": "default" if spec.match == "all" else "path",
                "match": "default" if spec.match == "all" else spec.match[1],
                "lua_pattern_enabled": spec.match[0] == "pattern",
                "access_control_list_id": acl_id
            },
            domain_id=domains[spec.domain])

    def disassociate_acl_from_scopes(self, acl_id, scope_ids):
        if not scope_ids:
            return
        self._req_uri("DELETE",
                      "access_control_lists/{0}/rule_scopes/batch_destroy", {
                          "ids": scope_ids,
                      }, acl_id)

    def associate_acl_to_scopes(self, acl_id, scope_ids):
        if not scope_ids:
            return
        self._post_uri("access_control_lists/{0}/rule_scopes/batch_create",
                       {"ids": scope_ids}, acl_id)

    def delete_scope(self, scope_id):
        self._delete_uri("rule_scopes/{0}", scope_id)


def extract_spec(rule):
    """
    Extracts a RuleSpec from an AccessRule
    """
    return RuleSpec(rule.type, rule.list, rule.name, rule.value,
                           rule.expires, rule.note)


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
    client = Client(module.params["token"])
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
    client = Client(module.params["token"], module.params["account"])
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
            RuleSpec(
                type=rule.get("type"),
                list="blacklist" if
                (rule.get("deny") == True) else "whitelist",
                name=rule.get("name"),
                value=rule.get("value"),
                expires=rule.get("expires"),
                note=rule.get("description") or ""))

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
            parsed.append(ScopeSpec(scope["domain"], match))

    return parsed


def apply_scope_changes(module, acl_id, result):
    client = Client(module.params["token"], module.params["account"])
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
    if changes["to_create"] or changes["to_destroy"] or changes[
            "add_to"] or changes["remove_from"]:
        result["changed"] = True


def apply_rule_changes(module, acl_id, result):
    """
    Given an AclRecord, fetch the set of rule changes that need to be made.
    """
    client = Client(module.params["token"], module.params["account"])
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
    client = Client(module.params["token"])
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
