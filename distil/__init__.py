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


def extract_spec(rule):
    return RuleSpec(rule.type, rule.list, rule.name, rule.value, rule.expires,
                    rule.note)


def split_modifications(missing, outdated):

    names = [rule.name for rule in outdated]

    updated = {rule for rule in missing if rule.name in names}

    for rule in missing:
        if rule.name in names:
            updated.add(rule)

    return updated, missing - updated, outdated - updated


def identify_rule_changes(existing, desired):
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

    def _post_uri(self, resource, body, *args, **kwargs):
        return self._req_uri("POST", resource, body, *args, **kwargs)

    def _delete_uri(self, resource, *args, **kwargs):
        return self._req_uri("DELETE", resource, None, *args, **kwargs)

    def get_acls(self, **kwargs):
        resp = self._get_uri("access_control_lists", **kwargs)

        return [AclRecord(**json) for json in resp['access_control_lists']]

    def get_acl_by_name(self, name):
        return list(
            filter(lambda x: x.name == name, self.get_acls(search=name)))

    def get_rules(self, acl_id):
        resp = self._get_uri("access_control_lists/{0}/rules", acl_id)

        return list(AccessRule(**json) for json in resp['rules'])

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
        resp = self._get_uri("platform/domains")

        return {domain['name']: domain['id'] for domain in resp['domains']}

    def get_scopes(self):
        resp = self._get_uri("rule_scopes")

        return ScopeCollection((RuleScope(
            id=scope['id'],
            type=scope['type'],
            match=scope['match'],
            lua_pattern_enabled=scope['lua_pattern_enabled'],
            domain=scope['domain'],
            access_control_list_ids=scope['access_control_list_ids'])
                                for scope in resp['rule_scopes']))

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
        self._req_uri("DELETE", "access_control_lists/{0}/rule_scopes/batch_destroy", {
            "ids": scope_ids,
        }, acl_id)

    def associate_acl_to_scopes(self, acl_id, scope_ids):
        if not scope_ids:
            return
        self._post_uri("access_control_lists/{0}/rule_scopes/batch_create",
                       {"ids": scope_ids}, acl_id)

    def delete_scope(self, scope_id):
        self._delete_uri("rule_scopes/{0}", scope_id)
