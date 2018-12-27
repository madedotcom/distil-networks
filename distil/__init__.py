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
    existing_names = {r.name: r.id for r in existing}
    existing = set(ids.keys())
    desired = set(desired)
    missing = desired - existing
    outdated = existing - desired

    updated = {rule for rule in missing if rule.name in existing_names}
    updated_names = [r.name for r in updated]

    update, create, delete = split_modifications(missing, outdated)

    return {
        "to_delete": [ids[r] for r in (delete) if r.name not in updated_names],
        "to_create": list(create),
        "to_update": {existing_names[r.name]: r
                      for r in update}
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
            print(json.dumps(body))
            kw["json"] = body

        resp = requests.request(method, API_ROOT + resource.format(*args),
                                **kw)
        print(resp.text)
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

    def modify_rules(self, acl_id, rules):
        if not rules:
            return
        modifications = []

        for id, rule in rules.items():
            data = rule._asdict()
            data["id"] = id
            modifications.append(data)

        return self.post_uri("access_control_lists/{0}/rules/batch_update",
                             {"rules": modifications}, acl_id)

    def delete_rules(self, acl_id, rules):
        if not rules:
            return

        return self._req_uri("DELETE",
                             "access_control_lists/{0}/rules/batch_destroy",
                             {"ids": rules}, acl_id)
