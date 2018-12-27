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

author:
    - Bob Gregory (bob@made.com)
'''

EXAMPLES = '''
# Create an ACL with a single ip rule
- name: Allow office ip
  distil_acl:
    name: Allow office IP
    token: abc-123
    account: abc-123
    rules:
        - type: ip
          name: office
          value: 172.31.0.1

# Create a temporary exemption for an IP range
- distil_acl:
      token: abc-123
      account: abc-123
      name: Allow temporary access for $PARTNER
      expires: "2019-02-01"
      description: "Need to have access for the next couple of weeks so they can ransack our data and break our website."
      rules:
          - type: ip
            name: $PARTNER
            value: 172.17.0.0/24

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

def remove_acl(module):
    client = distil.Client(module.params["token"])
    acl = client.get_acl_by_name(module.params["name"])

    if acl:
        [acl] = acl
        client.delete_acl(acl.id)
        module.exit_json(changed=True, changes={
            "deleted": acl
        })
    else:
        module.exit_json(changed=False)

def create_acl(module):
    client = distil.Client(module.params["token"], module.params["account"])
    acl = client.create_acl(module.params["name"])
    module.exit_json(changed=True, changes={
        "created": acl
    })

def parse_rules(module):
    raw = module.params["rules"] or []
    parsed = []

    for rule in raw:
        parsed.append(distil.RuleSpec(
            type=rule.get("type"),
            list="blacklist" if (rule.get("deny") == True) else "whitelist",
            name=rule.get("name"),
            value=rule.get("value"),
            expires=rule.get("expires"),
            note=rule.get("description")))

    return parsed



def get_changes(module, acl):
    client = distil.Client(module.params["token"], module.params["account"])
    existing = client.get_rules(acl.id)
    desired = parse_rules(module)

    return distil.identify_rule_changes(existing, desired)


def modify_acl(module):
    client = distil.Client(module.params["token"], module.params["account"])
    acl = client.get_acl_by_name(module.params["name"])[0]

    changes = get_changes(module, acl)
    if not (changes["to_delete"] or changes["to_create"] or changes["to_update"]):
        module.exit_json(changed=False)
    client.create_rules(acl.id, changes["to_create"])
    client.modify_rules(acl.id, changes["to_update"])
    client.delete_rules(acl.id, changes["to_delete"])
    module.exit_json(changed=True, changes=changes)

def main():
    argument_spec = dict(
        name=dict(required=True, type='str'),
        account=dict(),
        token=dict(required=True, type='str'),
        rules=dict(type='list'),
        state=dict(default='present', type='str', choices=['present', 'absent']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    if module.params["state"] == 'absent':
        return remove_acl(module)

    client = distil.Client(module.params["token"])
    acl = client.get_acl_by_name(module.params["name"])
    if acl:
        return modify_acl(module)

    return create_acl(module)

if __name__ == '__main__':
    main()
