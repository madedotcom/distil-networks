# Ansible Distil ACLs

This is a simple module to manage Access Control Lists in the [Distil Networks](https://distilnetworks.com) bot mitigation service.

```yaml
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
```
