from collections import namedtuple
import requests

API_ROOT = "https://api.distilnetworks.com/api/v1/"

AclRecord = namedtuple('_acl_record', [
    "id",
    "name",
    "global_link",
    "global_access_control_list_id"
])

class Client:

    def __init__(self, token):
        self.token = token

    def _get_uri(self, resource, **kwargs):
        if "auth_token" not in kwargs:
            kwargs["auth_token"] = self.token
        return requests.get(API_ROOT + resource, params=kwargs)

    def get_acls(self, **kwargs):
        resp = self._get_uri("access_control_lists", **kwargs)
        resp.raise_for_status()
        return [AclRecord(**json) for json in resp.json()['access_control_lists']]

    def get_acl_by_name(self, name):
        return list(filter(lambda x: x.name == name, self.get_acls(search=name)))
