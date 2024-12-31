import requests

from urllib.parse import quote_plus

AUTO_ACCEPT = "false"

BOB = "http://bob:3001"


def get(agent: str, path: str, **kwargs):
    """Get."""
    return requests.get(f"{agent}{path}", **kwargs)


def post(agent: str, path: str, **kwargs):
    """Post."""
    return requests.post(f"{agent}{path}", **kwargs)


class Agent:
    """Class for interacting with Agent over Admin API"""

    def __init__(self, url: str):
        self.url = url

    def register_did(self, json, **kwargs):
        """Register did."""
        return post(
            self.url, "/hedera/did/register", params=kwargs, json=json
        )

    def resolve_did(self, did):
        """Resolve did."""
        return get(self.url, f"/resolver/resolve/{did}")

    def get_schema(self, schema_id):
        """Get schema."""
        encoded_schema_id = quote_plus(schema_id)
        return get(self.url, f"/anoncreds/schema/{encoded_schema_id}")

    def register_schema(self, json):
        """Register schema."""
        return post(self.url, "/anoncreds/schema", json=json)

    def get_credential_definition(self, credential_definition_id):
        """Get credential definition."""
        encoded_credential_definition_id = quote_plus(credential_definition_id)
        return get(self.url, f"/anoncreds/credential-definition/{encoded_credential_definition_id}")

    def get_revocation_registry_definition(self, revocation_registry_definition_id):
        """Get revocation registry definition."""
        return get(self.url, f"/anoncreds/revocation/active-registry/{revocation_registry_definition_id}")

    def register_credential_definition(self, json):
        """Register credential definition."""
        return post(self.url, "/anoncreds/credential-definition", json=json)
