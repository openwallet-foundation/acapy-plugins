from time import sleep
import logging
from pprint import PrettyPrinter
from time import time
from typing import Literal
from urllib.parse import quote_plus

import requests

HOLDER_ENDPOINT = "http://holder:3001"
ISSUER_ENDPOINT = "http://issuer:3001"

pp = PrettyPrinter(indent=2, sort_dicts=False)

LOGGER = logging.getLogger(__name__)


def _format(obj):
    pretty_out = f"{pp.pformat(obj)}"

    return f"{pretty_out}\n"


class Agent:
    """Class for interacting with Agent over Admin API."""

    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url
        self.token: str | None = None

        # Don't proceed if unable to communicate with agent
        conn_tries_left = 5
        while conn_tries_left > 0:
            try:
                resp = requests.get(
                    f"{self.base_url}/status/live",
                )

                print(resp.json())

                break
            except requests.ConnectionError:
                sleep(5)
                conn_tries_left -= 1

        if conn_tries_left == 0:
            raise Exception("Could not connect to agent")

    def _log_request(self, destination_url, method, path, response, **kwargs):
        obj = {
            "origin_agent": self.name,
            "origin_agent_url": self.base_url,
            "destination_agent_url": destination_url,
            "method": method,
            "path": path,
            "kwargs": kwargs,
            "response_code": response.status_code,
        }

        try:
            obj["response_json"] = response.json()
        except Exception:
            obj["response_content"] = response.content

        LOGGER.info(_format(obj))

    def _validate_wallet_created(self):
        if not self.token:
            raise Exception("Requires call to create_wallet with token persisted")

    def _auth_get(self, path: str, **kwargs):
        """Get."""
        self._validate_wallet_created()

        kwargs["headers"] = {"Authorization": f"Bearer {self.token}"}

        response = requests.get(f"{self.base_url}/{path}", **kwargs)

        if response.status_code != 200:
            raise Exception("Failed! Bad status code")

        self._log_request(
            destination_url=self.base_url, method="get", path=path, response=response
        )

        return response.json()

    def _auth_post(self, path: str, **kwargs):
        """Post."""
        self._validate_wallet_created()

        kwargs["headers"] = {"Authorization": f"Bearer {self.token}"}

        response = requests.post(f"{self.base_url}{path}", **kwargs)

        if response.status_code != 200:
            raise Exception("Failed! Bad status code")

        self._log_request(
            destination_url=self.base_url,
            method="post",
            path=path,
            response=response,
            **kwargs,
        )

        return response.json()

    def create_wallet(self, *, persist_token=False):
        """Create wallet."""
        path = "/multitenancy/wallet"

        response = requests.post(
            f"{self.base_url}/{path}",
            json={
                "extra_settings": {},
                "image_url": "https://aries.ca/images/sample.png",
                "key_management_mode": "managed",
                "label": self.name,
                "wallet_dispatch_type": "default",
                "wallet_key": f"testwalletkey{self.name}{time()}",
                "wallet_name": f"testwalletname{self.name}{time()}",
                "wallet_type": "askar-anoncreds",
                "wallet_webhook_urls": [],
            },
        )

        response_body = response.json()

        if persist_token:
            self.token = response_body.get("token")

        self._log_request(
            destination_url=self.base_url,
            method="post",
            path=path,
            response=response,
        )

        return response

    def create_invitation(self, alias, goal, label):
        """Create out of band invitation."""
        return self._auth_post(
            "/out-of-band/create-invitation",
            json={
                "accept": ["didcomm/aip1", "didcomm/aip2;env=rfc19"],
                "alias": alias,
                "attachments": [],
                "goal": goal,
                "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
                "metadata": {},
                "my_label": label,
                "protocol_version": "1.1",
                "use_did_method": "did:peer:2",
                "use_public_did": False,
            },
            params={
                # Boolean querystring params in requests library
                # need to be passed as string
                "auto_accept": "true"
            },
        )

    def receive_invitation(self, invitation: dict):
        """Receive out of band invitation."""
        return self._auth_post("/out-of-band/receive-invitation", json=invitation)

    def list_connections(self):
        """List agent connections."""
        return self._auth_get("/connections")

    def register_did(self, key_type: Literal["Ed25519"]):
        """Register did."""
        return self._auth_post("/hedera/did/register", json={"key_type": key_type})

    def register_schema(self, name, version, issuer_id, attribute_names):
        """Register schema."""
        return self._auth_post(
            "/anoncreds/schema",
            json={
                "options": {},
                "schema": {
                    "attrNames": attribute_names,
                    "issuerId": issuer_id,
                    "name": name,
                    "version": version,
                },
            },
        )

    def register_credential_definition(self, schema_id, issuer_id, tag):
        """Register credential definition."""
        return self._auth_post(
            "/anoncreds/credential-definition",
            json={
                "credential_definition": {
                    "issuerId": issuer_id,
                    "schemaId": schema_id,
                    "tag": tag,
                },
                "options": {"revocation_registry_size": 1000, "support_revocation": True},
            },
        )

    def get_active_revocation_registry(
        self,
        credential_definition_id,
    ):
        """Get active revocation registry."""
        encoded_credential_definition_id = quote_plus(credential_definition_id)

        return self._auth_get(
            f"anoncreds/revocation/active-registry/{encoded_credential_definition_id}"
        )

    def issue_credential(
        self, connection_id, cred_def_id, issuer_id, schema_id, attributes, comment
    ):
        """Issue a credential."""
        return self._auth_post(
            "/issue-credential-2.0/send",
            json={
                "auto_remove": True,
                "comment": comment,
                "connection_id": connection_id,
                "credential_preview": {
                    "@type": "issue-credential/2.0/credential-preview",
                    "attributes": attributes,
                },
                "filter": {
                    "anoncreds": {
                        "cred_def_id": cred_def_id,
                        "issuer_id": issuer_id,
                        "schema_id": schema_id,
                    }
                },
            },
        )

    def get_issue_records(self):
        """Get records."""
        return self._auth_get("issue-credential-2.0/records")

    def accept_credential_offer(self, cred_ex_id, holder_did=None):
        """Accept credential offer."""
        return self._auth_post(
            f"/issue-credential-2.0/records/{cred_ex_id}/send-request",
            json={
                "auto_remove": False,
                "holder_did": holder_did,  # Only used as entropy value
            },
        )

    def store_credential(self, cred_ex_id, credential_id):
        """Accept credential offer."""

        return self._auth_post(
            f"/issue-credential-2.0/records/{cred_ex_id}/store",
            json={"credential_id": credential_id},
        )

    def send_presentation_proof_request(
        self,
        connection_id,
        cred_def_id,
        attributes,
        version,
        comment,
        *,
        non_revoked=None,
    ):
        """Send presentation proof."""
        requested_attributes = {
            key: {"name": key, "restrictions": [{"cred_def_id": cred_def_id}]}
            for key in attributes
        }

        obj = {
            "auto_remove": False,
            "auto_verify": True,
            "comment": comment,
            "connection_id": connection_id,
            "presentation_request": {
                "anoncreds": {
                    "name": "Proof request",
                    "requested_attributes": requested_attributes,
                    "requested_predicates": {},
                    "version": version,
                    "non_revoked": non_revoked if non_revoked else None,
                }
            },
            "trace": False,
        }

        return self._auth_post("/present-proof-2.0/send-request", json=obj)

    def get_presentation_proof_records(self, state=None):
        """Get presentation proof records."""

        params = {"state": state} if state else {}

        return self._auth_get("/present-proof-2.0/records", params=params)

    def accept_proof_request(self, pres_ex_id, cred_id, attributes):
        """Accept proof request."""

        attributes_obj = {
            attribute: {"cred_id": cred_id, "revealed": True} for attribute in attributes
        }

        return self._auth_post(
            f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
            json={
                "anoncreds": {
                    "requested_attributes": attributes_obj,
                    "requested_predicates": {},
                    "self_attested_attributes": {},
                    "trace": False,
                },
                "auto_remove": False,
                "trace": True,
            },
        )

    def revoke_credential(self, cred_ex_id, comment):
        """Revoke credential."""

        return self._auth_post(
            "/anoncreds/revocation/revoke",
            json={
                "cred_ex_id": cred_ex_id,
                "comment": comment,
                "notify": False,
                "notify_version": "v1_0",
                "publish": True,
                "thread_id": "1234",
            },
        )

    def get_wallet_did(self, method: Literal["hedera"], did: str):
        """Get did from local wallet."""
        return self._auth_get("/wallet/did", params={"method": method, "did": did})

    def resolve_did(self, did):
        """Resolve did."""
        return self._auth_get(f"/resolver/resolve/{did}")

    def get_schema(self, schema_id):
        """Get schema."""
        encoded_schema_id = quote_plus(schema_id)
        return self._auth_get(f"/anoncreds/schema/{encoded_schema_id}")

    def get_credential_definition(self, credential_definition_id):
        """Get credential definition."""
        # Encode needed because credential definition id includes slash characters
        encoded_credential_definition_id = quote_plus(credential_definition_id)

        return self._auth_get(
            f"/anoncreds/credential-definition/{encoded_credential_definition_id}"
        )

    def get_credential(self, credential_id):
        """Get credential."""
        return self._auth_get(f"/credential/{credential_id}")

    def send_message(self, connection_id, message):
        """Send message."""
        return self._auth_post(
            f"/connections/{connection_id}/send-message", json={"content": message}
        )
