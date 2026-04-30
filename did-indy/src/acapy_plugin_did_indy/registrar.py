"""did:indy registrar."""

import json
import logging
from typing import List

import base58
from acapy_agent.core.error import BaseError
from acapy_agent.core.profile import Profile
from acapy_agent.ledger.base import BaseLedger
from acapy_agent.protocols.coordinate_mediation.v1_0.models.mediation_record import (
    MediationRecord,
)
from acapy_agent.protocols.coordinate_mediation.v1_0.route_manager import (
    RouteManager,
)
from acapy_agent.utils.multiformats import multibase, multicodec
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519
from did_indy.author.author import Author
from did_indy.did import nym_from_verkey
from indy_vdr import ledger
from pydid.verification_method import Ed25519VerificationKey2020

from .author import AcapyAuthorDeps
from .did import INDY

LOGGER = logging.getLogger(__name__)


class IndyRegistrarError(BaseError):
    """Raised on errors in registrar."""


class IndyRegistrar:
    """did:indy registrar."""

    def __init__(
        self,
    ):
        """Initialize the registrar."""
        LOGGER.info("DID:Indy Initializing did:indy registrar")

    async def prepare_didcomm_services(
        self, profile: Profile, mediation_records: List[MediationRecord] | None = None
    ):
        LOGGER.info("DID:Indy Preparing didcomm services")
        """Prepare didcomm service for adding to diddocContent."""
        svc_endpoints = []
        default_endpoint = profile.settings.get("default_endpoint")
        if default_endpoint:
            svc_endpoints.append(default_endpoint)
        svc_endpoints.extend(profile.settings.get("additional_endpoints", []))

        route_manager = profile.inject(RouteManager)
        routing_keys: List[str] = []
        if mediation_records:
            for mediation_record in mediation_records:
                (
                    mediator_routing_keys,
                    endpoint,
                ) = await route_manager.routing_info(profile, mediation_record)
                routing_keys = [*routing_keys, *(mediator_routing_keys or [])]
                if endpoint:
                    svc_endpoints = [endpoint]

        services = []
        for index, endpoint in enumerate(svc_endpoints or []):
            services.append(
                {
                    "id": f"#didcomm-{index}",
                    "type": "did-communication",
                    "recipientKeys": ["#key-0"],
                    "routingKeys": routing_keys,
                    "serviceEndpoint": endpoint,
                    "priority": index,
                }
            )
        return services

    async def create_new_nym(
        self,
        profile: Profile,
        namespace: str,
        *,
        didcomm: bool = True,
        ldp_vc: bool = False,
        mediation_records: List[MediationRecord] | None = None,
    ) -> DIDInfo:
        LOGGER.info("DID:Indy Creating did:indy from public nym")
        """Create a new did:indy and publish it to the ledger."""
        if mediation_records and not didcomm:
            raise ValueError("Mediation records passed but didcomm flag not set")

        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            key = await wallet.create_key(key_type=ED25519)
            nym = nym_from_verkey(key.verkey, version=2)
            did = f"did:indy:{namespace}:{nym}"
            await wallet.assign_kid_to_key(key.verkey, did + "#verkey")

            # Enable ldp-vc issuance?
            verkey = key.verkey
            if ldp_vc:
                kid = f"{did}#assert"
                assertion_method = await wallet.create_key(key_type=ED25519, kid=kid)
                public_key_multibase = multibase.encode(
                    multicodec.wrap(
                        "ed25519-pub", base58.b58decode(assertion_method.verkey)
                    ),
                    "base58btc",
                )
                # verkey = key.verkey
                vm = Ed25519VerificationKey2020.make(
                    id=kid, controller=did, public_key_multibase=public_key_multibase
                )
                doc_content = {
                    "@context": ["https://w3id.org/security/suites/ed25519-2020/v1"],
                    "verificationMethod": [vm.serialize()],
                    "assertionMethod": [vm.id],
                }
            else:
                doc_content = {}

            if didcomm:
                services = await self.prepare_didcomm_services(
                    profile, mediation_records
                )
                doc_content["service"] = services

            author = session.inject(Author)
            deps = session.inject(AcapyAuthorDeps)
            ledger_response = await author.client.create_nym(
                namespace=namespace,
                verkey=verkey,
                nym=nym,
                diddoc_content=json.dumps(doc_content),
                taa=await deps.get_taa(namespace),
                # version=1,
            )
            LOGGER.debug("DID:Indy Nym creation response: %s", ledger_response)

            did_info = DIDInfo(
                did=ledger_response.did,
                verkey=verkey,
                metadata={
                    "namespace": namespace,
                },
                method=INDY,
                key_type=ED25519,
            )
            await wallet.store_did(did_info)

            return did_info

    async def from_public_nym(
        self,
        profile: Profile,
        namespace: str,
        nym: str | None,
        *,
        didcomm: bool = True,
        ldp_vc: bool = False,
        mediation_records: List[MediationRecord] | None = None,
    ) -> DIDInfo:
        LOGGER.info("DID:Indy Creating did:indy from public nym")
        """Create a did:indy from an already published nym.

        If nym is not provided, current public "did" is used.
        """
        if mediation_records and not didcomm:
            raise ValueError("Mediation records passed but didcomm flag not set")

        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            if nym:
                public_did = await wallet.get_local_did(nym)
            else:
                public_did = await wallet.get_public_did()

            if not public_did:
                raise IndyRegistrarError("No nym provided and public DID not set")
            did = f"did:indy:{namespace}:{public_did.did}"

            # Enable ldp-vc issuance?
            verkey = public_did.verkey
            if ldp_vc:
                kid = f"{did}#assert"
                key = await wallet.create_key(key_type=ED25519, kid=kid)
                public_key_multibase = multibase.encode(
                    multicodec.wrap("ed25519-pub", base58.b58decode(key.verkey)),
                    "base58btc",
                )
                verkey = key.verkey
                vm = Ed25519VerificationKey2020.make(
                    id=kid, controller=did, public_key_multibase=public_key_multibase
                )
                doc_content = {
                    "@context": ["https://w3id.org/security/suites/ed25519-2020/v1"],
                    "verificationMethod": [vm.serialize()],
                    "assertionMethod": [vm.id],
                }
            else:
                doc_content = {}

            if didcomm:
                services = await self.prepare_didcomm_services(
                    profile, mediation_records
                )
                doc_content["service"] = services

            did_info = DIDInfo(
                did=did,
                verkey=verkey,
                metadata={
                    "namespace": namespace,
                },
                method=INDY,
                key_type=ED25519,
            )
            await wallet.store_did(did_info)

            nym_txn = ledger.build_nym_request(
                public_did.did, public_did.did, diddoc_content=json.dumps(doc_content)
            )
            base_ledger = session.inject(BaseLedger)
            async with base_ledger:
                await base_ledger.txn_submit(
                    nym_txn.body, sign=True, sign_did=public_did
                )
                attrib_txn = ledger.build_attrib_request(
                    public_did.did,
                    public_did.did,
                    xhash=None,
                    raw=json.dumps({"diddocContent": doc_content}),
                    enc=None,
                )
                await base_ledger.txn_submit(attrib_txn, sign=True, sign_did=public_did)

            return did_info
