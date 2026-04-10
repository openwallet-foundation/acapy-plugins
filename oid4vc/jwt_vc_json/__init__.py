"""jwt_vc_json credential handler plugin."""

from acapy_agent.config.injection_context import InjectionContext

from oid4vc.cred_processor import CredProcessors

from .cred_processor import JwtVcJsonCredProcessor
from . import routes as routes  # noqa: F401 — triggers ACA-Py route discovery


async def setup(context: InjectionContext):
    """Setup the plugin."""

    jwt_vc_json = JwtVcJsonCredProcessor()
    processors = context.inject(CredProcessors)
    processors.register_issuer("jwt_vc_json", jwt_vc_json)
    processors.register_issuer("jwt_vc", jwt_vc_json)
    processors.register_cred_verifier("jwt_vc_json", jwt_vc_json)
    processors.register_cred_verifier("jwt_vc", jwt_vc_json)
    processors.register_pres_verifier("jwt_vp_json", jwt_vc_json)
    processors.register_pres_verifier("jwt_vp", jwt_vc_json)
