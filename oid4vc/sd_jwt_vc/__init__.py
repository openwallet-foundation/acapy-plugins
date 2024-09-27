"""SD-JWT Crendential Handler Plugin."""

from importlib.util import find_spec

from aries_cloudagent.config.injection_context import InjectionContext
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor
from oid4vc.cred_processor import CredProcessors

jsonpointer = find_spec("jsonpointer")
if not jsonpointer:
    raise ImportError("`sd_jwt` extra required")


async def setup(context: InjectionContext):
    """Setup the plugin."""
    processors = context.inject(CredProcessors)
    sd_jwt = SdJwtCredIssueProcessor()
    processors.register_issuer("vc+sd-jwt", sd_jwt)
    processors.register_cred_verifier("vc+sd-jwt", sd_jwt)
    processors.register_pres_verifier("vc+sd-jwt", sd_jwt)
