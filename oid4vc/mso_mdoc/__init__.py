"""MSO_MDOC Credential Handler Plugin."""

import logging

from acapy_agent.config.injection_context import InjectionContext

from mso_mdoc.cred_processor import MsoMdocCredProcessor
from oid4vc.cred_processor import CredProcessors
from . import routes as routes  # noqa: F401 — triggers ACA-Py route discovery

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("Setting up MSO_MDOC plugin")

    processors = context.inject_or(CredProcessors)
    if not processors:
        processors = CredProcessors()
        context.injector.bind_instance(CredProcessors, processors)

    _mso_mdoc_processor = MsoMdocCredProcessor()
    processors.register_issuer("mso_mdoc", _mso_mdoc_processor)
    processors.register_cred_verifier("mso_mdoc", _mso_mdoc_processor)
    processors.register_pres_verifier("mso_mdoc", _mso_mdoc_processor)
