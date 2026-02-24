"""Module for handling pending webvh attested resource requests."""

from typing import Optional, Tuple

from acapy_agent.core.profile import Profile

from ..base_record import BasePendingRecord


class PendingAttestedResourceRecord(BasePendingRecord):
    """Class to manage pending webvh attested resource witness requests."""

    RECORD_TYPE = "attested-resource"
    RECORD_TOPIC = "attested_resource"
    instance = None
    scids = None

    async def get_pending_record_for_resource(
        self, profile: Profile, resource: dict
    ) -> Optional[Tuple[dict, str]]:
        """Find an existing pending record for this resource.

        Prevents duplicate witness requests when the controller retries (e.g.
        revocation list registration). For anonCredsStatusList, matches by
        rev_reg_def_id since retries create new content with new timestamp.
        For other types, matches by resource id.

        Returns:
            (pending_record, request_id) if found, else None
        """
        resource_type = resource.get("metadata", {}).get("resourceType", "")
        resource_id = resource.get("id", "")
        content = resource.get("content", {})

        for pending in await self.get_pending_records(profile):
            if pending.get("role") != "controller":
                continue
            stored = pending.get("record", {})
            stored_type = stored.get("metadata", {}).get("resourceType", "")
            stored_content = stored.get("content", {})

            if (
                resource_type == "anonCredsStatusList"
                and stored_type == "anonCredsStatusList"
            ):
                # Match by rev_reg_def_id - retries create new digest (timestamp)
                rev_id = content.get("rev_reg_def_id") or content.get("revRegDefId")
                stored_rev_id = stored_content.get(
                    "rev_reg_def_id"
                ) or stored_content.get("revRegDefId")
                if rev_id and rev_id == stored_rev_id:
                    return pending, pending.get("record_id", "")
            elif stored.get("id") == resource_id:
                return pending, pending.get("record_id", "")

        return None
