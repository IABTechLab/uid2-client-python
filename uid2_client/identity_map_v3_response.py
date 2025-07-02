import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .unmapped_identity_reason import UnmappedIdentityReason


class IdentityMapV3Response:
    def __init__(self, response: str, identity_map_input):
        self._mapped_identities: Dict[str, MappedIdentity] = {}
        self._unmapped_identities: Dict[str, UnmappedIdentity] = {}
        response_json = json.loads(response)
        self._status = response_json["status"]
        
        if not self.is_success():
            raise ValueError("Got unexpected identity map status: " + self._status)

        body = response_json["body"]
        self._populate_identities(body, identity_map_input)

    def _populate_identities(self, api_response: Dict[str, List[Dict]], identity_map_input):
        for identity_type, identities in api_response.items():
            self._populate_identities_for_type(identity_map_input, identity_type, identities)

    def _populate_identities_for_type(self, identity_map_input, identity_type: str, identities: List[Dict]):
        for i, api_identity_data in enumerate(identities):
            api_identity = ApiIdentity.from_json(api_identity_data)
            input_diis = identity_map_input.get_input_diis(identity_type, i)
            
            for input_dii in input_diis:
                if api_identity.error is None:
                    self._mapped_identities[input_dii] = MappedIdentity.from_api_identity(api_identity)
                else:
                    self._unmapped_identities[input_dii] = UnmappedIdentity(api_identity.error)

    def is_success(self) -> bool:
        return self._status == "success"

    @property
    def mapped_identities(self) -> Dict[str, 'MappedIdentity']:
        return self._mapped_identities.copy()

    @property
    def unmapped_identities(self) -> Dict[str, 'UnmappedIdentity']:
        return self._unmapped_identities.copy()

    @property
    def status(self) -> str:
        return self._status


class ApiIdentity:
    def __init__(self, current_uid: Optional[str], previous_uid: Optional[str], 
                 refresh_from_seconds: Optional[int], error: Optional[str]):
        self.current_uid = current_uid
        self.previous_uid = previous_uid
        self.refresh_from_seconds = refresh_from_seconds
        self.error = error

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'ApiIdentity':
        return cls(
            current_uid=data.get("u"),
            previous_uid=data.get("p"),
            refresh_from_seconds=data.get("r"),
            error=data.get("e")
        )


class MappedIdentity:
    def __init__(self, current_uid: str, previous_uid: Optional[str], refresh_from_seconds: datetime):
        self._current_uid = current_uid
        self._previous_uid = previous_uid
        self._refresh_from = refresh_from_seconds

    @classmethod
    def from_api_identity(cls, api_identity: ApiIdentity):
        return cls(api_identity.current_uid,
                              api_identity.previous_uid,
                              datetime.fromtimestamp(api_identity.refresh_from_seconds, tz=timezone.utc))

    @property
    def current_raw_uid(self) -> str:
        return self._current_uid

    @property
    def previous_raw_uid(self) -> Optional[str]:
        return self._previous_uid

    @property
    def refresh_from(self) -> datetime:
        return self._refresh_from


class UnmappedIdentity:
    def __init__(self, reason: str):
        self._reason = UnmappedIdentityReason.from_string(reason)
        self._raw_reason = reason

    @property
    def reason(self) -> UnmappedIdentityReason:
        return self._reason

    @property
    def raw_reason(self) -> str:
        return self._raw_reason
