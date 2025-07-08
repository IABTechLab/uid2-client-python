import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Literal

from .identity_map_v3_input import IdentityMapV3Input
from .unmapped_identity_reason import UnmappedIdentityReason


class IdentityMapV3Response:
    def __init__(self, response: str, identity_map_input: IdentityMapV3Input):
        self._mapped_identities: Dict[str, MappedIdentity] = {}
        self._unmapped_identities: Dict[str, UnmappedIdentity] = {}

        response_json = json.loads(response)
        api_response = ApiResponse.from_json(response_json)
        self._status = api_response.status
        
        if not self.is_success():
            raise ValueError("Got unexpected identity map status: " + self._status)

        self._populate_identities(api_response.body, identity_map_input)

    def _populate_identities(self, api_response: Dict[Literal['email_hash', 'phone_hash'], List['ApiIdentity']], identity_map_input: IdentityMapV3Input) -> None:
        for identity_type, identities in api_response.items():
            self._populate_identities_for_type(identity_map_input, identity_type, identities)

    def _populate_identities_for_type(self, identity_map_input: IdentityMapV3Input, identity_type: Literal['email_hash', 'phone_hash'], identities: List['ApiIdentity']) -> None:
        for i, api_identity in enumerate(identities):
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


class ApiResponse:
    def __init__(self, status: str, body: Dict[Literal['email_hash', 'phone_hash'], List['ApiIdentity']]):
        self.status = status
        self.body = body

    @classmethod
    def from_json(cls, data) -> 'ApiResponse':
        if not set(data['body'].keys()).issubset(['email', 'phone', 'email_hash', 'phone_hash']):
            raise ValueError("api response body does not contain correct keys")

        api_body: Dict[Literal['email_hash', 'phone_hash'], List['ApiIdentity']] = {
            'email_hash': [ApiIdentity.from_json(item) for item in data['body']['email_hash']] if data['body'].get('email_hash') else [],
            'phone_hash': [ApiIdentity.from_json(item) for item in data['body']['phone_hash']] if data['body'].get('phone_hash') else [],
        }
        return cls(
            status=data['status'],
            body=api_body
        )


class ApiIdentity:
    def __init__(self, current_uid: Optional[str], previous_uid: Optional[str], 
                 refresh_from_seconds: Optional[int], error: Optional[str]):
        self.current_uid = current_uid
        self.previous_uid = previous_uid
        self.refresh_from_seconds = refresh_from_seconds
        self.error = error

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'ApiIdentity':
        mapped_identity = data.keys().__contains__("u") and data.keys().__contains__("p") and data.keys().__contains__("r")
        unmapped_identity = data.keys().__contains__("e")
        if not mapped_identity and not unmapped_identity:
            raise ValueError("api identity does not contain the correct keys")

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
    def from_api_identity(cls, api_identity: ApiIdentity) -> 'MappedIdentity':
        if api_identity.current_uid is None or api_identity.refresh_from_seconds is None:
            raise ValueError("Mapped identity cannot be created from API identity with missing current_uid or refresh_from_seconds")
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
