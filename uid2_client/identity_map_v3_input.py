import json
from typing import List, Dict, Literal

from uid2_client import normalize_and_hash_email, normalize_and_hash_phone


class IdentityMapV3Input:
    """Input for IdentityMapV3Client, representing emails and/or phone numbers to be mapped"""

    def __init__(self):
        self._hashed_dii_to_raw_diis: Dict[str, List[str]] = {}
        self._hashed_emails: List[str] = []
        self._hashed_phones: List[str] = []

    @staticmethod
    def from_emails(emails: List[str]) -> 'IdentityMapV3Input':
        return IdentityMapV3Input().with_emails(emails)

    @staticmethod
    def from_phones(phones: List[str]) -> 'IdentityMapV3Input':
        return IdentityMapV3Input().with_phones(phones)

    @staticmethod
    def from_hashed_emails(hashed_emails: List[str]) -> 'IdentityMapV3Input':
        return IdentityMapV3Input().with_hashed_emails(hashed_emails)

    @staticmethod
    def from_hashed_phones(hashed_phones: List[str]) -> 'IdentityMapV3Input':
        return IdentityMapV3Input().with_hashed_phones(hashed_phones)

    def with_emails(self, emails: List[str]) -> 'IdentityMapV3Input':
        for email in emails:
            self.with_email(email)
        return self

    def with_email(self, email: str) -> 'IdentityMapV3Input':
        hashed_email = normalize_and_hash_email(email)
        self._hashed_emails.append(hashed_email)
        self._add_to_dii_mappings(hashed_email, email)
        return self

    def with_phones(self, phones: List[str]) -> 'IdentityMapV3Input':
        for phone in phones:
            self.with_phone(phone)
        return self

    def with_phone(self, phone: str) -> 'IdentityMapV3Input':
        hashed_phone = normalize_and_hash_phone(phone)
        self._hashed_phones.append(hashed_phone)
        self._add_to_dii_mappings(hashed_phone, phone)
        return self

    def with_hashed_emails(self, hashed_emails: List[str]) -> 'IdentityMapV3Input':
        for hashed_email in hashed_emails:
            self.with_hashed_email(hashed_email)
        return self

    def with_hashed_email(self, hashed_email: str) -> 'IdentityMapV3Input':
        self._hashed_emails.append(hashed_email)
        self._add_to_dii_mappings(hashed_email, hashed_email)
        return self

    def with_hashed_phones(self, hashed_phones: List[str]) -> 'IdentityMapV3Input':
        for hashed_phone in hashed_phones:
            self.with_hashed_phone(hashed_phone)
        return self

    def with_hashed_phone(self, hashed_phone: str) -> 'IdentityMapV3Input':
        self._hashed_phones.append(hashed_phone)
        self._add_to_dii_mappings(hashed_phone, hashed_phone)
        return self

    def get_input_diis(self, identity_type: Literal['email_hash', 'phone_hash'], index: int) -> List[str]:
        hashed_dii = self._get_hashed_dii(identity_type, index)
        return self._hashed_dii_to_raw_diis.get(hashed_dii, [])

    def _add_to_dii_mappings(self, hashed_dii: str, raw_dii: str) -> None:
        if hashed_dii not in self._hashed_dii_to_raw_diis:
            self._hashed_dii_to_raw_diis[hashed_dii] = []
        self._hashed_dii_to_raw_diis[hashed_dii].append(raw_dii)

    def _get_hashed_dii(self, identity_type: Literal['email_hash', 'phone_hash'], index: int) -> str:
        if identity_type == "email_hash":
            return self._hashed_emails[index]
        elif identity_type == "phone_hash":
            return self._hashed_phones[index]
        else:
            raise ValueError(f"Unexpected identity type: {identity_type}")

    def get_identity_map_input_as_json_string(self) -> str:
        json_object = {
            "email_hash": self._hashed_emails,
            "phone_hash": self._hashed_phones
        }
        return json.dumps({k: v for k, v in json_object.items() if v is not None})
