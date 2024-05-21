import json

from uid2_client import IdentityType, normalize_and_hash_email, normalize_and_hash_phone


class IdentityMapInput:
    """input for IdentityMapClient, such as email addresses or phone numbers"""

    def __init__(self, identity_type, emails_or_phones, already_hashed):
        self.hashed_dii_to_raw_diis = {}
        self.hashed_normalized_emails = None
        self.hashed_normalized_phones = None
        if identity_type == IdentityType.Email:
            if already_hashed:
                self.hashed_normalized_emails = emails_or_phones
            else:
                self.hashed_normalized_emails = []
                for email in emails_or_phones:
                    hashed_normalized_email = normalize_and_hash_email(email)
                    self._add_hashed_to_raw_dii_mapping(hashed_normalized_email, email)
                    self.hashed_normalized_emails.append(hashed_normalized_email)
        else:  # phone
            if already_hashed:
                self.hashed_normalized_phones = emails_or_phones
            else:
                self.hashed_normalized_phones = []
                for phone in emails_or_phones:
                    hashed_normalized_phone = normalize_and_hash_phone(phone)
                    self._add_hashed_to_raw_dii_mapping(hashed_normalized_phone, phone)
                    self.hashed_normalized_phones.append(hashed_normalized_phone)

    @staticmethod
    def from_emails(emails):
        return IdentityMapInput(IdentityType.Email, emails, False)

    @staticmethod
    def from_phones(phones):
        return IdentityMapInput(IdentityType.Phone, phones, False)

    @staticmethod
    def from_hashed_emails(hashed_emails):
        return IdentityMapInput(IdentityType.Email, hashed_emails, True)

    @staticmethod
    def from_hashed_phones(hashed_phones):
        return IdentityMapInput(IdentityType.Phone, hashed_phones, True)

    def _add_hashed_to_raw_dii_mapping(self, hashed_dii, raw_dii):
        self.hashed_dii_to_raw_diis.setdefault(hashed_dii, []).append(raw_dii)

    def get_raw_diis(self, identifier):
        if len(self.hashed_dii_to_raw_diis) <= 0:
            return [identifier]
        else:
            return self.hashed_dii_to_raw_diis[identifier]

    def get_identity_map_input_as_json_string(self):
        json_object = {
            "email_hash": self.hashed_normalized_emails,
            "phone_hash": self.hashed_normalized_phones
        }
        return json.dumps({k: v for k, v in json_object.items() if v is not None})
