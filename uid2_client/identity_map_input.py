import json

from uid2_client import IdentityType, normalize_email_string, get_base64_encoded_hash, is_phone_number_normalized


class IdentityMapInput:
    """input for IdentityMapClient, such as email addresses or phone numbers"""

    def __init__(self, identity_type, emails_or_phones, already_hashed):
        self.hashed_dii_to_raw_diis = {}
        self.hashed_normalized_emails = []
        self.hashed_normalized_phones = []
        if identity_type == IdentityType.Email:
            for email in emails_or_phones:
                if already_hashed:
                    self.hashed_normalized_emails.append(email)
                else:
                    normalized_email = normalize_email_string(email)
                    if normalized_email is None:
                        raise ValueError("invalid email address")
                    hashed_normalized_email = get_base64_encoded_hash(normalized_email)
                    self.hashed_normalized_emails.append(hashed_normalized_email)
                    self._add_hashed_to_raw_dii_mapping(hashed_normalized_email, email)
        else:  # phone
            for phone in emails_or_phones:
                if already_hashed:
                    self.hashed_normalized_phones.append(phone)
                else:
                    if not is_phone_number_normalized(phone):
                        raise ValueError("phone number is not normalized: " + phone)
                    hashed_normalized_phone = get_base64_encoded_hash(phone)
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

    def get_identity_map_input_as_json_string(self):
        json_object = {
            "email_hash": self.hashed_normalized_emails,
            "phone_hash": self.hashed_normalized_phones
        }
        return json.dumps({k: v for k, v in json_object.items() if v is not None and len(v) > 0})
