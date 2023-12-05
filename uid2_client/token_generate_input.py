import json
from .identity_type import IdentityType
from .input_util import *


class TokenGenerateInput:
    def __init__(self, identity_type, email_or_phone, need_hash, already_hashed):
        self.identity_type = identity_type
        self.email_or_phone = email_or_phone
        self.need_hash = need_hash
        self.already_hashed = already_hashed
        self.generate_for_opted_out = True
        self.transparency_and_consent_string = None

    @staticmethod
    def from_email(email):
        return TokenGenerateInput(IdentityType.Email, email, True, False)

    @staticmethod
    def from_phone(phone):
        return TokenGenerateInput(IdentityType.Phone, phone, True, False)

    @staticmethod
    def from_hashed_email(hashed_email):
        return TokenGenerateInput(IdentityType.Email, hashed_email, False, True)

    @staticmethod
    def from_hashed_phone(hashed_phone):
        return TokenGenerateInput(IdentityType.Phone, hashed_phone, False, True)

    def with_transparency_and_consent_string(self, tc_string):
        self.transparency_and_consent_string = tc_string
        return self

    def do_not_hash(self):
        self.need_hash = False
        return self

    # Always use .do_not_generate_tokens_for_opted_out(), which applies policy=1. Support for policy=0 will be removed soon.
    def do_not_generate_tokens_for_opted_out(self):
        self.generate_for_opted_out = False
        return self

    def get_as_json_string(self):
        if self.already_hashed:
            return self.create_already_hashed_json_request_for_generate_token()
        elif self.need_hash:
            return self.create_hashed_json_request_for_generate_token()
        else:
            return self.create_json_request_for_generate_token()

    def create_json_request_for_generate_token(self):
        property = "email" if self.identity_type == IdentityType.Email else "phone"
        return self._create_json_request_for_generate_token(property, self.email_or_phone,
                                                            self.transparency_and_consent_string,
                                                            self.generate_for_opted_out)

    @staticmethod
    def _create_json_request_for_generate_token(property, value, tc_string, generate_for_opted_out):
        json_object = {
            property: value
        }
        if tc_string is not None:
            json_object["tcf_consent_string"] = tc_string
        if not generate_for_opted_out:
            json_object["policy"] = 1
        return json.dumps(json_object)

    def create_hashed_json_request_for_generate_token(self):
        # The details of InputUtil are not given in the question
        # But you need to implement InputUtil in Python
        if self.identity_type == IdentityType.Email:
            normalized_email = normalize_email_string(self.email_or_phone)
            if normalized_email is None:
                raise ValueError("invalid email address")
            hashed_normalized_email = get_base64_encoded_hash(normalized_email)
            return self._create_json_request_for_generate_token("email_hash", hashed_normalized_email,
                                                                self.transparency_and_consent_string,
                                                                self.generate_for_opted_out)
        else:  # phone
            if not is_phone_number_normalized(self.email_or_phone):
                raise ValueError("phone number is not normalized")
            hashed_normalized_phone = get_base64_encoded_hash(self.email_or_phone)
            return self._create_json_request_for_generate_token("phone_hash", hashed_normalized_phone,
                                                                self.transparency_and_consent_string,
                                                                self.generate_for_opted_out)

    def create_already_hashed_json_request_for_generate_token(self):
        if self.identity_type == IdentityType.Email:
            return self._create_json_request_for_generate_token("email_hash", self.email_or_phone,
                                                                self.transparency_and_consent_string,
                                                                self.generate_for_opted_out)
        else:  # phone
            return self._create_json_request_for_generate_token("phone_hash", self.email_or_phone,
                                                                self.transparency_and_consent_string,
                                                                self.generate_for_opted_out)
