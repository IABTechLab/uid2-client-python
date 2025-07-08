import unittest
from datetime import datetime
from uid2_client import IdentityMapV3Input, IdentityMapV3Response
from uid2_client.unmapped_identity_reason import UnmappedIdentityReason


class IdentityMapV3ResponseTest(unittest.TestCase):
    SOME_EMAIL = "email1@example.com"

    def test_mapped_identity(self):
        email1 = "email1@example.com"
        email2 = "email2@example.com"
        phone1 = "+1234567890"
        phone2 = "+0987654321"
        hashed_email1 = "email 1 hash"
        hashed_email2 = "email 2 hash" 
        hashed_phone1 = "phone 1 hash"
        hashed_phone2 = "phone 2 hash"

        email1_refresh_from = datetime.fromisoformat('2025-01-01T00:00:01+00:00')
        email2_refresh_from = datetime.fromisoformat('2025-06-30T00:00:20+00:00')
        phone1_refresh_from = datetime.fromisoformat('2025-01-01T00:05:00+00:00')
        phone2_refresh_from = datetime.fromisoformat('2025-06-30T00:00:22+00:00')
        hashed_email1_refresh_from = datetime.fromisoformat('2025-01-01T00:00:33+00:00')
        hashed_email2_refresh_from = datetime.fromisoformat('2025-06-30T00:00:00+00:00')
        hashed_phone1_refresh_from = datetime.fromisoformat('2025-01-01T00:00:11+00:00')
        hashed_phone2_refresh_from = datetime.fromisoformat('2025-06-30T00:00:01+00:00')

        email_hash_entries = [
            self._mapped_response_payload_entry("email 1 current uid", "email 1 previous uid", email1_refresh_from),
            self._mapped_response_payload_entry("email 2 current uid", "email 2 previous uid", email2_refresh_from),
            self._mapped_response_payload_entry("hashed email 1 current uid", "hashed email 1 previous uid", hashed_email1_refresh_from),
            self._mapped_response_payload_entry("hashed email 2 current uid", "hashed email 2 previous uid", hashed_email2_refresh_from)
        ]

        phone_hash_entries = [
            self._mapped_response_payload_entry("phone 1 current uid", "phone 1 previous uid", phone1_refresh_from),
            self._mapped_response_payload_entry("phone 2 current uid", "phone 2 previous uid", phone2_refresh_from),
            self._mapped_response_payload_entry("hashed phone 1 current uid", "hashed phone 1 previous uid", hashed_phone1_refresh_from),
            self._mapped_response_payload_entry("hashed phone 2 current uid", "hashed phone 2 previous uid", hashed_phone2_refresh_from)
        ]

        response_payload = self._mapped_response_payload(email_hash_entries, phone_hash_entries)

        input_obj = (IdentityMapV3Input()
                     .with_emails([email1, email2])
                     .with_hashed_emails([hashed_email1, hashed_email2])
                     .with_phones([phone1, phone2])
                     .with_hashed_phones([hashed_phone1, hashed_phone2]))

        response = IdentityMapV3Response(response_payload, input_obj)

        self.assertTrue(response.is_success())
        self.assertEqual(8, len(response.mapped_identities))
        self.assertEqual(0, len(response.unmapped_identities))

        # Email
        raw_email_mapping1 = response.mapped_identities.get(email1)
        self.assertEqual("email 1 current uid", raw_email_mapping1.current_raw_uid)
        self.assertEqual("email 1 previous uid", raw_email_mapping1.previous_raw_uid)
        self.assertEqual(email1_refresh_from, raw_email_mapping1.refresh_from)

        raw_email_mapping2 = response.mapped_identities.get(email2)
        self.assertEqual("email 2 current uid", raw_email_mapping2.current_raw_uid)
        self.assertEqual("email 2 previous uid", raw_email_mapping2.previous_raw_uid)
        self.assertEqual(email2_refresh_from, raw_email_mapping2.refresh_from)

        # Phone
        raw_phone_mapping1 = response.mapped_identities.get(phone1)
        self.assertEqual("phone 1 current uid", raw_phone_mapping1.current_raw_uid)
        self.assertEqual("phone 1 previous uid", raw_phone_mapping1.previous_raw_uid)
        self.assertEqual(phone1_refresh_from, raw_phone_mapping1.refresh_from)

        raw_phone_mapping2 = response.mapped_identities.get(phone2)
        self.assertEqual("phone 2 current uid", raw_phone_mapping2.current_raw_uid)
        self.assertEqual("phone 2 previous uid", raw_phone_mapping2.previous_raw_uid)
        self.assertEqual(phone2_refresh_from, raw_phone_mapping2.refresh_from)

        # Hashed Email
        hashed_email_mapping1 = response.mapped_identities.get(hashed_email1)
        self.assertEqual("hashed email 1 current uid", hashed_email_mapping1.current_raw_uid)
        self.assertEqual("hashed email 1 previous uid", hashed_email_mapping1.previous_raw_uid)
        self.assertEqual(hashed_email1_refresh_from, hashed_email_mapping1.refresh_from)

        hashed_email_mapping2 = response.mapped_identities.get(hashed_email2)

        self.assertEqual("hashed email 2 current uid", hashed_email_mapping2.current_raw_uid)
        self.assertEqual("hashed email 2 previous uid", hashed_email_mapping2.previous_raw_uid)
        self.assertEqual(hashed_email2_refresh_from, hashed_email_mapping2.refresh_from)

        # Hashed Phone
        hashed_phone_mapping1 = response.mapped_identities.get(hashed_phone1)
        self.assertEqual("hashed phone 1 current uid", hashed_phone_mapping1.current_raw_uid)
        self.assertEqual("hashed phone 1 previous uid", hashed_phone_mapping1.previous_raw_uid)
        self.assertEqual(hashed_phone1_refresh_from, hashed_phone_mapping1.refresh_from)

        hashed_phone_mapping2 = response.mapped_identities.get(hashed_phone2)
        self.assertEqual("hashed phone 2 current uid", hashed_phone_mapping2.current_raw_uid)
        self.assertEqual("hashed phone 2 previous uid", hashed_phone_mapping2.previous_raw_uid)
        self.assertEqual(hashed_phone2_refresh_from, hashed_phone_mapping2.refresh_from)

    def test_unmapped_identity_reason_unknown(self):
        input_obj = IdentityMapV3Input.from_emails([self.SOME_EMAIL])

        response = IdentityMapV3Response(self._unmapped_response_payload("some new unmapped reason"), input_obj)
        self.assertTrue(response.is_success())

        unmapped_identity = response.unmapped_identities.get(self.SOME_EMAIL)
        self.assertEqual(UnmappedIdentityReason.UNKNOWN, unmapped_identity.reason)
        self.assertEqual("some new unmapped reason", unmapped_identity.raw_reason)

    def test_unmapped_identity_reason_optout(self):
        input_obj = IdentityMapV3Input.from_emails([self.SOME_EMAIL])

        response = IdentityMapV3Response(self._unmapped_response_payload("optout"), input_obj)
        self.assertTrue(response.is_success())

        unmapped_identity = response.unmapped_identities.get(self.SOME_EMAIL)
        self.assertEqual(UnmappedIdentityReason.OPTOUT, unmapped_identity.reason)
        self.assertEqual("optout", unmapped_identity.raw_reason)

    def test_unmapped_identity_reason_invalid(self):
        input_obj = IdentityMapV3Input.from_emails([self.SOME_EMAIL])

        response = IdentityMapV3Response(self._unmapped_response_payload("invalid identifier"), input_obj)
        self.assertTrue(response.is_success())

        unmapped_identity = response.unmapped_identities.get(self.SOME_EMAIL)
        self.assertEqual(UnmappedIdentityReason.INVALID_IDENTIFIER, unmapped_identity.reason)
        self.assertEqual("invalid identifier", unmapped_identity.raw_reason)

    def test_response_status_not_success(self):
        input_obj = IdentityMapV3Input.from_emails([self.SOME_EMAIL])
        
        failure_response_payload = '{"status":"error","body":{}}'
        
        with self.assertRaises(ValueError) as context:
            IdentityMapV3Response(failure_response_payload, input_obj)
        
        self.assertEqual("Got unexpected identity map status: error", str(context.exception))

    @staticmethod
    def _unmapped_response_payload(reason: str) -> str:
        return f'{{"status":"success","body":{{"email_hash":[{{"e":"{reason}"}}]}}}}'

    @staticmethod
    def _mapped_response_payload(email_hash_entries: list, phone_hash_entries: list) -> str:
        email_entries_str = ",".join(email_hash_entries)
        phone_entries_str = ",".join(phone_hash_entries)
        return (f'{{"status":"success","body":{{'
                f'"email_hash":[{email_entries_str}],'
                f'"phone_hash":[{phone_entries_str}]'
                f'}}}}')

    @staticmethod
    def _mapped_response_payload_entry(current_uid: str, previous_uid: str, refresh_from: datetime) -> str:
        return f'{{"u":"{current_uid}","p":"{previous_uid}","r":{refresh_from.timestamp()}}}'


if __name__ == '__main__':
    unittest.main() 