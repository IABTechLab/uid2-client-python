import os
import unittest

from datetime import datetime, timedelta, timezone
from urllib.error import URLError, HTTPError

from uid2_client import IdentityMapV3Client, IdentityMapV3Input, IdentityMapV3Response, normalize_and_hash_email, normalize_and_hash_phone
from uid2_client.unmapped_identity_reason import UnmappedIdentityReason

@unittest.skipIf(
    os.getenv("UID2_BASE_URL") == None
    or os.getenv("UID2_API_KEY") == None
    or os.getenv("UID2_SECRET_KEY") == None,
    reason="Environment variables UID2_BASE_URL, UID2_API_KEY, and UID2_SECRET_KEY must be set",
)
class IdentityMapV3IntegrationTests(unittest.TestCase):
    UID2_BASE_URL = None
    UID2_API_KEY = None
    UID2_SECRET_KEY = None

    identity_map_client = None

    @classmethod
    def setUpClass(cls):
        cls.UID2_BASE_URL = os.getenv("UID2_BASE_URL")
        cls.UID2_API_KEY = os.getenv("UID2_API_KEY")
        cls.UID2_SECRET_KEY = os.getenv("UID2_SECRET_KEY")

        if cls.UID2_BASE_URL and cls.UID2_API_KEY and cls.UID2_SECRET_KEY:
            cls.identity_map_client = IdentityMapV3Client(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
        else:
            raise Exception("set the required UID2_BASE_URL/UID2_API_KEY/UID2_SECRET_KEY environment variables first")

    def test_identity_map_emails(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["hopefully-not-opted-out@example.com", "somethingelse@example.com", "optout@example.com"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_mapped(response, "hopefully-not-opted-out@example.com")
        self.assert_mapped(response, "somethingelse@example.com")

        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, "optout@example.com")

    def test_identity_map_nothing_unmapped(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["hopefully-not-opted-out@example.com", "somethingelse@example.com"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_mapped(response, "hopefully-not-opted-out@example.com")
        self.assert_mapped(response, "somethingelse@example.com")

    def test_identity_map_nothing_mapped(self):
        identity_map_input = IdentityMapV3Input.from_emails(["optout@example.com"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, "optout@example.com")

    def test_identity_map_invalid_email(self):
        self.assertRaises(ValueError, IdentityMapV3Input.from_emails,
                          ["email@example.com", "this is not an email"])

    def test_identity_map_invalid_phone(self):
        self.assertRaises(ValueError, IdentityMapV3Input.from_phones,
                          ["+12345678901", "this is not a phone number"])

    def test_identity_map_invalid_hashed_email(self):
        identity_map_input = IdentityMapV3Input.from_hashed_emails(["this is not a hashed email"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_unmapped(response, UnmappedIdentityReason.INVALID_IDENTIFIER, "this is not a hashed email")

    def test_identity_map_invalid_hashed_phone(self):
        identity_map_input = IdentityMapV3Input.from_hashed_phones(["this is not a hashed phone"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_unmapped(response, UnmappedIdentityReason.INVALID_IDENTIFIER, "this is not a hashed phone")

    def test_identity_map_hashed_emails(self):
        hashed_email1 = normalize_and_hash_email("hopefully-not-opted-out@example.com")
        hashed_email2 = normalize_and_hash_email("somethingelse@example.com")
        hashed_opted_out_email = normalize_and_hash_email("optout@example.com")
        identity_map_input = IdentityMapV3Input.from_hashed_emails([hashed_email1, hashed_email2, hashed_opted_out_email])

        response = self.identity_map_client.generate_identity_map(identity_map_input)

        self.assert_mapped(response, hashed_email1)
        self.assert_mapped(response, hashed_email2)

        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, hashed_opted_out_email)

    def test_identity_map_duplicate_emails(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["JANE.SAOIRSE@gmail.com", "Jane.Saoirse@gmail.com", "JaneSaoirse+UID2@gmail.com", "janesaoirse@gmail.com",
             "JANE.SAOIRSE@gmail.com"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)

        mapped_identities = response.mapped_identities
        self.assertEqual(4, len(mapped_identities))

        raw_uid = mapped_identities.get("JANE.SAOIRSE@gmail.com").current_raw_uid
        self.assertEqual(raw_uid, mapped_identities.get("Jane.Saoirse@gmail.com").current_raw_uid)
        self.assertEqual(raw_uid, mapped_identities.get("JaneSaoirse+UID2@gmail.com").current_raw_uid)
        self.assertEqual(raw_uid, mapped_identities.get("janesaoirse@gmail.com").current_raw_uid)

    def test_identity_map_duplicate_hashed_emails(self):
        hashed_email = normalize_and_hash_email("hopefully-not-opted-out@example.com")
        duplicate_hashed_email = hashed_email
        hashed_opted_out_email = normalize_and_hash_email("optout@example.com")
        duplicate_hashed_opted_out_email = hashed_opted_out_email

        identity_map_input = IdentityMapV3Input.from_hashed_emails(
            [hashed_email, duplicate_hashed_email, hashed_opted_out_email, duplicate_hashed_opted_out_email])
        response = self.identity_map_client.generate_identity_map(identity_map_input)

        self.assert_mapped(response, hashed_email)
        self.assert_mapped(response, duplicate_hashed_email)

        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, hashed_opted_out_email)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, duplicate_hashed_opted_out_email)

    def test_identity_map_empty_input(self):
        identity_map_input = IdentityMapV3Input.from_emails([])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assertTrue(len(response.mapped_identities) == 0)
        self.assertTrue(len(response.unmapped_identities) == 0)

    def test_identity_map_phones(self):
        identity_map_input = IdentityMapV3Input.from_phones(["+12345678901", "+98765432109", "+00000000000"])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_mapped(response, "+12345678901")
        self.assert_mapped(response, "+98765432109")

        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, "+00000000000")

    def test_identity_map_hashed_phones(self):
        hashed_phone1 = normalize_and_hash_phone("+12345678901")
        hashed_phone2 = normalize_and_hash_phone("+98765432109")
        hashed_opted_out_phone = normalize_and_hash_phone("+00000000000")
        identity_map_input = IdentityMapV3Input.from_hashed_phones([hashed_phone1, hashed_phone2, hashed_opted_out_phone])
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        self.assert_mapped(response, hashed_phone1)
        self.assert_mapped(response, hashed_phone2)

        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, hashed_opted_out_phone)

    def test_identity_map_all_identity_types_in_one_request(self):
        mapped_email = "hopefully-not-opted-out@example.com"
        optout_email = "optout@example.com"
        mapped_phone = "+12345678901"
        optout_phone = "+00000000000"
        
        mapped_email_hash = normalize_and_hash_email("mapped-email@example.com")
        optout_email_hash = normalize_and_hash_email(optout_email)
        mapped_phone_hash = normalize_and_hash_phone(mapped_phone)
        optout_phone_hash = normalize_and_hash_phone(optout_phone)
        
        identity_map_input = (IdentityMapV3Input.from_emails([mapped_email, optout_email])
                             .with_hashed_emails([mapped_email_hash, optout_email_hash])
                             .with_phones([mapped_phone, optout_phone])
                             .with_hashed_phones([mapped_phone_hash, optout_phone_hash]))
        
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        
        # Test mapped identities
        self.assert_mapped(response, mapped_email)
        self.assert_mapped(response, mapped_email_hash)
        self.assert_mapped(response, mapped_phone)
        self.assert_mapped(response, mapped_phone_hash)
        
        # Test unmapped identities
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_email)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_email_hash)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_phone)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_phone_hash)

    def test_identity_map_all_identity_types_added_one_by_one(self):
        mapped_email = "hopefully-not-opted-out@example.com"
        optout_phone = "+00000000000"
        mapped_phone_hash = normalize_and_hash_phone("+12345678901")
        optout_email_hash = normalize_and_hash_email("optout@example.com")
        
        identity_map_input = IdentityMapV3Input()
        identity_map_input.with_email(mapped_email)
        identity_map_input.with_phone(optout_phone)
        identity_map_input.with_hashed_phone(mapped_phone_hash)
        identity_map_input.with_hashed_email(optout_email_hash)
        
        response = self.identity_map_client.generate_identity_map(identity_map_input)
        
        # Test mapped identities
        self.assert_mapped(response, mapped_email)
        self.assert_mapped(response, mapped_phone_hash)
        
        # Test unmapped identities
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_phone)
        self.assert_unmapped(response, UnmappedIdentityReason.OPTOUT, optout_email_hash)

    def test_identity_map_client_bad_url(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["hopefully-not-opted-out@example.com", "somethingelse@example.com", "optout@example.com"])
        client = IdentityMapV3Client("https://operator-bad-url.uidapi.com", os.getenv("UID2_API_KEY"), os.getenv("UID2_SECRET_KEY"))
        self.assertRaises(URLError, client.generate_identity_map, identity_map_input)

    def test_identity_map_client_bad_api_key(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["hopefully-not-opted-out@example.com", "somethingelse@example.com", "optout@example.com"])
        client = IdentityMapV3Client(os.getenv("UID2_BASE_URL"), "bad-api-key", os.getenv("UID2_SECRET_KEY"))
        self.assertRaises(HTTPError, client.generate_identity_map, identity_map_input)

    def test_identity_map_client_bad_secret(self):
        identity_map_input = IdentityMapV3Input.from_emails(
            ["hopefully-not-opted-out@example.com", "somethingelse@example.com", "optout@example.com"])

        client = IdentityMapV3Client(os.getenv("UID2_BASE_URL"), os.getenv("UID2_API_KEY"), "wJ0hP19QU4hmpB64Y3fV2dAed8t/mupw3sjN5jNRFzg=")
        self.assertRaises(HTTPError, client.generate_identity_map, identity_map_input)

    def assert_mapped(self, response: IdentityMapV3Response, dii):
        mapped_identity = response.mapped_identities.get(dii)
        self.assertIsNotNone(mapped_identity)
        self.assertIsNotNone(mapped_identity.current_raw_uid)

        # Refresh from should be now or in the future, allow some slack for time between request and this assertion
        one_minute_ago = datetime.now(timezone.utc) - timedelta(seconds=60)
        self.assertTrue(mapped_identity.refresh_from > one_minute_ago)

        unmapped_identity = response.unmapped_identities.get(dii)
        self.assertIsNone(unmapped_identity)

    def assert_unmapped(self, response, reason, dii):
        unmapped_identity = response.unmapped_identities.get(dii)
        self.assertEqual(reason, unmapped_identity.reason)

        mapped_identity = response.mapped_identities.get(dii)
        self.assertIsNone(mapped_identity)



if __name__ == '__main__':
    unittest.main()
