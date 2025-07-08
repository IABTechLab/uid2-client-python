import os
import unittest
from urllib.error import HTTPError

from uid2_client import SharingClient, Uid2PublisherClient, TokenGenerateInput, EncryptionStatus, BidstreamClient


@unittest.skipIf(
    os.getenv("UID2_BASE_URL") is None
    or os.getenv("UID2_API_KEY") is None
    or os.getenv("UID2_SECRET_KEY") is None,
    "Environment variables UID2_BASE_URL, UID2_API_KEY, and UID2_SECRET_KEY must be set",
)
class SharingClientIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.UID2_BASE_URL = os.getenv("UID2_BASE_URL")
        cls.UID2_API_KEY = os.getenv("UID2_API_KEY")
        cls.UID2_SECRET_KEY = os.getenv("UID2_SECRET_KEY")

        if cls.UID2_BASE_URL and cls.UID2_API_KEY and cls.UID2_SECRET_KEY:
            cls.sharing_client = SharingClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
            cls.publisher_client = Uid2PublisherClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
            cls.bidstream_client = BidstreamClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
        else:
            raise Exception("set the required UID2_BASE_URL/UID2_API_KEY/UID2_SECRET_KEY environment variables first")

    def test_sharing_client_key_refresh(self):
        refresh_response = self.sharing_client.refresh()
        self.assertTrue(refresh_response.success)

    def test_sharing_client_encrypt_decrypt_raw_uid(self):
        # Get raw uid
        token_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("hopefully-not-opted-out@example.com").do_not_generate_tokens_for_opted_out()
        )
        identity = token_response.get_identity()

        self.bidstream_client.refresh()
        decrypted_token = self.bidstream_client.decrypt_token_into_raw_uid(identity.get_advertising_token(), "example.com")
        self.assertTrue(decrypted_token.success)
        raw_uid = decrypted_token.uid
        
        # Refresh keys first
        refresh_response = self.sharing_client.refresh()
        self.assertTrue(refresh_response.success)

        # Encrypt the raw UID
        encryption_response = self.sharing_client.encrypt_raw_uid_into_token(raw_uid)
        self.assertTrue(encryption_response.success)
        self.assertIsNotNone(encryption_response.encrypted_data)
        
        # Now decrypt the encrypted token
        decryption_response = self.sharing_client.decrypt_token_into_raw_uid(
            encryption_response.encrypted_data
        )
        self.assertTrue(decryption_response.success)
        self.assertEqual(decryption_response.uid, raw_uid)

    def test_sharing_client_encrypt_with_invalid_raw_uid(self):
        refresh_response = self.sharing_client.refresh()
        self.assertTrue(refresh_response.success)

        invalid_raw_uid = "invalid_raw_uid"
        encryption_response = self.sharing_client.encrypt_raw_uid_into_token(invalid_raw_uid)

        self.assertFalse(encryption_response.success)

    def test_sharing_client_decrypt_with_invalid_token(self):
        refresh_response = self.sharing_client.refresh()
        self.assertTrue(refresh_response.success)

        invalid_token = "invalid-token"
        decryption_response = self.sharing_client.decrypt_token_into_raw_uid(invalid_token)

        self.assertFalse(decryption_response.success)

    def test_sharing_client_without_refresh(self):
        fresh_client = SharingClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)

        token_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("hopefully-not-opted-out@example.com").do_not_generate_tokens_for_opted_out()
        )
        identity = token_response.get_identity()
        self.bidstream_client.refresh()
        decrypted_token = self.bidstream_client.decrypt_token_into_raw_uid(identity.get_advertising_token(), "example.com")
        self.assertTrue(decrypted_token.success)
        raw_uid = decrypted_token.uid

        encryption_response = fresh_client.encrypt_raw_uid_into_token(raw_uid)

        self.assertFalse(encryption_response.success)

    def test_sharing_client_error_handling(self):
        bad_client = SharingClient(self.UID2_BASE_URL, "bad-api-key", self.UID2_SECRET_KEY)
        refresh_response = bad_client.refresh()
        self.assertFalse(refresh_response.success)

        bad_client = SharingClient(self.UID2_BASE_URL, self.UID2_API_KEY, "bad-secret-key")
        refresh_response = bad_client.refresh()
        self.assertFalse(refresh_response.success)

if __name__ == '__main__':
    unittest.main() 