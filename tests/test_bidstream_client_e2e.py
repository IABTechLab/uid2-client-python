import os
import unittest

from uid2_client import BidstreamClient, Uid2PublisherClient, TokenGenerateInput, DecryptionStatus


@unittest.skipIf(
    os.getenv("UID2_BASE_URL") is None
    or os.getenv("UID2_API_KEY") is None
    or os.getenv("UID2_SECRET_KEY") is None,
    "Environment variables UID2_BASE_URL, UID2_API_KEY, and UID2_SECRET_KEY must be set",
)
class BidstreamClientIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.UID2_BASE_URL = os.getenv("UID2_BASE_URL")
        cls.UID2_API_KEY = os.getenv("UID2_API_KEY")
        cls.UID2_SECRET_KEY = os.getenv("UID2_SECRET_KEY")

        if cls.UID2_BASE_URL and cls.UID2_API_KEY and cls.UID2_SECRET_KEY:
            cls.bidstream_client = BidstreamClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
            cls.publisher_client = Uid2PublisherClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
        else:
            raise Exception("set the required UID2_BASE_URL/UID2_API_KEY/UID2_SECRET_KEY environment variables first")

    def test_bidstream_client_key_refresh(self):
        refresh_response = self.bidstream_client.refresh()
        self.assertTrue(refresh_response.success)

    def test_bidstream_client_with_generated_token(self):
        token_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("hopefully-not-opted-out@example.com").do_not_generate_tokens_for_opted_out()
        )
        identity = token_response.get_identity()

        advertising_token = identity.get_advertising_token()
        self.assertIsNotNone(advertising_token)

        refresh_response = self.bidstream_client.refresh()
        self.assertTrue(refresh_response.success)

        decryption_response = self.bidstream_client.decrypt_token_into_raw_uid(
            advertising_token, "example.com"
        )

        self.assertTrue(decryption_response.success)
        self.assertIsNotNone(decryption_response.uid)
        self.assertIsNotNone(decryption_response.established)
        self.assertIsNotNone(decryption_response.site_id)

    def test_bidstream_client_with_invalid_token(self):
        refresh_response = self.bidstream_client.refresh()
        self.assertTrue(refresh_response.success)

        invalid_token = "invalid-token"
        decryption_response = self.bidstream_client.decrypt_token_into_raw_uid(
            invalid_token, "example.com"
        )
        self.assertFalse(decryption_response.success)

    def test_bidstream_client_without_refresh(self):
        token_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("hopefully-not-opted-out@example.com").do_not_generate_tokens_for_opted_out()
        )
        identity = token_response.get_identity()
        advertising_token = identity.get_advertising_token()

        fresh_client = BidstreamClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)

        decryption_response = fresh_client.decrypt_token_into_raw_uid(
            advertising_token, "example.com"
        )
        self.assertFalse(decryption_response.success)

    def test_bidstream_client_error_handling(self):
        bad_client = BidstreamClient(self.UID2_BASE_URL, "bad-api-key", self.UID2_SECRET_KEY)
        refresh_response = bad_client.refresh()
        self.assertFalse(refresh_response.success)

        bad_client = BidstreamClient(self.UID2_BASE_URL, self.UID2_API_KEY, "bad-secret-key")
        refresh_response = bad_client.refresh()
        self.assertFalse(refresh_response.success)

    def test_bidstream_client_phone_token_decryption(self):
        token_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_phone("+12345678901").do_not_generate_tokens_for_opted_out()
        )
        self.assertFalse(token_response.is_optout())
        
        identity = token_response.get_identity()
        advertising_token = identity.get_advertising_token()

        refresh_response = self.bidstream_client.refresh()
        self.assertTrue(refresh_response.success)

        decryption_response = self.bidstream_client.decrypt_token_into_raw_uid(
            advertising_token, "example.com"
        )

        self.assertTrue(decryption_response.success)
        self.assertIsNotNone(decryption_response.uid)


if __name__ == '__main__':
    unittest.main() 