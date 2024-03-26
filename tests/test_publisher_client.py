import os
import unittest

from uid2_client import Uid2PublisherClient
from uid2_client import TokenGenerateInput
from uid2_client import TokenGenerateResponse
from uid2_client.identity_tokens import IdentityTokens
from urllib.request import HTTPError


class PublisherEuidIntegrationTests(unittest.TestCase):

    EUID_SECRET_KEY = None
    EUID_API_KEY = None
    EUID_BASE_URL = None

    publisher_client = None

    @classmethod
    def setUpClass(cls):
        cls.EUID_BASE_URL = os.getenv("EUID_BASE_URL")
        cls.EUID_API_KEY = os.getenv("EUID_API_KEY")
        cls.EUID_SECRET_KEY = os.getenv("EUID_SECRET_KEY")

        print(cls.EUID_BASE_URL, cls.EUID_API_KEY, cls.EUID_SECRET_KEY)

        if cls.EUID_BASE_URL and cls.EUID_API_KEY and cls.EUID_SECRET_KEY:
            cls.publisher_client = Uid2PublisherClient(cls.EUID_BASE_URL, cls.EUID_API_KEY, cls.EUID_SECRET_KEY)
        else:
            raise Exception("set the required EUID_BASE_URL/EUID_API_KEY/EUID_SECRET_KEY environment variables first")

    # this test requires these env vars to be configured: EUID_BASE_URL, EUID_API_KEY, EUID_SECRET_KEY
    def test_integration_tc_string(self):
        tc_string = "CPhJRpMPhJRpMABAMBFRACBoALAAAEJAAIYgAKwAQAKgArABAAqAAA"

        token_generate_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("user@example.com").with_transparency_and_consent_string(tc_string))
        self.assertFalse(token_generate_response.is_optout())

        identity = token_generate_response.get_identity()
        self.assertIsNotNone(identity)
        self.assertFalse(identity.is_due_for_refresh())
        self.assertIsNotNone(identity.get_advertising_token())
        self.assertIsNotNone(identity.get_refresh_token())
        self.assertIsNotNone(identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

    # this test requires these env vars to be configured: EUID_BASE_URL, EUID_API_KEY, EUID_SECRET_KEY
    def test_integration_tc_string_with_insufficient_consent(self):
        tc_string = "CPehXK9PehXK9ABAMBFRACBoADAAAEJAAIYgAKwAQAKgArABAAqAAA"
        with self.assertRaises(ValueError):
            self.publisher_client.generate_token(TokenGenerateInput.from_email("user@example.com").with_transparency_and_consent_string(tc_string))

    # this test requires these env vars to be configured: EUID_BASE_URL, EUID_API_KEY, EUID_SECRET_KEY
    def test_integration_optout_generate_token(self):
        publisher_client = Uid2PublisherClient(self.EUID_BASE_URL, self.EUID_API_KEY, self.EUID_SECRET_KEY)
        tc_string = "CPhJRpMPhJRpMABAMBFRACBoALAAAEJAAIYgAKwAQAKgArABAAqAAA"
        input = TokenGenerateInput.from_email("optout@example.com").do_not_generate_tokens_for_opted_out().with_transparency_and_consent_string(tc_string)
        token_generate_response = publisher_client.generate_token(input)
        self.assertTrue(token_generate_response.is_optout())
        self.assertFalse(token_generate_response.is_success())
        self.assertIsNone(token_generate_response.get_identity())

class PublisherUid2IntegrationTests(unittest.TestCase):

    UID2_SECRET_KEY = None
    UID2_API_KEY = None
    UID2_BASE_URL = None

    publisher_client = None

    @classmethod
    def setUpClass(cls):
        cls.UID2_BASE_URL = os.getenv("UID2_BASE_URL")
        cls.UID2_API_KEY = os.getenv("UID2_API_KEY")
        cls.UID2_SECRET_KEY = os.getenv("UID2_SECRET_KEY")

        print(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)

        if cls.UID2_BASE_URL and cls.UID2_API_KEY and cls.UID2_SECRET_KEY:
            cls.publisher_client = Uid2PublisherClient(cls.UID2_BASE_URL, cls.UID2_API_KEY, cls.UID2_SECRET_KEY)
        else:
            raise Exception("set the required UID2_BASE_URL/UID2_API_KEY/UID2_SECRET_KEY environment variables first")

    # this test requires these env vars to be configured: UID2_BASE_URL, UID2_API_KEY, UID2_SECRET_KEY
    def test_integration_generate_and_refresh(self):

        token_generate_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_email("test@example.com"))

        self.assertFalse(token_generate_response.is_optout())

        identity = token_generate_response.get_identity()
        self.assertIsNotNone(identity)
        self.assertFalse(identity.is_due_for_refresh())
        self.assertIsNotNone(identity.get_advertising_token())
        self.assertIsNotNone(identity.get_refresh_token())
        self.assertIsNotNone(identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

        token_refresh_response = self.publisher_client.refresh_token(identity)
        self.assertTrue(token_refresh_response.is_success())
        self.assertFalse(token_refresh_response.is_optout())
        self.assertIsNotNone(token_refresh_response.get_identity_json_string())

        refreshed_identity = token_refresh_response.get_identity()
        self.assertIsNotNone(refreshed_identity)
        self.assertFalse(refreshed_identity.is_due_for_refresh())
        self.assertIsNotNone(refreshed_identity.get_advertising_token())
        self.assertIsNotNone(refreshed_identity.get_refresh_token())
        self.assertIsNotNone(refreshed_identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

    # this test requires these env vars to be configured: UID2_BASE_URL, UID2_API_KEY, UID2_SECRET_KEY
    def test_integration_optout(self):

        token_generate_response = self.publisher_client.generate_token(TokenGenerateInput.from_email("refresh-optout@example.com").do_not_generate_tokens_for_opted_out())

        self.assertFalse(token_generate_response.is_optout())

        identity = token_generate_response.get_identity()
        self.assertIsNotNone(identity)
        self.assertFalse(identity.is_due_for_refresh())
        self.assertIsNotNone(identity.get_advertising_token())
        self.assertIsNotNone(identity.get_refresh_token())
        self.assertIsNotNone(identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

        token_refresh_response = self.publisher_client.refresh_token(identity)
        self.assertFalse(token_refresh_response.is_success())
        self.assertTrue(token_refresh_response.is_optout())
        self.assertIsNone(token_refresh_response.get_identity_json_string())
        self.assertIsNone(token_refresh_response.get_identity())

    # this test requires these env vars to be configured: UID2_BASE_URL, UID2_API_KEY, UID2_SECRET_KEY
    def test_integration_phone(self):

        token_generate_response = self.publisher_client.generate_token(
            TokenGenerateInput.from_phone("+12345678901"))

        self.assertFalse(token_generate_response.is_optout())
        identity = token_generate_response.get_identity()
        self.assertIsNotNone(identity)
        self.assertFalse(identity.is_due_for_refresh())
        self.assertIsNotNone(identity.get_advertising_token())
        self.assertIsNotNone(identity.get_refresh_token())
        self.assertIsNotNone(identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

        token_refresh_response = self.publisher_client.refresh_token(identity)
        self.assertTrue(token_refresh_response.is_success())
        self.assertFalse(token_refresh_response.is_optout())
        self.assertIsNotNone(token_refresh_response.get_identity_json_string())

        refreshed_identity = token_refresh_response.get_identity()
        self.assertIsNotNone(refreshed_identity)
        self.assertFalse(refreshed_identity.is_due_for_refresh())
        self.assertIsNotNone(refreshed_identity.get_advertising_token())
        self.assertIsNotNone(refreshed_identity.get_refresh_token())
        self.assertIsNotNone(refreshed_identity.get_json_string())
        self.assertTrue(identity.is_refreshable())

    # this test requires these env vars to be configured: UID2_BASE_URL, UID2_API_KEY, UID2_SECRET_KEY
    def test_integration_bad_requests(self):

        with self.assertRaises(ValueError):
            self.publisher_client.generate_token(TokenGenerateInput.from_email("this is not an email address"))

        with self.assertRaises(ValueError):
            self.publisher_client.generate_token(TokenGenerateInput.from_phone("this is not a phone number"))

        unnormalized_phone_number = " +123 44 55-66-77"
        with self.assertRaises(ValueError):
            self.publisher_client.generate_token(TokenGenerateInput.from_phone(unnormalized_phone_number))

        expired_respose = "{\"advertising_token\":\"AgAAAAN6QZRCFTau+sfOlMMUY2ftElFMq2TCrcu1EAaD9WmEfoT2BWm2ZKz1tumbT00tWLffRDQ/9POXfA0O/Ljszn7FLtG5EzTBM3HYs4f5irkqeEvu38DhVCxUEpI+gZZZkynRap1oYx6AmC/ip3rk+7pmqa3r3saDs1mPRSSTm+Nh6A==\",\"user_token\":\"AgAAAAL6aleYI4BubI5ZXMBshqmMEfCkbCJF4fLeg1sdI0BTLzj9sXsSISjkG0lMC743diC2NVy3ElkbO1lLysd+Lm6alkqevPrcuWDisQ1939YdoH6LqpwBH3FNSE4/xa3Q+94=\",\"refresh_token\":\"AAAAAARomrP3NjjH+8mt5djfTHbmRZXjOMnAN8WpjJoe30AhUCvYksO/xoDSj77GzWv4M99DhnPl2cVco8CZFTcE10nauXI4Barr890ILnH0IIacOei5Zjwh6DycFkoXkAAuHY1zjmxb7niGLfSP2RctWkZdRVGWQv/UW/grw6+paU9bnKEWPzVvLwwdW2NgjDKu+szE6A+b5hkY+I3voKoaz8/kLDmX8ddJGLy/YOh/LIveBspSAvEg+v89OuUCwAqm8L3Rt8PxDzDnt0U4Na+AUawvvfsIhmsn/zMpRRks6GHhIAB/EQUHID8TedU8Hv1WFRsiraG9Dfn1Kc5/uYnDJhEagWc+7RgTGT+U5GqI6+afrAl5091eBLbmvXnXn9ts\",\"identity_expires\":1668059799628,\"refresh_expires\":1668142599628,\"refresh_from\":1668056202628,\"refresh_response_key\":\"P941vVeuyjaDRVnFQ8DPd0AZnW4bPeiJPXER2K9QXcU=\"}"
        current_identity = IdentityTokens.from_json_string(expired_respose)
        with self.assertRaises(HTTPError):
            self.publisher_client.refresh_token(current_identity)

        with self.assertRaises(TypeError):
            self.publisher_client.generate_token(TokenGenerateInput.from_email(None))

        with self.assertRaises(AttributeError):
            self.publisher_client.refresh_token(None)

        bad_url_client = Uid2PublisherClient("https://www.something.com", self.UID2_API_KEY, self.UID2_SECRET_KEY)
        with self.assertRaises(HTTPError):
            bad_url_client.generate_token(TokenGenerateInput.from_email("test@example.com"))

        bad_secret_client = Uid2PublisherClient(self.UID2_BASE_URL, self.UID2_API_KEY, "badSecretKeypB64Y3fV2dAed8t/mupw3sjN5jNRFzg=")
        with self.assertRaises(HTTPError):
            bad_secret_client.generate_token(TokenGenerateInput.from_email("test@example.com"))

        bad_api_client = Uid2PublisherClient(self.UID2_BASE_URL, "not-real-key", self.UID2_SECRET_KEY)
        with self.assertRaises(HTTPError):
            bad_secret_client.generate_token(TokenGenerateInput.from_email("test@example.com"))


if __name__ == '__main__':
    unittest.main()
