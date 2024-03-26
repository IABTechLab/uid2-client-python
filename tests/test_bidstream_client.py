import unittest
from unittest.mock import patch

from uid2_client import BidStreamClient, ClientType, EncryptionError
from test_utils import *


@patch('uid2_client.bid_stream_client.refresh_bidstream_keys')
class TestBidStreamClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    def setUp(self):
        self._key_collection = create_key_collection(IdentityScope.UID2)
        self._client = BidStreamClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

    def test_smoke_test(self, mock_refresh_bidstream_keys):  # SmokeTest
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version)
                mock_refresh_bidstream_keys.return_value = create_key_collection(expected_scope)
                self._client.refresh_keys()
                decrypted = self._client.decrypt_ad_token_into_raw_uid(token, None)
                self.assertEqual(decrypted.identity_scope, expected_scope)
                self.assertEqual(decrypted.advertising_token_version, expected_version)

    def test_phone_uids(self, mock_refresh_bidstream_keys):  # PhoneTest
        for expected_scope, expected_version in test_cases_all_scopes_v3_v4_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                mock_refresh_bidstream_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                    expected_scope, site_id, 1,
                                                                                  99999, 86400)
                self._client.refresh_keys()
                token = generate_uid_token(expected_scope, expected_version, phone_uid)
                self.assertEqual(IdentityType.Phone, get_identity_type(token))
                result = self._client.decrypt_ad_token_into_raw_uid(token, None)
                self.assertIsNotNone(result)
                self.assertEqual(result.uid2, phone_uid)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    def test_token_lifetime_too_long_for_bidstream(self, mock_refresh_bidstream_keys):  # TokenLifetimeTooLongForBidstream
        expires_in_sec = IN_3_DAYS + dt.timedelta(minutes=1)
        max_bidstream_lifetime = dt.timedelta(days=3).total_seconds()
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                mock_refresh_bidstream_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                                                  99999, 86400,
                                                                                  max_bidstream_lifetime_seconds=max_bidstream_lifetime)
                self._client.refresh_keys()
                with self.assertRaises(EncryptionError):
                    self._client.decrypt_ad_token_into_raw_uid(token, None)

    def test_token_generated_in_the_future_to_simulate_clock_skew(self, mock_refresh_bidstream_keys):  # TokenGeneratedInTheFutureToSimulateClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=31)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                mock_refresh_bidstream_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                self._client.refresh_keys()
                with self.assertRaises(EncryptionError):
                    self._client.decrypt_ad_token_into_raw_uid(token, None)

    def test_token_generated_in_the_future_within_allowed_clock_skew(self, mock_refresh_bidstream_keys):  # TokenGeneratedInTheFutureWithinAllowedClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=29)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=created_at_future)
                mock_refresh_bidstream_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                self._client.refresh_keys()
                result = self._client.decrypt_ad_token_into_raw_uid(token, None)
                self.assertIsNotNone(result)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    def test_empty_keys(self, mock_refresh_bidstream_keys):  # EmptyKeyContainer
        token = generate_uid_token(IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3)
        mock_refresh_bidstream_keys.return_value = None
        self._client.refresh_keys()
        with self.assertRaises(EncryptionError):
            self._client.decrypt_ad_token_into_raw_uid(token, None)

    def test_master_key_expired(self, mock_refresh_keys_util):  #ExpiredKeyContainer
        def get_post_refresh_keys_response_with_key_expired():
            master_key_expired = EncryptionKey(master_key_id, site_id, created=now, activates=YESTERDAY, expires=YESTERDAY, secret=master_secret,
                                        keyset_id=99999)
            expired_key = EncryptionKey(site_key_id, site_id, created=now, activates=YESTERDAY, expires=YESTERDAY, secret=site_secret,
                                        keyset_id=99999)
            return create_default_key_collection([master_key, expired_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_expired()
        self._client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            self._client.decrypt_ad_token_into_raw_uid(example_uid, None)
            self.assertTrue('No Keyset Key Found' in context.exception)

    def test_refresh_keys(self, mock_refresh_bidstream_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_bidstream_keys.return_value = key_collection
        client = BidStreamClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        mock_refresh_bidstream_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                            client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
