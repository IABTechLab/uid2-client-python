import json
import unittest
from unittest.mock import patch

from test_utils import *
from uid2_client import BidstreamClient, Uid2Base64UrlCoder, DecryptionStatus, Uid2ClientFactory
from uid2_client.refresh_response import RefreshResponse


def create_default_refresh_keys_success():
    return RefreshResponse.make_success(create_default_key_collection([master_key, site_key]))


def encode_keys(keys):
    key_json = []
    for key in keys:
        encoded_key = {
            "id": key.key_id,
            "created": int(key.created.timestamp()),
            "activates": int(key.activates.timestamp()),
            "expires": int(key.expires.timestamp()),
            "secret": base64.b64encode(key.secret).decode("utf-8"),
            "unexpected_key_field": "123"
        }
        key_json.append(encoded_key)
    return key_json


def key_bidstream_response_json(keys, identity_scope=IdentityScope.UID2):
    encoded_keys = encode_keys(keys)
    json_obj = {
        "body": {
            "max_bidstream_lifetime_seconds": dt.timedelta(days=3).total_seconds(),
            "identity_scope": identity_scope.name,
            "allow_clock_skew_seconds": 1800,  # 30 mins
            "keys": encoded_keys,
            "unexpected_header_field": 12345,  # ensure new fields can be handled by old SDK versions
            "site_data": [
                {
                    "id": site_id,
                    "domain_names": ["example.com", "example.org"],
                    "unexpected_domain_field": "123"  # ensure new fields can be handled by old SDK versions
                },
                {
                    "id": site_id2,
                    "domain_names": ["example.net", "example.edu"],
                    "unexpected_domain_field": "123"  # ensure new fields can be handled by old SDK versions
                }
            ]
        }
    }
    return json.dumps(json_obj)


def key_bidstream_response_json_default_keys(identity_scope=IdentityScope.UID2):
    return key_bidstream_response_json([master_key, site_key], identity_scope)


class TestBidStreamClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    def assert_success(self, decryption_response, token_version, scope):
        self.assertTrue(decryption_response.success)
        self.assertEqual(decryption_response.uid, example_uid)
        self.assertEqual(decryption_response.advertising_token_version, token_version)
        if (token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V3
                or token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4):
            self.assertEqual(decryption_response.identity_type, IdentityType.Email)
        else:
            self.assertEqual(decryption_response.identity_type, None)
        self.assertEqual(decryption_response.identity_scope, scope)
        self.assertEqual(decryption_response.is_client_side_generated, False)

    def assert_fails(self, decryption_response, token_version, scope):
        self.assertFalse(decryption_response.success)
        self.assertEqual(decryption_response.status, DecryptionStatus.INVALID_TOKEN_LIFETIME)
        self.assertEqual(decryption_response.advertising_token_version, token_version)
        self.assertEqual(decryption_response.identity_scope, scope)
        if (token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V3
                or token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4):
            self.assertEqual(decryption_response.identity_type, IdentityType.Email)

    def _decrypt_and_assert_success(self, token, token_version, scope):
        decrypted = self._client.decrypt_token_into_raw_uid(token, None)
        self.assert_success(decrypted, token_version, scope)

    def setUp(self):
        self._client = BidstreamClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

    def test_smoke_test(self):  # SmokeTest
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version)
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                self._decrypt_and_assert_success(token, expected_version, expected_scope)

    def test_phone_uids(self):  # PhoneTest
        for expected_scope, expected_version in test_cases_all_scopes_v3_v4_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                token = generate_uid_token(expected_scope, expected_version, phone_uid)
                self.assertEqual(IdentityType.Phone, get_identity_type(token))
                result = self._client.decrypt_token_into_raw_uid(token, None)
                self.assertIsNotNone(result)
                self.assertEqual(result.uid, phone_uid)
                self.assertEqual(result.identity_type, IdentityType.Phone)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    def test_token_lifetime_too_long_for_bidstream(self):  # TokenLifetimeTooLongForBidstream
        expires_in_sec = IN_3_DAYS + dt.timedelta(minutes=1)
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                result = self._client.decrypt_token_into_raw_uid(token, None)
                self.assert_fails(result, expected_version, expected_scope)

    def test_token_generated_in_the_future_to_simulate_clock_skew(self):  # TokenGeneratedInTheFutureToSimulateClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=31)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                result = self._client.decrypt_token_into_raw_uid(token, None)
                self.assert_fails(result, expected_version, expected_scope)
                self.assertEqual(result.status, DecryptionStatus.INVALID_TOKEN_LIFETIME)

    def test_token_generated_in_the_future_within_allowed_clock_skew(self):  # TokenGeneratedInTheFutureWithinAllowedClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=29)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=created_at_future)
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                self._decrypt_and_assert_success(token, expected_version, expected_scope)

    def test_legacy_response_from_old_operator(self):
        test_cases = [AdvertisingTokenVersion.ADVERTISING_TOKEN_V2,
                      AdvertisingTokenVersion.ADVERTISING_TOKEN_V3,
                      AdvertisingTokenVersion.ADVERTISING_TOKEN_V4]
        refresh_response = self._client._refresh_json(key_set_to_json_for_sharing([master_key, site_key]))
        self.assertTrue(refresh_response.success)
        for token_version in test_cases:
            with self.subTest(token_version=token_version):
                token = generate_uid_token(IdentityScope.UID2, token_version)
                self._decrypt_and_assert_success(token, token_version, IdentityScope.UID2)

    def test_token_generated_in_the_future_legacy_client(self):  # TokenGeneratedInTheFutureLegacyClient
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=3)  # max allowed clock skew is 30m
        legacy_client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                legacy_client.refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                result = legacy_client.decrypt(token)
                self.assert_success(result, expected_version, expected_scope)

    def test_token_lifetime_too_long_legacy_client(self):  # TokenLifetimeTooLongLegacyClient
        expires_in_sec = IN_3_DAYS + dt.timedelta(minutes=1)
        legacy_client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                legacy_client.refresh_json(key_bidstream_response_json_default_keys(
                    expected_scope))
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                result = legacy_client.decrypt(token)
                self.assert_success(result, expected_version, expected_scope)  # check skipped for legacy clients

    def test_identity_scope_and_types(self):  # IdentityScopeAndType_TestCases
        test_cases = [
            [example_email_raw_uid2_v2, IdentityScope.UID2, IdentityType.Email],
            [example_phone_raw_uid2_v2, IdentityScope.UID2, IdentityType.Phone],
            [example_email_raw_uid2_v2, IdentityScope.EUID, IdentityType.Email],
            [example_phone_raw_uid2_v2, IdentityScope.EUID, IdentityType.Phone]
        ]
        for uid, identity_scope, identity_type in test_cases:
            with self.subTest(identity_scope=identity_scope, identity_type=identity_type):
                token = generate_uid_token(identity_scope, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4)
                refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys(
                    identity_scope))
                self.assertTrue(refresh_response.success)
                self._decrypt_and_assert_success(token, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4, identity_scope)

    def test_empty_keys(self):  # EmptyKeyContainer
        token = generate_uid_token(IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3)
        result = self._client.decrypt_token_into_raw_uid(token, None)
        self.assertFalse(result.success)
        self.assertEqual(result.status, DecryptionStatus.NOT_INITIALIZED)

    def test_master_key_expired(self):  #ExpiredKeyContainer
        master_key_expired = EncryptionKey(master_key_id, -1, created=now, activates=now - dt.timedelta(hours=2),
                                           expires=now - dt.timedelta(hours=1), secret=master_secret, keyset_id=99999)
        site_key_expired = EncryptionKey(site_key_id, site_id, created=now, activates=now - dt.timedelta(hours=2),
                                         expires=now - dt.timedelta(hours=1), secret=site_secret, keyset_id=99999)

        refresh_response = self._client._refresh_json(key_bidstream_response_json(
            [master_key_expired, site_key_expired]))
        self.assertTrue(refresh_response.success)

        result = self._client.decrypt_token_into_raw_uid(example_uid, None)
        self.assertFalse(result.success)
        self.assertEqual(result.status, DecryptionStatus.KEYS_NOT_SYNCED)

    def test_not_authorized_for_master_key(self):  #NotAuthorizedForMasterKey

        another_master_key = EncryptionKey(master_key_id + site_key_id + 1, -1, created=now, activates=now, expires=now + dt.timedelta(hours=1), secret=master_secret)
        another_site_key = EncryptionKey(master_key_id + site_key_id + 2, site_id, created=now, activates=now, expires=now + dt.timedelta(hours=1), secret=site_secret)
        refresh_response = self._client._refresh_json(key_bidstream_response_json(
            [another_master_key, another_site_key]))
        self.assertTrue(refresh_response.success)
        token = generate_uid_token(IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4)

        result = self._client.decrypt_token_into_raw_uid(token, None)
        self.assertFalse(result.success)
        self.assertEqual(result.status, DecryptionStatus.NOT_AUTHORIZED_FOR_MASTER_KEY)

    def test_invalid_payload(self):  #InvalidPayload
        refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys())
        self.assertTrue(refresh_response.success)
        token = generate_uid_token(IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4)
        payload = Uid2Base64UrlCoder.decode(token)
        bad_token = base64.urlsafe_b64encode(payload[:0])

        result = self._client.decrypt_token_into_raw_uid(bad_token, None)
        self.assertFalse(result.success)
        self.assertEqual(result.status, DecryptionStatus.INVALID_PAYLOAD)

    def test_token_expiry_custom_decryption_time(self):  #TokenExpiryAndCustomNow
        refresh_response = self._client._refresh_json(key_bidstream_response_json_default_keys())
        self.assertTrue(refresh_response.success)

        expires_at = now - dt.timedelta(days=60)
        created_at = expires_at - dt.timedelta(minutes=1)
        token = generate_uid_token(IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4,
                                   created_at=created_at, expires_at=expires_at)
        result = self._client._decrypt_token_into_raw_uid(token, None, expires_at + dt.timedelta(seconds=1))
        self.assertFalse(result.success)
        self.assertEqual(result.status, DecryptionStatus.TOKEN_EXPIRED)
        self.assertEqual(result.expiry, expires_at)

        result = self._client._decrypt_token_into_raw_uid(token, None, expires_at - dt.timedelta(seconds=1))
        self.assertIsNotNone(result)
        self.assertEqual(result.identity_scope, IdentityScope.UID2)
        self.assertEqual(result.advertising_token_version, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4)

    @patch('uid2_client.bidstream_client.refresh_bidstream_keys')
    def test_refresh_keys(self, mock_refresh_bidstream_keys):
        mock_refresh_bidstream_keys.return_value = RefreshResponse.make_success(create_default_key_collection([master_key]))
        self._client.refresh()
        mock_refresh_bidstream_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                            client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
