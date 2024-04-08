import json
import unittest
from unittest.mock import patch

from test_utils import *
from tests.test_bidstream_client import TestBidStreamClient
from tests.test_encryption import TestEncryptionFunctions
from uid2_client import SharingClient, DecryptionStatus, Uid2ClientFactory
from uid2_client.encryption_status import EncryptionStatus
from uid2_client.refresh_response import RefreshResponse


def get_keyset_id(key):
    if key.site_id == -1:
        return 1
    elif key.site_id == site_id:
        return 99999
    else:
        return key.site_id


def encode_keys(keys):
    key_json = []
    for key in keys:
        encoded_key = {
            "id": key.key_id,
            "keyset_id": get_keyset_id(key),
            "created": int(key.created.timestamp()),
            "activates": int(key.activates.timestamp()),
            "expires": int(key.expires.timestamp()),
            "secret": base64.b64encode(key.secret).decode("utf-8"),
            "unexpected_key_field": "123"
        }
        key_json.append(encoded_key)
    return key_json


def key_sharing_response_json(keys, identity_scope=IdentityScope.UID2, caller_site_id=site_id, default_keyset_id=None, token_expiry_seconds=2592000):
    encoded_keys = encode_keys(keys)
    json_obj = {
        "body": {
            "caller_site_id": caller_site_id,
            "master_keyset_id": 1,
            "token_expiry_seconds": token_expiry_seconds,
            "identity_scope": identity_scope.name,
            "allow_clock_skew_seconds": 1800,  # 30 mins
            "max_sharing_lifetime_seconds": dt.timedelta(days=30).total_seconds(),
            "keys": encoded_keys,
            "unexpected_header_field": 12345  # ensure new fields can be handled by old SDK versions
        }
    }
    if default_keyset_id is not None:
        json_obj["body"]["default_keyset_id"] = default_keyset_id
    return json.dumps(json_obj)


def key_sharing_response_json_default_keys(identity_scope=IdentityScope.UID2):
    return key_sharing_response_json([master_key, site_key], identity_scope)


def keyset_to_json_for_sharing(keys=None, identity_scope=IdentityScope.UID2):
    if keys is None:
        keys = [master_key, site_key]
    return key_sharing_response_json(keys, identity_scope, caller_site_id=site_id,
                                     default_keyset_id=99999)


class TestSharingClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'
    _test_bidstream_client = TestBidStreamClient()

    def setUp(self):
        self._client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

    def decrypt_and_assert_success(self, token, token_version, scope):
        decrypted = self._client.decrypt_token_into_raw_uid(token)
        self._test_bidstream_client.assert_success(decrypted, token_version, scope)

    def test_smoke_test(self):  # SmokeTest
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version)
                refresh_response = self._client._refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                self.decrypt_and_assert_success(token, expected_version, expected_scope)

    def test_token_lifetime_too_long_for_sharing(self):  # TokenLifetimeTooLongForSharing
        expires_in_sec = dt.datetime.now(tz=timezone.utc) + dt.timedelta(days=31)
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                refresh_response = self._client._refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                result = self._client.decrypt_token_into_raw_uid(token)
                self._test_bidstream_client.assert_fails(result, expected_version, expected_scope)

    def test_token_generated_in_the_future_to_simulate_clock_skew(self):  # TokenGeneratedInTheFutureToSimulateClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=31)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                refresh_response = self._client._refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                result = self._client.decrypt_token_into_raw_uid(token)
                self._test_bidstream_client.assert_fails(result, expected_version, expected_scope)

    def test_token_generated_in_the_future_within_allowed_clock_skew(self):  # TokenGeneratedInTheFutureWithinAllowedClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=29)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=created_at_future)
                refresh_response = self._client._refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                self.decrypt_and_assert_success(token, expected_version, expected_scope)

    def test_phone_uids(self):  # PhoneTest
        for expected_scope, expected_version in test_cases_all_scopes_v3_v4_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                refresh_response = self._client._refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                self.assertTrue(refresh_response.success)
                token = generate_uid_token(expected_scope, expected_version, phone_uid)
                self.assertEqual(IdentityType.Phone, get_identity_type(token))
                result = self._client.decrypt_token_into_raw_uid(token)
                self.assertIsNotNone(result)
                self.assertEqual(result.uid, phone_uid)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    def test_legacy_response_from_old_operator(self):
        test_cases = [AdvertisingTokenVersion.ADVERTISING_TOKEN_V2,
                      AdvertisingTokenVersion.ADVERTISING_TOKEN_V3,
                      AdvertisingTokenVersion.ADVERTISING_TOKEN_V4]
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, site_key]))
        self.assertTrue(refresh_response.success)
        for token_version in test_cases:
            with self.subTest(token_version=token_version):
                token = generate_uid_token(IdentityScope.UID2, token_version)
                self.decrypt_and_assert_success(token, token_version, IdentityScope.UID2)

    def test_token_generated_in_the_future_legacy_client(self):  # TokenGeneratedInTheFutureLegacyClient
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=3)  # max allowed clock skew is 30m
        legacy_client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                legacy_client.refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                result = legacy_client.decrypt(token)
                self._test_bidstream_client.assert_success(result, expected_version, expected_scope)

    def test_token_lifetime_too_long_legacy_client(self):  # TokenLifetimeTooLongLegacyClient
        expires_in_sec = IN_3_DAYS + dt.timedelta(minutes=1)
        legacy_client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                legacy_client.refresh_json(key_sharing_response_json_default_keys(
                    expected_scope))
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                result = legacy_client.decrypt(token)
                self._test_bidstream_client.assert_success(result, expected_version, expected_scope)  # check skipped for legacy clients

    # Tests below taken from test_client.py related to Sharing

    def sharing_encrypt(self, identity_scope=IdentityScope.UID2):
        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_email_raw_uid2_v2)
        self.assertEqual(encryption_data_response.status, EncryptionStatus.SUCCESS)
        tester = TestEncryptionFunctions()
        tester.validate_advertising_token(encryption_data_response.encrypted_data, identity_scope, IdentityType.Email)
        return encryption_data_response.encrypted_data

    def test_client_produces_token_with_correct_prefix(self):  #ClientProducesTokenWithCorrectPrefix
        for expected_scope in [IdentityScope.UID2, IdentityScope.EUID]:
            with self.subTest(expected_scope=expected_scope):
                refresh_response = self._client._refresh_json(keyset_to_json_for_sharing(identity_scope=expected_scope))
                self.assertTrue(refresh_response.success)
                self.sharing_encrypt(expected_scope)

    def sharing_setup_and_encrypt(self):
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, site_key]))
        self.assertTrue(refresh_response.success)
        return self.sharing_encrypt()

    def test_can_encrypt_decrypt_for_sharing(self):  #CanEncryptAndDecryptForSharing
        token = self.sharing_setup_and_encrypt()
        decryption_response = self._client.decrypt_token_into_raw_uid(token)
        self.assertTrue(decryption_response.success)
        self.assertEqual(example_email_raw_uid2_v2, decryption_response.uid)

    def test_can_decrypt_another_clients_encrypted_token(self):  #CanDecryptAnotherClientsEncryptedToken
        token = self.sharing_setup_and_encrypt()

        receiving_client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        refresh_response = receiving_client._refresh_json(key_sharing_response_json([master_key, site_key], IdentityScope.UID2,
                                                                                    caller_site_id=4874, default_keyset_id=12345))
        self.assertTrue(refresh_response.success)

        result = receiving_client.decrypt_token_into_raw_uid(token)
        self.assertTrue(result.success)
        self.assertEqual(example_uid, result.uid)

    def test_sharing_token_is_v4(self):  # SharingTokenIsV4
        token = self.sharing_setup_and_encrypt()
        contains_base_64_special_chars = "+" in token or "/" in token or "=" in token
        self.assertFalse(contains_base_64_special_chars)

    def test_uid2_client_produces_uid2_token(self):  # Uid2ClientProducesUid2Token
        token = self.sharing_setup_and_encrypt()
        self.assertEqual("A", token[0])

    def test_raw_uid_produces_correct_identity_type_in_token(self):  #RawUidProducesCorrectIdentityTypeInToken
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing())
        self.assertTrue(refresh_response.success)
        raw_uids = [[IdentityType.Email, "Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk="],  # v2 +12345678901
                    [IdentityType.Phone, "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ"],  # v3 +12345678901
                    [IdentityType.Email, "oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs="],  # v2 test@example.com
                    [IdentityType.Email, "AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb"],  # v3 test@example.com
                    [IdentityType.Email, "EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb"]   # v3 EUID test@example.com
        ]
        for identity_type, raw_uid in raw_uids:
            with self.subTest(identity_type, raw_uid=raw_uid):
                encrypt_response = self._client.encrypt_raw_uid_into_token(raw_uid)
                self.assertEqual(encrypt_response.status, EncryptionStatus.SUCCESS)
                self.assertEqual(raw_uid, self._client.decrypt_token_into_raw_uid(encrypt_response.encrypted_data).uid)
                first_char = encrypt_response.encrypted_data[0]
                if 'A' == first_char or 'E' == first_char:
                    actual_identity_type = IdentityType.Email
                elif 'F' == first_char or 'B' == first_char:
                    actual_identity_type = IdentityType.Phone
                else:
                    raise Exception("unknown IdentityType")
                self.assertEqual(identity_type, actual_identity_type)

    def test_multiple_keys_per_keyset(self):  # MultipleKeysPerKeyset
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, master_key2, site_key, site_key2]))
        self.assertTrue(refresh_response.success)

        sharing_token = self._client.encrypt_raw_uid_into_token(example_uid)

        result = self._client.decrypt_token_into_raw_uid(sharing_token.encrypted_data)
        self.assertTrue(result.success)
        self.assertEqual(example_uid, result.uid)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self):  #CannotEncryptIfNoKeyFromTheDefaultKeyset
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key]))
        self.assertTrue(refresh_response.success)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    def test_cannot_encrypt_if_theres_no_default_keyset_header(self):  #CannotEncryptIfTheresNoDefaultKeysetHeader
        refresh_response = self._client._refresh_json(key_sharing_response_json([master_key, site_key], identity_scope=IdentityScope.UID2))
        self.assertTrue(refresh_response.success)
        self._client.encrypt_raw_uid_into_token(example_uid)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    def test_expiry_in_token_matches_expiry_in_response(self):  # ExpiryInTokenMatchesExpiryInResponse
        refresh_response = self._client._refresh_json(
            key_sharing_response_json([master_key, site_key], identity_scope=IdentityScope.UID2,
                                      default_keyset_id=99999, token_expiry_seconds=2))
        self.assertTrue(refresh_response.success)

        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(encryption_data_response.status, EncryptionStatus.SUCCESS)

        result = self._client._decrypt_token_into_raw_uid(encryption_data_response.encrypted_data, now + dt.timedelta(seconds=1))
        self.assertTrue(result.status)
        self.assertEqual(example_uid, result.uid)

        future_decryption_result = self._client._decrypt_token_into_raw_uid(encryption_data_response.encrypted_data, now + dt.timedelta(seconds=3))
        self.assertFalse(future_decryption_result.success)
        self.assertEqual(DecryptionStatus.EXPIRED_TOKEN, future_decryption_result.status)
        self.assertEqual(now + dt.timedelta(seconds=2), future_decryption_result.expiry)

    def test_encrypt_key_expired(self):  #EncryptKeyExpired
        expired_key = EncryptionKey(site_key_id, site_id, created=now, activates=now, expires=YESTERDAY, secret=site_secret)
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, expired_key]))
        self.assertTrue(refresh_response.success)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    def test_encrypt_key_inactive(self):  #EncryptKeyInactive
        inactive_key = EncryptionKey(site_key_id, site_id, now, TOMORROW, IN_2_DAYS, site_secret)
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, inactive_key]))
        self.assertTrue(refresh_response.success)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    def test_encrypt_site_key_expired(self):  #EncryptSiteKeyExpired
        expired_key = EncryptionKey(site_key_id, site_id, created=now, activates=now, expires=YESTERDAY, secret=site_secret)
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, expired_key]))
        self.assertTrue(refresh_response.success)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    def test_encrypt_site_key_inactive(self):  #EncryptSiteKeyInactive
        inactive_key = EncryptionKey(site_key_id, site_id, now, TOMORROW, IN_2_DAYS, site_secret)
        refresh_response = self._client._refresh_json(keyset_to_json_for_sharing([master_key, inactive_key]))
        self.assertTrue(refresh_response.success)

        result = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(result.status, EncryptionStatus.NOT_AUTHORIZED_FOR_KEY)

    @patch('uid2_client.sharing_client.refresh_sharing_keys')
    def test_refresh_keys(self, mock_refresh_sharing_keys):
        mock_refresh_sharing_keys.return_value = RefreshResponse.make_success(create_default_key_collection([master_key]))
        self._client.refresh()
        mock_refresh_sharing_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                          client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
