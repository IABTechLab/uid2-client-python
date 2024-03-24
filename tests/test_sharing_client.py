import unittest
from unittest.mock import patch

from tests.uid2_token_generator import UID2TokenGenerator
from uid2_client import SharingClient, ClientType, EncryptionError, encryption, AdvertisingTokenVersion
from test_utils import *


def _create_key_collection(identity_scope):
    key_set = [master_key, site_key]
    return EncryptionKeysCollection(key_set, identity_scope, site_id, 1,
                             99999, 86400)


def _generate_uid_token(identity_scope, version, created_at=None, expires_at=None):
    return UID2TokenGenerator.generate_uid_token(example_id, master_key, site_id, site_key,
                                                 identity_scope, version, created_at, expires_at)


@patch('uid2_client.sharing_client.refresh_sharing_keys')
class TestSharingClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    def setUp(self):
        self._key_collection = _create_key_collection(IdentityScope.UID2)
        self._test_cases = [
            [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V2],
            [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
            [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4],
            [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V2],
            [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
            [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4]
        ]

    def test_encrypt_decrypt(self, mock_refresh_sharing_keys):  #CanEncryptAndDecryptForSharing
        key_collection = self._key_collection
        mock_refresh_sharing_keys.return_value = key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        sharing_token = client.encrypt_raw_uid_into_sharing_token(example_uid, key_collection.get_default_keyset_id())
        self.assertIsNotNone(sharing_token)
        self.assertIsInstance(sharing_token, str)
        result = client.decrypt_sharing_token_into_raw_uid(sharing_token)
        self.assertEqual(example_uid, result.uid2)
        mock_refresh_sharing_keys.assert_called_once()

    def test_can_decrypt_another_clients_encrypted_token(self, mock_refresh_keys_util):  #CanDecryptAnotherClientsEncryptedToken
        mock_refresh_keys_util.return_value = self._key_collection
        sending_client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        sending_client.refresh_keys()

        ad_token = sending_client.encrypt_raw_uid_into_sharing_token(example_uid)

        receiving_client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        receiving_client.refresh_keys()

        result = receiving_client.decrypt_sharing_token_into_raw_uid(ad_token)
        self.assertEqual(example_uid, result.uid2)

    def test_sharing_token_is_v4(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = self._key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt_raw_uid_into_sharing_token(example_uid)
        contains_base_64_special_chars = "+" in ad_token or "/" in ad_token or "=" in ad_token
        self.assertFalse(contains_base_64_special_chars)

    def test_sharing_client_produces_uid2_token(self, mock_refresh_keys_util):  #ClientProducesTokenWithCorrectPrefix
        mock_refresh_keys_util.return_value = self._key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt_raw_uid_into_sharing_token(example_uid)
        self.assertEqual("A", ad_token[0])

    def test_sharing_client_produces_euid_token(self, mock_refresh_keys_util):  #ClientProducesTokenWithCorrectPrefix
        mock_refresh_keys_util.return_value = _create_key_collection(IdentityScope.EUID)
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt_raw_uid_into_sharing_token(example_uid)
        self.assertEqual("E", ad_token[0])

    def test_raw_uid_produces_correct_identity_type_in_token(self, mock_refresh_keys_util):  #RawUidProducesCorrectIdentityTypeInToken
        mock_refresh_keys_util.return_value = self._key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        self.assertEqual(IdentityType.Email, get_identity_type(client.encrypt_raw_uid_into_sharing_token(
            "Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=")))
        self.assertEqual(IdentityType.Phone, get_identity_type(client.encrypt_raw_uid_into_sharing_token(
            "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ")))
        self.assertEqual(IdentityType.Email, get_identity_type(client.encrypt_raw_uid_into_sharing_token(
            "oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=")))
        self.assertEqual(IdentityType.Email, get_identity_type(client.encrypt_raw_uid_into_sharing_token(
            "AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")))
        self.assertEqual(IdentityType.Email, get_identity_type(client.encrypt_raw_uid_into_sharing_token(
            "EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")))

    def test_multiple_keys_per_keyset(self, mock_refresh_keys_util):  # MultipleKeysPerKeyset
        def get_post_refresh_keys_response_with_multiple_keys():
            return create_default_key_collection([master_key, site_key, master_key2, site_key2])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_multiple_keys()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        sharing_token = client.encrypt_raw_uid_into_sharing_token(example_uid)

        result = client.decrypt_sharing_token_into_raw_uid(sharing_token)
        self.assertEqual(example_uid, result.uid2)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self, mock_refresh_keys_util):  #CannotEncryptIfNoKeyFromTheDefaultKeyset
        def get_post_refresh_keys_response_with_no_default_keyset_key():
            return create_default_key_collection([master_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_key()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt_raw_uid_into_sharing_token(example_uid)
            self.assertTrue('No Site ID in keys' in context.exception)

    def test_cannot_encrypt_if_theres_no_default_keyset_header(self, mock_refresh_keys_util):  #CannotEncryptIfTheresNoDefaultKeysetHeader
        def get_post_refresh_keys_response_with_no_default_keyset_header():
            key_set = [master_key, site_key]
            return EncryptionKeysCollection(key_set, IdentityScope.UID2, 9000, 1,
                                            "", 86400)

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_header()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt_raw_uid_into_sharing_token(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)

    def test_expiry_in_token_matches_expiry_in_response(self, mock_refresh_keys_util):  # ExpiryInTokenMatchesExpiryInResponse
        def get_post_refresh_keys_response_with_token_expiry():
            return create_default_key_collection([master_key, site_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_token_expiry()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt_raw_uid_into_sharing_token(example_uid)

        result = client.decrypt_sharing_token_into_raw_uid(ad_token)
        self.assertEqual(example_uid, result.uid2)

        real_decrypt_v3 = encryption._decrypt_token_v3

        with patch('uid2_client.encryption._decrypt_token_v3') as mock_decrypt:
            def decrypt_side_effect(token_bytes, keys, now):
                return real_decrypt_v3(token_bytes, keys, '', ClientType.Sharing, now + dt.timedelta(seconds=3), AdvertisingTokenVersion.ADVERTISING_TOKEN_V4)

            mock_decrypt.side_effect = decrypt_side_effect

            with self.assertRaises(EncryptionError) as context:
                client.decrypt_sharing_token_into_raw_uid(ad_token)
                self.assertTrue('token expired' in context.exception)

    def test_encrypt_key_inactive(self, mock_refresh_keys_util):  #EncryptKeyInactive
        def get_post_refresh_keys_response_with_key_inactive():
            inactive_key = EncryptionKey(245, site_id, now, now + dt.timedelta(days=1), now + dt.timedelta(days=2),
                                         site_secret, keyset_id=99999)
            return create_default_key_collection([inactive_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_inactive()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt_raw_uid_into_sharing_token(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)

    def test_encrypt_key_expired(self, mock_refresh_keys_util):  #EncryptKeyExpired
        def get_post_refresh_keys_response_with_key_expired():
            expired_key = EncryptionKey(245, site_id, now, now, now - dt.timedelta(days=1), site_secret,
                                        keyset_id=99999)
            return create_default_key_collection([expired_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_expired()
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt_raw_uid_into_sharing_token(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)

    def test_refresh_keys(self, mock_refresh_sharing_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_sharing_keys.return_value = key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        mock_refresh_sharing_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                          client_secret_bytes)

    def test_smoke_test(self, mock_refresh_sharing_keys):  # SmokeTest
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        for expected_scope, expected_version in self._test_cases:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = _generate_uid_token(expected_scope, expected_version, None)
                mock_refresh_sharing_keys.return_value = _create_key_collection(expected_scope)
                client.refresh_keys()
                decrypted = client.decrypt_sharing_token_into_raw_uid(token)
                self.assertEqual(decrypted.identity_scope, expected_scope)
                self.assertEqual(decrypted.advertising_token_version, expected_version)

    def test_token_lifetime_too_long_for_sharing(self, mock_refresh_sharing_keys):  # TokenLifetimeTooLongForSharing
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        expires_in_sec = dt.datetime.now(tz=timezone.utc) + dt.timedelta(days=31)
        max_sharing_lifetime = dt.timedelta(days=30).total_seconds()
        for expected_scope, expected_version in self._test_cases:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = _generate_uid_token(expected_scope, expected_version, expires_in_sec)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400, max_sharing_lifetime)
                client.refresh_keys()
                with self.assertRaises(EncryptionError):
                    client.decrypt_sharing_token_into_raw_uid(token)

    def test_token_generated_in_the_future_to_simulate_clock_skew(self, mock_refresh_sharing_keys):  # TokenGeneratedInTheFutureToSimulateClockSkew
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=31)  #max allowed clock skew is 30m
        for expected_scope, expected_version in self._test_cases:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = _generate_uid_token(expected_scope, expected_version, created_at_future)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                client.refresh_keys()
                with self.assertRaises(EncryptionError):
                    client.decrypt_sharing_token_into_raw_uid(token)

    def test_token_generated_in_the_future_within_allowed_clock_skew(self, mock_refresh_sharing_keys):  # TokenGeneratedInTheFutureWithinAllowedClockSkew
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=29)  #max allowed clock skew is 30m
        for expected_scope, expected_version in self._test_cases:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = _generate_uid_token(expected_scope, expected_version, created_at_future)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                client.refresh_keys()
                result = client.decrypt_sharing_token_into_raw_uid(token)
                self.assertIsNotNone(result)



if __name__ == '__main__':
    unittest.main()
