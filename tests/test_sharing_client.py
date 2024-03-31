import unittest
from unittest.mock import patch

from test_utils import *
from uid2_client import SharingClient, EncryptionError, DecryptionStatus
from uid2_client.encryption_status import EncryptionStatus


@patch('uid2_client.sharing_client.refresh_sharing_keys')
class TestSharingClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    def setUp(self):
        self._key_collection = create_key_collection(IdentityScope.UID2)
        self._client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)

    def test_smoke_test(self, mock_refresh_sharing_keys):  # SmokeTest
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version)
                mock_refresh_sharing_keys.return_value = create_key_collection(expected_scope)
                self._client.refresh()
                decrypted = self._client.decrypt_token_into_raw_uid(token)
                self.assertEqual(decrypted.identity_scope, expected_scope)
                self.assertEqual(decrypted.advertising_token_version, expected_version)
                self.assertEqual((now - decrypted.established).total_seconds(), 0)

    def test_token_lifetime_too_long_for_sharing(self, mock_refresh_sharing_keys):  # TokenLifetimeTooLongForSharing
        expires_in_sec = dt.datetime.now(tz=timezone.utc) + dt.timedelta(days=31)
        max_sharing_lifetime = dt.timedelta(days=30).total_seconds()
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=expires_in_sec)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400, max_sharing_lifetime)
                self._client.refresh()
                result = self._client.decrypt_token_into_raw_uid(token)
                self.assertFalse(result.success)
                self.assertEqual(DecryptionStatus.INVALID_TOKEN_LIFETIME, result.status)

    def test_token_generated_in_the_future_to_simulate_clock_skew(self, mock_refresh_sharing_keys):  # TokenGeneratedInTheFutureToSimulateClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=31)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, created_at=created_at_future)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                self._client.refresh()
                result = self._client.decrypt_token_into_raw_uid(token)
                self.assertFalse(result.success)
                self.assertEqual(DecryptionStatus.INVALID_TOKEN_LIFETIME, result.status)

    def test_token_generated_in_the_future_within_allowed_clock_skew(self, mock_refresh_sharing_keys):  # TokenGeneratedInTheFutureWithinAllowedClockSkew
        created_at_future = dt.datetime.now(tz=timezone.utc) + dt.timedelta(minutes=29)  #max allowed clock skew is 30m
        for expected_scope, expected_version in test_cases_all_scopes_all_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                token = generate_uid_token(expected_scope, expected_version, expires_at=created_at_future)
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                99999, 86400)
                self._client.refresh()
                result = self._client.decrypt_token_into_raw_uid(token)
                self.assertIsNotNone(result)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    def test_phone_uids(self, mock_refresh_sharing_keys):  # PhoneTest
        for expected_scope, expected_version in test_cases_all_scopes_v3_v4_versions:
            with self.subTest(expected_scope=expected_scope, expected_version=expected_version):
                mock_refresh_sharing_keys.return_value = EncryptionKeysCollection([master_key, site_key],
                                                                                  expected_scope, site_id, 1,
                                                                                  99999, 86400)
                self._client.refresh()
                token = generate_uid_token(expected_scope, expected_version, phone_uid)
                self.assertEqual(IdentityType.Phone, get_identity_type(token))
                result = self._client.decrypt_token_into_raw_uid(token)
                self.assertIsNotNone(result)
                self.assertEqual(result.uid, phone_uid)
                self.assertEqual(result.identity_scope, expected_scope)
                self.assertEqual(result.advertising_token_version, expected_version)

    # Tests below taken from test_client.py related to Sharing

    def test_sharing_client_produces_uid2_token(self, mock_refresh_keys_util):  #ClientProducesTokenWithCorrectPrefix
        mock_refresh_keys_util.return_value = self._key_collection
        self._client.refresh()

        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual("A", encryption_data_response.encrypted_data[0])

    def test_sharing_client_produces_euid_token(self, mock_refresh_keys_util):  #ClientProducesTokenWithCorrectPrefix
        mock_refresh_keys_util.return_value = create_key_collection(IdentityScope.EUID)
        self._client.refresh()

        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual("E", encryption_data_response.encrypted_data[0])

    def test_encrypt_decrypt(self, mock_refresh_sharing_keys):  #CanEncryptAndDecryptForSharing
        key_collection = self._key_collection
        mock_refresh_sharing_keys.return_value = key_collection

        self._client.refresh()
        sharing_token = self._client.encrypt_raw_uid_into_token(example_uid, key_collection.get_default_keyset_id())
        self.assertIsNotNone(sharing_token)
        # self.assertIsInstance(sharing_token, str)
        result = self._client.decrypt_token_into_raw_uid(sharing_token.encrypted_data)
        self.assertEqual(example_uid, result.uid)
        mock_refresh_sharing_keys.assert_called_once()

    def test_can_decrypt_another_clients_encrypted_token(self, mock_refresh_keys_util):  #CanDecryptAnotherClientsEncryptedToken
        mock_refresh_keys_util.return_value = self._key_collection
        sending_client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        sending_client.refresh()

        token = sending_client.encrypt_raw_uid_into_token(example_uid)

        receiving_client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        receiving_client.refresh()

        result = receiving_client.decrypt_token_into_raw_uid(token.encrypted_data)
        self.assertEqual(example_uid, result.uid)

    def test_sharing_token_is_v4(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = self._key_collection
        self._client.refresh()

        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_uid)
        token = encryption_data_response.encrypted_data
        contains_base_64_special_chars = "+" in token or "/" in token or "=" in token
        self.assertFalse(contains_base_64_special_chars)

    def test_raw_uid_produces_correct_identity_type_in_token(self, mock_refresh_keys_util):  #RawUidProducesCorrectIdentityTypeInToken
        mock_refresh_keys_util.return_value = self._key_collection
        self._client.refresh()
        raw_uids = [[IdentityType.Email, "Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk="],
                    [IdentityType.Phone, "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ"],
                    [IdentityType.Email, "oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs="],
                    [IdentityType.Email, "AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb"],
                    [IdentityType.Email, "EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb"]
        ]
        for identity_type, raw_uid  in raw_uids:
            with self.subTest(identity_type=identity_type, raw_uid=raw_uid):
                self.assertEqual(identity_type, get_identity_type(self._client.encrypt_raw_uid_into_token(
                    raw_uid).encrypted_data))

    def test_multiple_keys_per_keyset(self, mock_refresh_keys_util):  # MultipleKeysPerKeyset
        def get_post_refresh_keys_response_with_multiple_keys():
            return create_default_key_collection([master_key, site_key, master_key2, site_key2])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_multiple_keys()
        self._client.refresh()

        sharing_token = self._client.encrypt_raw_uid_into_token(example_uid)

        result = self._client.decrypt_token_into_raw_uid(sharing_token.encrypted_data)
        self.assertEqual(example_uid, result.uid)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self, mock_refresh_keys_util):  #CannotEncryptIfNoKeyFromTheDefaultKeyset
        def get_post_refresh_keys_response_with_no_default_keyset_key():
            return create_default_key_collection([master_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_key()
        self._client.refresh()

        with self.assertRaises(EncryptionError) as context:
            self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual('No Keyset Key Found', str(context.exception))

    def test_cannot_encrypt_if_theres_no_default_keyset_header(self, mock_refresh_keys_util):  #CannotEncryptIfTheresNoDefaultKeysetHeader
        def get_post_refresh_keys_response_with_no_default_keyset_header():
            key_set = [master_key, site_key]
            return EncryptionKeysCollection(key_set, IdentityScope.UID2, 9000, 1,
                                            "", 86400)

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_header()
        self._client.refresh()

        with self.assertRaises(EncryptionError) as context:
            self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual('No Keyset Key Found', str(context.exception))

    def test_expiry_in_token_matches_expiry_in_response(self, mock_refresh_keys_util):  # ExpiryInTokenMatchesExpiryInResponse

        mock_refresh_keys_util.return_value = create_default_key_collection([master_key, site_key])
        self._client.refresh()

        encryption_data_response = self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual(encryption_data_response.status, EncryptionStatus.SUCCESS)

        result = self._client._decrypt_token_into_raw_uid(encryption_data_response.encrypted_data, now + dt.timedelta(seconds=1))
        self.assertTrue(result.status)
        self.assertEqual(example_uid, result.uid)

        result = self._client._decrypt_token_into_raw_uid(encryption_data_response.encrypted_data, now + dt.timedelta(seconds=3))
        self.assertFalse(result.success)
        self.assertEqual(DecryptionStatus.TOKEN_EXPIRED, result.status)


    def test_encrypt_key_inactive(self, mock_refresh_keys_util):  #EncryptKeyInactive
        def get_post_refresh_keys_response_with_key_inactive():
            inactive_key = EncryptionKey(245, site_id, now, TOMORROW, IN_2_DAYS,
                                         site_secret, keyset_id=99999)
            return create_default_key_collection([inactive_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_inactive()
        self._client.refresh()

        with self.assertRaises(EncryptionError) as context:
            self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual('No Keyset Key Found', str(context.exception))

    def test_encrypt_key_expired(self, mock_refresh_keys_util):  #EncryptKeyExpired
        def get_post_refresh_keys_response_with_key_expired():
            expired_key = EncryptionKey(245, site_id, created=now, activates=now, expires=YESTERDAY, secret=site_secret,
                                        keyset_id=99999)
            return create_default_key_collection([expired_key])

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_expired()
        self._client.refresh()

        with self.assertRaises(EncryptionError) as context:
            self._client.encrypt_raw_uid_into_token(example_uid)
        self.assertEqual('No Keyset Key Found', str(context.exception))

    def test_refresh_keys(self, mock_refresh_sharing_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_sharing_keys.return_value = key_collection
        self._client.refresh()
        mock_refresh_sharing_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                          client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
