import unittest
from unittest.mock import patch

from test_utils import *
from uid2_client import *
from uid2_client.euid_client_factory import EuidClientFactory
from uid2_client.refresh_response import RefreshResponse
from uid2_client.uid2_client_factory import Uid2ClientFactory


@patch('uid2_client.client.refresh_sharing_keys')
class TestClient(unittest.TestCase):

    _CONST_BASE_URL = "base_url"
    _CONST_API_KEY = "api_key"

    def setUp(self):
        key_set = [master_key, site_key]
        self._key_collection = EncryptionKeysCollection(key_set, IdentityScope.UID2, site_id, 1,
                                                        99999, 86400)

    def test_refresh(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        mock_refresh_keys_util.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY, base64.b64decode(client_secret))
        self.assertEqual(client._keys, self._key_collection)

    def test_refresh_fail(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_error('Exception msg')
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        with self.assertRaises(Exception) as context:
            client.refresh_keys()
        self.assertEqual(str(context.exception), 'Exception msg')

    @patch('uid2_client.client.parse_keys_json')
    def test_refresh_json(self, mock_refresh_keys, mock_parse_keys):
        mock_parse_keys.return_value = self._key_collection
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        keys = client.refresh_json("{\"body\":{\"obj1\":\"value\"}}")
        self.assertIsNotNone(keys)

    def test_encrypt_decrypt(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertIsNotNone(ad_token)
        self.assertIsInstance(ad_token, str)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid)

    def test_can_decrypt_another_clients_encrypted_token(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        receiving_client = Uid2ClientFactory.create("endpoint2", "authkey2", client_secret)
        receiving_client.refresh_keys()

        result = receiving_client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid)

    def test_sharing_token_is_v4(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        contains_base_64_special_chars = "+" in ad_token or "/" in ad_token or "=" in ad_token
        self.assertFalse(contains_base_64_special_chars)

    def test_uid2_client_produces_uid2_token(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertEqual("A", ad_token[0])

    def test_euid_client_produces_euid_token(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = EuidClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertEqual("E", ad_token[0])

    def test_raw_uid_produces_correct_identity_type_in_token(self, mock_refresh_keys_util):
        mock_refresh_keys_util.return_value = RefreshResponse.make_success(self._key_collection)
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        self.assertEqual(IdentityType.Email,
                         get_identity_type(client.encrypt("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=")))
        self.assertEqual(IdentityType.Phone,
                         get_identity_type(client.encrypt("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ")))
        self.assertEqual(IdentityType.Email,
                         get_identity_type(client.encrypt("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=")))
        self.assertEqual(IdentityType.Email,
                         get_identity_type(client.encrypt("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")))
        self.assertEqual(IdentityType.Email,
                         get_identity_type(client.encrypt("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb")))

    def test_multiple_keys_per_keyset(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_multiple_keys():
            return RefreshResponse.make_success(
                create_default_key_collection([master_key, site_key, master_key2, site_key2]))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_multiple_keys()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_no_default_keyset_key():
            return RefreshResponse.make_success(create_default_key_collection([master_key]))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_key()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
        self.assertEqual("No Keyset Key Found", str(context.exception))

    def test_cannot_encrypt_if_theres_no_default_keyset_header(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_no_default_keyset_header():
            key_set = [master_key, site_key]
            return RefreshResponse.make_success(EncryptionKeysCollection(key_set, IdentityScope.UID2, 9000, 1,
                                            "", 86400))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_no_default_keyset_header()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
        self.assertEqual("No Keyset Key Found", str(context.exception))

    def test_expiry_in_token_matches_expiry_in_response(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_token_expiry():
            return RefreshResponse.make_success(create_default_key_collection([master_key, site_key]))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_token_expiry()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid)

        real_decrypt_v3 = encryption._decrypt_token_v3

        with patch('uid2_client.encryption._decrypt_token_v3') as mock_decrypt:
            def decrypt_side_effect(token_bytes, keys, now):
                return real_decrypt_v3(token_bytes, keys, now + dt.timedelta(seconds=3))

            mock_decrypt.side_effect = decrypt_side_effect

            with self.assertRaises(EncryptionError) as context:
                client.decrypt(ad_token)
            self.assertEqual('invalid payload', str(context.exception))

    def test_encrypt_key_inactive(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_key_inactive():
            inactive_key = EncryptionKey(245, site_id, now, now + dt.timedelta(days=1), now + dt.timedelta(days=2),
                                         site_secret, keyset_id=99999)
            return RefreshResponse.make_success(create_default_key_collection([inactive_key]))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_inactive()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
        self.assertEqual(EncryptionStatus.NOT_AUTHORIZED_FOR_MASTER_KEY.value, str(context.exception))

    def test_encrypt_key_expired(self, mock_refresh_keys_util):
        def get_post_refresh_keys_response_with_key_expired():
            expired_key = EncryptionKey(245, site_id, now, now, now - dt.timedelta(days=1), site_secret,
                                        keyset_id=99999)
            return RefreshResponse.make_success(create_default_key_collection([expired_key]))

        mock_refresh_keys_util.return_value = get_post_refresh_keys_response_with_key_expired()
        client = Uid2ClientFactory.create(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
        self.assertEqual(EncryptionStatus.KEYS_NOT_SYNCED.value, str(context.exception))
