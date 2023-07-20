import unittest
from unittest.mock import patch

from test_utils import *
from uid2_client import *
from uid2_client.encryption import _encrypt_gcm, _decrypt_gcm
from uid2_client.euid_client_factory import EuidClientFactory
from uid2_client.uid2_client_factory import Uid2ClientFactory


class TestClient(unittest.TestCase):
    class MockPostResponse:
        def __init__(self, return_value):
            self.return_value = return_value

        def read(self):
            return base64.b64encode(self.return_value)

    def _make_post_response(self, request_data, response_payload):
        d = base64.b64decode(request_data)[1:]
        d = _decrypt_gcm(d, client_secret_bytes)
        nonce = d[8:16]

        payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
        payload += nonce
        payload += response_payload
        envelope = _encrypt_gcm(payload, None, client_secret_bytes)

        return self.MockPostResponse(envelope)

    def _get_post_refresh_keys_response(self, base_url, path, headers, data):
        response_payload = key_set_to_json_for_sharing([master_key, site_key]).encode()
        return self._make_post_response(data, response_payload)


    def _validate_master_and_site_key(self, keys):
        self.assertEqual(len(keys.values()), 2)

        master = keys.get_master_key(now)
        self.assertIsNotNone(master)
        self.assertIsInstance(master, EncryptionKey)
        self.assertEqual(164, master.key_id)
        self.assertEqual(-1, master.site_id)
        self.assertEqual(now - dt.timedelta(days=-1), master.created)
        self.assertEqual(now, master.activates)
        self.assertEqual(now + dt.timedelta(days=1), master.expires)
        self.assertEqual(master_secret, master.secret)
        self.assertEqual(1, master.keyset_id)

        site = keys.get(165)
        self.assertIsNotNone(site)
        self.assertIsInstance(master, EncryptionKey)
        self.assertEqual(-1, master.site_id)
        self.assertEqual(now - dt.timedelta(days=-1), master.created)
        self.assertEqual(now, master.activates)
        self.assertEqual(now + dt.timedelta(days=1), master.expires)
        self.assertEqual(master_secret, master.secret)
        self.assertEqual(1, master.keyset_id)

    @patch('uid2_client.client.post')
    def test_refresh(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()
        keys = client._keys
        self._validate_master_and_site_key(keys)

    def test_refresh_json(self):
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        keys_json = key_set_to_json_for_sharing([master_key, site_key])
        keys = client.refresh_json(keys_json)
        self._validate_master_and_site_key(keys)

    @patch('uid2_client.client.post')
    def test_encrypt_decrypt(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertIsNotNone(ad_token)
        self.assertIsInstance(ad_token, str)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid2)

    @patch('uid2_client.client.post')
    def test_can_decrypt_another_clients_encrypted_token(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        def get_post_refresh_keys_response_with_header(base_url, path, headers, data):
            response_payload = key_set_to_json_for_sharing_with_header('"default_keyset_id": 12345,', 4874,
                                                                       [master_key, site_key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_header
        receiving_client = Uid2ClientFactory.create("endpoint2", "authkey2", client_secret)
        receiving_client.refresh_keys()

        result = receiving_client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid2)

    @patch('uid2_client.client.post')
    def test_sharing_token_is_v4(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        contains_base_64_special_chars = "+" in ad_token or "/" in ad_token or "=" in ad_token
        self.assertFalse(contains_base_64_special_chars)

    @patch('uid2_client.client.post')
    def test_uid2_client_produces_uid2_token(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertEqual("A", ad_token[0])

    @patch('uid2_client.client.post')
    def test_euid_client_produces_euid_token(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = EuidClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)
        self.assertEqual("E", ad_token[0])

    @patch('uid2_client.client.post')
    def test_raw_uid_produces_correct_identity_type_in_token(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        self.assertEqual(IdentityType.Email,
                         get_token_identity_type("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=", client._keys))
        self.assertEqual(IdentityType.Phone,
                         get_token_identity_type("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ", client._keys))
        self.assertEqual(IdentityType.Email,
                         get_token_identity_type("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=", client._keys))
        self.assertEqual(IdentityType.Email,
                         get_token_identity_type("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", client._keys))
        self.assertEqual(IdentityType.Email,
                         get_token_identity_type("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", client._keys))

    @patch('uid2_client.client.post')
    def test_multiple_keys_per_keyset(self, mock_post):
        def get_post_refresh_keys_response_with_multiple_keys(base_url, path, headers, data):
            response_payload = key_set_to_json_for_sharing([master_key, site_key, master_key2, site_key2]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_multiple_keys
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid2)

    @patch('uid2_client.client.post')
    def test_cannot_encrypt_if_no_key_from_default_keyset(self, mock_post):
        def get_post_refresh_keys_response_with_no_default_keyset_key(base_url, path, headers, data):
            response_payload = key_set_to_json_for_sharing([master_key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_no_default_keyset_key
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
            self.assertTrue('No Site ID in keys' in context.exception)

    @patch('uid2_client.client.post')
    def test_cannot_encrypt_if_theres_no_default_keyset_header(self, mock_post):
        def get_post_refresh_keys_response_with_no_default_keyset_header(base_url, path, headers, data):
            response_payload = key_set_to_json_for_sharing_with_header("", site_id, [master_key, site_key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_no_default_keyset_header
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)

    @patch('uid2_client.client.post')
    def test_expiry_in_token_matches_expiry_in_response(self, mock_post):
        def get_post_refresh_keys_response_with_token_expiry(base_url, path, headers, data):
            response_payload = key_set_to_json_for_sharing_with_header('"default_keyset_id": 99999, '
                                                                       '"token_expiry_seconds": 2,', 99999, [master_key,
                                                                                                             site_key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_token_expiry
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        ad_token = client.encrypt(example_uid)

        result = client.decrypt(ad_token)
        self.assertEqual(example_uid, result.uid2)

        real_decrypt_v3 = encryption._decrypt_token_v3

        with patch('uid2_client.encryption._decrypt_token_v3') as mock_decrypt:
            def decrypt_side_effect(token_bytes, keys, now):
                return real_decrypt_v3(token_bytes, keys, now + dt.timedelta(seconds=3))

            mock_decrypt.side_effect = decrypt_side_effect

            with self.assertRaises(EncryptionError) as context:
                client.decrypt(ad_token)
                self.assertTrue('token expired' in context.exception)




    @patch('uid2_client.client.post')
    def test_encrypt_key_inactive(self, mock_post):
        def get_post_refresh_keys_response_with_key_inactive(base_url, path, headers, data):
            key = EncryptionKey(245, site_id, now, now + dt.timedelta(days=1), now + dt.timedelta(days=2), site_secret,
                                keyset_id=99999)
            response_payload = key_set_to_json_for_sharing([master_key, key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_key_inactive
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)

    @patch('uid2_client.client.post')
    def test_encrypt_key_expired(self, mock_post):
        def get_post_refresh_keys_response_with_key_expired(base_url, path, headers, data):
            key = EncryptionKey(245, site_id, now, now, now - dt.timedelta(days=1), site_secret, keyset_id=99999)
            response_payload = key_set_to_json_for_sharing([master_key, key]).encode()
            return self._make_post_response(data, response_payload)

        mock_post.side_effect = get_post_refresh_keys_response_with_key_expired
        client = Uid2ClientFactory.create("base_url", "api_key", client_secret)
        client.refresh_keys()

        with self.assertRaises(EncryptionError) as context:
            client.encrypt(example_uid)
            self.assertTrue('No Keyset Key Found' in context.exception)
