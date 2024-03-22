import unittest
from unittest.mock import patch

from uid2_client import SharingClient, ClientType
from test_utils import *


class TestSharingClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    @patch('uid2_client.sharing_client.refresh_sharing_keys')
    @patch('uid2_client.sharing_client.encrypt')
    def test_encrypt_raw_uid_into_sharing_token(self, mock_encrypt, mock_refresh_sharing_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_sharing_keys.return_value = key_collection
        mock_encrypt.return_value = 'encrypted_token'
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        encrypted_token = client.encrypt_raw_uid_into_sharing_token(example_uid, key_collection.get_default_keyset_id())
        self.assertEqual(encrypted_token, 'encrypted_token')
        mock_refresh_sharing_keys.assert_called_once()
        mock_encrypt.assert_called_once_with(example_uid, None, key_collection, key_collection.get_default_keyset_id())

    @patch('uid2_client.sharing_client.refresh_sharing_keys')
    @patch('uid2_client.sharing_client.decrypt_token')
    def test_decrypt_sharing_token_into_raw_uid(self, mock_decrypt_token, mock_refresh_sharing_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_sharing_keys.return_value = key_collection
        mock_decrypt_token.return_value = example_uid
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        raw_uid = client.decrypt_sharing_token_into_raw_uid('token')
        self.assertEqual(raw_uid, example_uid)
        mock_refresh_sharing_keys.assert_called_once()
        mock_decrypt_token.assert_called_once_with('token', key_collection, None, ClientType.Sharing)

    @patch('uid2_client.sharing_client.refresh_sharing_keys')
    def test_refresh_keys(self, mock_refresh_sharing_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_sharing_keys.return_value = key_collection
        client = SharingClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        mock_refresh_sharing_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                          client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
