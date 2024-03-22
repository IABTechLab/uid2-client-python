import unittest
from unittest.mock import patch

from uid2_client import BidStreamClient, ClientType
from test_utils import *


class TestBidStreamClient(unittest.TestCase):
    _CONST_BASE_URL = 'base_url'
    _CONST_API_KEY = 'api_key'

    @patch('uid2_client.bid_stream_client.refresh_bidstream_keys')
    @patch('uid2_client.bid_stream_client.decrypt_token')
    def test_decrypt_ad_token_into_raw_uid(self, mock_decrypt_token, mock_refresh_bidstream_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_bidstream_keys.return_value = key_collection
        mock_decrypt_token.return_value = 'decrypted_token'
        client = BidStreamClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        decrypted_token = client.decrypt_ad_token_into_raw_uid('token', 'domain_app_name')
        self.assertEqual(decrypted_token, 'decrypted_token')
        mock_refresh_bidstream_keys.assert_called_once()
        mock_decrypt_token.assert_called_once_with('token', key_collection, 'domain_app_name', ClientType.Bidstream)

    @patch('uid2_client.bid_stream_client.refresh_bidstream_keys')
    def test_refresh_keys(self, mock_refresh_bidstream_keys):
        key_collection = create_default_key_collection([master_key])
        mock_refresh_bidstream_keys.return_value = key_collection
        client = BidStreamClient(self._CONST_BASE_URL, self._CONST_API_KEY, client_secret)
        client.refresh_keys()
        mock_refresh_bidstream_keys.assert_called_once_with(self._CONST_BASE_URL, self._CONST_API_KEY,
                                                            client_secret_bytes)


if __name__ == '__main__':
    unittest.main()
