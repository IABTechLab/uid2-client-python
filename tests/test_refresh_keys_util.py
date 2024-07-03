import json
import unittest
from unittest.mock import patch

from uid2_client import refresh_keys_util
from test_utils import *
from uid2_client.encryption import _encrypt_gcm, _decrypt_gcm


class TestRefreshKeysUtil(unittest.TestCase):
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

    @patch('uid2_client.refresh_keys_util.post')
    def test_refresh_sharing_keys(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        refresh_response = refresh_keys_util.refresh_sharing_keys("base_url", "auth_key", base64.b64decode(client_secret))
        self.assertTrue(refresh_response.success)
        self._validate_master_and_site_key(refresh_response.keys)
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0], ('base_url', '/v2/key/sharing'))

    @patch('uid2_client.refresh_keys_util.post')
    def test_refresh_bidstream_keys(self, mock_post):
        mock_post.side_effect = self._get_post_refresh_keys_response
        refresh_response = refresh_keys_util.refresh_bidstream_keys("base_url", "auth_key", base64.b64decode(client_secret))
        self.assertTrue(refresh_response.success)
        self._validate_master_and_site_key(refresh_response.keys)
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0], ('base_url', '/v2/key/bidstream'))

    def test_parse_keys_json_identity(self):
        response_body_str = key_set_to_json_for_sharing([master_key, site_key])
        response = json.loads(response_body_str)
        response_body = response.get('body')
        response_body['identity_scope'] = 'EUID'
        response_body['caller_site_id'] = '1'
        response_body['master_keyset_id'] = master_key.keyset_id
        response_body['default_keyset_id'] = site_key.keyset_id
        response_body['token_expiry_seconds'] = '400'
        response_body['max_bidstream_lifetime_seconds'] = '100'
        response_body['max_sharing_lifetime_seconds'] = '200'
        response_body['allow_clock_skew_seconds'] = '300'
        refresh_response = refresh_keys_util.parse_keys_json(response_body)
        self.assertTrue(refresh_response.success)
        keys = refresh_response.keys
        self.assertIsNotNone(keys)
        self.assertEqual(IdentityScope.EUID, keys.get_identity_scope())
        self.assertEqual('1', keys.get_caller_site_id())
        self.assertEqual(master_key.keyset_id, keys.get_master_keyset_id())
        self.assertEqual(site_key.keyset_id, keys.get_default_keyset_id())
        self.assertEqual('400', keys.get_token_expiry_seconds())
        self.assertEqual('100', keys.get_max_bidstream_lifetime_seconds())
        self.assertEqual('200', keys.get_max_sharing_lifetime_seconds())
        self.assertEqual('300', keys.get_allow_clock_skew_seconds())


if __name__ == '__main__':
    unittest.main()
