import unittest

from tests.uid2_token_generator import UID2TokenGenerator, Params
from uid2_client import *
import base64

_master_secret = bytes(
    [139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168,
     16, 169, 164, 38, 139, 8, 155])
_site_secret = bytes(
    [32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108,
     51, 254, 125, 65, 24, 23, 133])
_master_key_id = 164
_site_key_id = 165
_test_site_key_id = 166
_site_id = 9000
_site_id2 = 2

_example_id = 'ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM='
_now = dt.datetime.now(tz=timezone.utc)
_master_key = EncryptionKey(_master_key_id, -1, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1),
                            _master_secret, keyset_id=9999)
_site_key = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1),
                          _site_secret, keyset_id=99999)

_client_secret = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo="
_example_uid = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM="


class TestSharing(unittest.TestCase):
    def setup_sharing_and_encrypt(self, id_scope=IdentityScope.UID2):
        client = Uid2Client("endpoint", "key", _client_secret)
        json = self._key_set_to_json_for_sharing([_master_key, _site_key])
        keys = client.refresh_json(json)

        ad_token = encrypt(_example_uid, id_scope, keys)

        return ad_token, keys

    def _key_set_to_json_for_sharing(self, keys):
        return self._key_set_to_json_for_sharing_with_header("\"default_keyset_id\": 99999,", _site_id, keys)

    def _key_set_to_json_for_sharing_with_header(self, default_keyset, caller_site_id, keys):
        return """{{
                    "body": {{
                        "caller_site_id": {0}, 
                        "master_keyset_id": 1,
                        "token_expiry_seconds": 86400,
                        {1}
                        "keys": [{2}        
                        ]
                    }}
                }}""".format(caller_site_id, default_keyset, ",\n".join([self.format_key(x) for x in keys]))

    def format_key(self, key: EncryptionKey):
        return """
                            {{ 
                                "id": {0},
                                {1} 
                                "created": {2},
                                "activates": {3},
                                "expires": {4},
                                "secret": "{5}"
                            }}""".format(key.key_id,
                                        "" if key.keyset_id is None else '"keyset_id": ' + str(key.keyset_id) + ",",
                                        int(key.created.timestamp()),
                                        int(key.activates.timestamp()),
                                        int(key.expires.timestamp()),
                                        base64.b64encode(key.secret).decode("utf-8"))

    def test_can_encrypt_and_decrypt_for_sharing(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        results = decrypt(ad_token, keys)
        self.assertEqual(_example_uid, results.uid2)

    def test_can_decrypt_another_clients_encrypted_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        receiving_client = Uid2Client("endpoint2", "authkey2", _client_secret)
        keys_json = self._key_set_to_json_for_sharing_with_header('"default_keyset_id": 12345,', 4874, [_master_key, _site_key])

        receiving_keys = receiving_client.refresh_json(keys_json)

        result = decrypt(ad_token, receiving_keys)
        self.assertEqual(_example_uid, result.uid2)

    def test_sharing_token_is_v4(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        contains_base_64_special_chars = "+" in ad_token or "/" in ad_token or "=" in ad_token
        self.assertFalse(contains_base_64_special_chars)

    def test_uid2_client_produces_uid2_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        self.assertEqual("A", ad_token[0])

    def test_euid_client_produces_euid_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt(IdentityScope.EUID)
        self.assertEqual("E", ad_token[0])

    def _get_token_identity_type(self, uid2, keys):
        token = encrypt(uid2, IdentityScope.UID2, keys)

        first_char = token[0]
        if ('A' == first_char or 'E' == first_char):
            return IdentityType.Email
        if ('F' == first_char or 'B' == first_char):
            return IdentityType.Phone

        return None

    def test_raw_uid_produces_correct_identity_type_in_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt()

        self.assertEqual(IdentityType.Email, self._get_token_identity_type("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=", keys))
        self.assertEqual(IdentityType.Phone, self._get_token_identity_type("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ", keys))
        self.assertEqual(IdentityType.Email, self._get_token_identity_type("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=", keys))
        self.assertEqual(IdentityType.Email, self._get_token_identity_type("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", keys))
        self.assertEqual(IdentityType.Email, self._get_token_identity_type("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", keys))

    def test_multiple_keys_per_keyset(self):
        master_key2 = EncryptionKey(264, -1, _now - dt.timedelta(days=-2), _now - dt.timedelta(days=-1), _now - dt.timedelta(hours=-1),
                            _master_secret, keyset_id=9999)
        site_key2 = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-2), _now - dt.timedelta(days=-1), _now - dt.timedelta(hours=-1),
                          _site_secret, keyset_id=99999)
        client = Uid2Client("endpoint", "authkey", _client_secret)
        json_body = self._key_set_to_json_for_sharing([_master_key, master_key2, _site_key, site_key2])
        keys = client.refresh_json(json_body)

        ad_token = encrypt(_example_uid, IdentityScope.UID2, keys)

        result = decrypt(ad_token, keys)

        self.assertEqual(_example_uid, result.uid2)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self):
        client = Uid2Client("endpoint", "authkey", _client_secret)
        json_body = self._key_set_to_json_for_sharing([_master_key])
        keys = client.refresh_json(json_body)

        self.assertRaises(EncryptionError, encrypt, _example_uid, IdentityScope.UID2, keys)

    def test_cannot_encrypt_if_theres_to_default_keyset_header(self):
        client = Uid2Client("endpoint", "authkey", _client_secret)
        json_body = self._key_set_to_json_for_sharing_with_header("", _site_id, [_master_key, _site_key])
        keys = client.refresh_json(json_body)
        self.assertRaises(EncryptionError, encrypt, _example_uid, IdentityScope.UID2, keys)


    def test_expiry_in_token_matches_expiry_in_reponse(self):
        client = Uid2Client("endpoint", "authkey", _client_secret)
        json_body = self._key_set_to_json_for_sharing_with_header('"default_keyset_id": 99999, "token_expiry_seconds": 2,', 99999, [_master_key, _site_key])
        keys = client.refresh_json(json_body)

        now = dt.datetime.now(tz=timezone.utc)
        ad_token = encrypt(_example_uid, IdentityScope.UID2, keys)

        result = decrypt(ad_token, keys, now=now + dt.timedelta(seconds=1))
        self.assertEqual(_example_uid, result.uid2)

        self.assertRaises(EncryptionError, decrypt, ad_token, keys, now=now + dt.timedelta(seconds=3))

    def test_encrypt_key_inactive(self):
        client = Uid2Client("endpoint", "authkey", _client_secret)
        key = EncryptionKey(245, _site_id, _now, _now + dt.timedelta(days=1), _now +dt.timedelta(days=2), _site_secret, keyset_id=99999)
        keys = client.refresh_json(self._key_set_to_json_for_sharing([_master_key, key]))
        self.assertRaises(EncryptionError, encrypt, _example_uid, IdentityScope.UID2, keys)

    def test_encrypt_key_expired(self):
        client = Uid2Client("endpoint", "authkey", _client_secret)
        key = EncryptionKey(245, _site_id, _now, _now, _now - dt.timedelta(days=1), _site_secret, keyset_id=99999)
        keys = client.refresh_json(self._key_set_to_json_for_sharing([_master_key, key]))
        self.assertRaises(EncryptionError, encrypt, _example_uid, IdentityScope.UID2, keys)


