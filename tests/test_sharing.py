import unittest

from uid2_client import *
from test_utils import *

import datetime as dt


class TestSharing(unittest.TestCase):
    def setup_sharing_and_encrypt(self, id_scope=IdentityScope.UID2):
        client = Uid2Client("endpoint", "key", client_secret)
        json = key_set_to_json_for_sharing([master_key, site_key])
        keys = client.refresh_json(json)

        ad_token = encrypt(example_uid, id_scope, keys)

        return ad_token, keys

    def test_can_encrypt_and_decrypt_for_sharing(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        results = decrypt(ad_token, keys)
        self.assertEqual(example_uid, results.uid2)

    def test_can_decrypt_another_clients_encrypted_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt()
        receiving_client = Uid2Client("endpoint2", "authkey2", client_secret)
        keys_json = key_set_to_json_for_sharing_with_header('"default_keyset_id": 12345,', 4874, [master_key, site_key])

        receiving_keys = receiving_client.refresh_json(keys_json)

        result = decrypt(ad_token, receiving_keys)
        self.assertEqual(example_uid, result.uid2)

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

    def test_raw_uid_produces_correct_identity_type_in_token(self):
        ad_token, keys = self.setup_sharing_and_encrypt()

        self.assertEqual(IdentityType.Email, get_token_identity_type("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=", keys))
        self.assertEqual(IdentityType.Phone, get_token_identity_type("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ", keys))
        self.assertEqual(IdentityType.Email, get_token_identity_type("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=", keys))
        self.assertEqual(IdentityType.Email, get_token_identity_type("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", keys))
        self.assertEqual(IdentityType.Email, get_token_identity_type("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb", keys))

    def test_multiple_keys_per_keyset(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        json_body = key_set_to_json_for_sharing([master_key, master_key2, site_key, site_key2])
        keys = client.refresh_json(json_body)

        ad_token = encrypt(example_uid, IdentityScope.UID2, keys)

        result = decrypt(ad_token, keys)

        self.assertEqual(example_uid, result.uid2)

    def test_cannot_encrypt_if_no_key_from_default_keyset(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        json_body = key_set_to_json_for_sharing([master_key])
        keys = client.refresh_json(json_body)

        self.assertRaises(EncryptionError, encrypt, example_uid, IdentityScope.UID2, keys)

    def test_cannot_encrypt_if_theres_no_default_keyset_header(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        json_body = key_set_to_json_for_sharing_with_header("", site_id, [master_key, site_key])
        keys = client.refresh_json(json_body)
        self.assertRaises(EncryptionError, encrypt, example_uid, IdentityScope.UID2, keys)


    def test_expiry_in_token_matches_expiry_in_reponse(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        json_body = key_set_to_json_for_sharing_with_header('"default_keyset_id": 99999, "token_expiry_seconds": 2,', 99999, [master_key, site_key])
        keys = client.refresh_json(json_body)

        now = dt.datetime.now(tz=timezone.utc)
        ad_token = encrypt(example_uid, IdentityScope.UID2, keys)

        result = decrypt(ad_token, keys, now=now + dt.timedelta(seconds=1))
        self.assertEqual(example_uid, result.uid2)

        self.assertRaises(EncryptionError, decrypt, ad_token, keys, now=now + dt.timedelta(seconds=3))

    def test_encrypt_key_inactive(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        key = EncryptionKey(245, site_id, now, now + dt.timedelta(days=1), now +dt.timedelta(days=2), site_secret, keyset_id=99999)
        keys = client.refresh_json(key_set_to_json_for_sharing([master_key, key]))
        self.assertRaises(EncryptionError, encrypt, example_uid, IdentityScope.UID2, keys)

    def test_encrypt_key_expired(self):
        client = Uid2Client("endpoint", "authkey", client_secret)
        key = EncryptionKey(245, site_id, now, now, now - dt.timedelta(days=1), site_secret, keyset_id=99999)
        keys = client.refresh_json(key_set_to_json_for_sharing([master_key, key]))
        self.assertRaises(EncryptionError, encrypt, example_uid, IdentityScope.UID2, keys)