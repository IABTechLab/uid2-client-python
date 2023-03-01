import base64

from datetime import timezone
import unittest

from tests.uid2_token_generator import UID2TokenGenerator
from uid2_client import decrypt_token, encrypt_data, decrypt_data, encryption_block_size, EncryptionError, IdentityScope
from uid2_client.keys import *

_master_secret = bytes([139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155])
_site_secret =   bytes([32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133])
_master_key_id = 164
_site_key_id = 165
_test_site_key_id = 166
_site_id = 2001
_site_id2 = 2

_uid2 = 'ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM='
_now = dt.datetime.now(tz=timezone.utc)
_master_key = EncryptionKey(_master_key_id, -1, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _master_secret)
_site_key = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _site_secret)
_test_site_key = EncryptionKey(_test_site_key_id, _site_id, dt.datetime(2020, 1, 1, tzinfo=timezone.utc), dt.datetime(2020, 1, 1, tzinfo=timezone.utc), _now + dt.timedelta(days=1), encryption_block_size * b'9')

class TestEncryptionFunctions(unittest.TestCase):

    # def crossPlatformConsistencyCheck_Base64UrlTestCases(self):
    #     case1 = bytes([ 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99])
    #     # the Base64 equivalent is "/+CI/+6ZmQ=="
    #     # and we want the Base64URL encoded to remove 2 '=' paddings at the back
    #     # String case1Base64Encoded = Base64.getEncoder().encodeToString(intArrayToByteArray(case1));
    #     self.crossPlatformConsistencyCheck_Base64UrlTest(case1, "_-CI_-6ZmQ");
    #
    #
    #
    # def crossPlatformConsistencyCheck_Base64UrlTest(self, raw_input, expected_base64_url_str):
    #     base64UrlEncodedStr = UID2Base64UrlCoder.encode(writer.array());
    #     assertEquals(expectedBase64URLStr, base64UrlEncodedStr);




    def test_decrypt_token_v4(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt_token(token, keys)

        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v4_empty_keys(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v4_no_master_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v4_no_site_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)

    def test_decrypt_token_v4_invalid_version(self):
        token = UID2TokenGenerator.generate_uid2_token_with_debug_info(_uid2, _master_key, _site_key, 0, 1, dt.timedelta(hours=1), 0, 0)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v4_expired(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v4_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key, expiry=expiry)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys, now=expiry+dt.timedelta(seconds=1))

        result = decrypt_token(token, keys, now=expiry-dt.timedelta(seconds=1))
        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v4_invalid_payload(self):
        token = UID2TokenGenerator.generate_uid2_token_v4(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token[:-3], keys)


    def test_decrypt_token_v3(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt_token(token, keys)

        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v3_empty_keys(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v3_no_master_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v3_no_site_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)

    def test_decrypt_token_v3_invalid_version(self):
        token = UID2TokenGenerator.generate_uid2_token_with_debug_info(_uid2, _master_key, _site_key, 0, 1, dt.timedelta(hours=1), 0, 0)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v3_expired(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v3_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key, expiry=expiry)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys, now=expiry+dt.timedelta(seconds=1))

        result = decrypt_token(token, keys, now=expiry-dt.timedelta(seconds=1))
        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v3_invalid_payload(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token[:-3], keys)


    def test_decrypt_token_v2(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt_token(token, keys)

        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v2_empty_keys(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v2_no_master_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v2_no_site_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v2_invalid_version(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key, version=1)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v2_expired(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_v2_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key, expiry=expiry)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys, now=expiry+dt.timedelta(seconds=1))

        result = decrypt_token(token, keys, now=expiry-dt.timedelta(seconds=1))
        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_v2_invalid_payload(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token[:-3], keys)


    def test_encrypt_data_specific_key_and_iv(self):
        data = b'123456'
        iv = 12 * b'0'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, iv=iv, key=key)
        self.assertTrue(len(data) + len(iv) < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_specific_key_and_generated_iv(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, key=key)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_specific_site_id(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, site_id=key.site_id, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_site_id_from_token(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=key.site_id)
        encrypted = encrypt_data(data, IdentityScope.UID2, advertising_token=token, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_site_id_from_token_custom_site_key_site_id(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=_site_id2)
        encrypted = encrypt_data(data, IdentityScope.UID2, advertising_token=token, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_keys_and_specific_key_set(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(ValueError):
            encrypt_data(data, IdentityScope.UID2, key=key, keys=keys)


    def test_encrypt_data_site_id_and_token_set(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=key.site_id)
        with self.assertRaises(ValueError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, site_id=key.site_id, advertising_token=token)


    def test_encrypt_data_token_decrypt_failed(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, _test_site_key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token="bogus-token")


    def test_encrypt_data_token_decrypt_key_expired(self):
        data = b'123456'
        key = EncryptionKey(101, _site_id2, _now - dt.timedelta(days=2), _now - dt.timedelta(days=2), _now - dt.timedelta(days=1), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=_site_id)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, advertising_token=token, keys=keys)


    def test_encrypt_data_key_expired(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now - dt.timedelta(days=2), _now - dt.timedelta(days=1), encryption_block_size * b'9')
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, key=key)


    def test_encrypt_data_key_inactive(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now + dt.timedelta(days=2), _now + dt.timedelta(days=3), encryption_block_size * b'9')
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, key=key)


    def test_encrypt_data_key_expired_custom_now(self):
        data = b'123456'
        key = _test_site_key
        now = _test_site_key.expires
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, key=key, now=now)


    def test_encrypt_data_key_inactive_custom_now(self):
        data = b'123456'
        key = _test_site_key
        now = _test_site_key.activates - dt.timedelta(seconds=1)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, key=key, now=now)


    def test_encrypt_data_no_site_key(self):
        data = b'123456'
        keys = EncryptionKeysCollection([_master_key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, site_id=205)


    def test_encrypt_data_site_key_expired(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now - dt.timedelta(days=2), _now - dt.timedelta(days=1), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, site_id=site_id)


    def test_encrypt_data_site_key_inactive(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now + dt.timedelta(days=2), _now + dt.timedelta(days=3), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, site_id=site_id)


    def test_encrypt_data_site_key_expired_custom_now(self):
        data = b'123456'
        site_id = 205
        now = dt.datetime.now(tz=timezone.utc) - dt.timedelta(days=1)
        key = EncryptionKey(101, site_id, now, now, now + dt.timedelta(seconds=1), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, site_id=site_id, keys=keys, now=now)
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)
        self.assertEqual(format_time(now), format_time(decrypted.encrypted_at))


    def test_encrypt_data_expired_token(self):
        data = b'123456'
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=key.site_id, expiry=expiry)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token=token)


    def test_encrypt_data_expired_token_custom_now(self):
        data = b'123456'
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_uid2, _master_key, key, site_id=key.site_id, expiry=expiry)

        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token=token, now=expiry+dt.timedelta(seconds=1))

        now = expiry-dt.timedelta(seconds=1)
        encrypted = encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token=token, now=now)
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)
        self.assertEqual(format_time(now), format_time(decrypted.encrypted_at))


    def test_decrypt_data_bad_payload_type(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, key=key)
        encrypted_bytes = base64.b64decode(encrypted)
        encrypted = base64.b64encode(bytes([0]) + encrypted_bytes[1:]).decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)


    def test_decrypt_data_bad_version(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, key=key)
        encrypted_bytes = base64.b64decode(encrypted)
        encrypted = base64.b64encode(encrypted_bytes[0:1] + bytes([0]) + encrypted_bytes[2:]).decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)


    def test_decrypt_data_bad_payload(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, key=key)
        encrypted_bytes = base64.b64decode(encrypted)
        encrypted = base64.b64encode(encrypted_bytes + b'1').decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)
        encrypted = base64.b64encode(encrypted_bytes[:-2]).decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)


    def test_decrypt_data_no_decryption_key(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, IdentityScope.UID2, key=key)
        dkeys = EncryptionKeysCollection([_master_key])
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, dkeys)


    def test_decrypt_data_v2(self):
        data = b'123456'
        now = dt.datetime.now(tz=timezone.utc) - dt.timedelta(days=1)
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = UID2TokenGenerator.encrypt_data_v2(data, key=key, site_id=12345, now=now)
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)
        self.assertEqual(format_time(now), format_time(decrypted.encrypted_at))

def format_time(t):
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    return s[:-3]
