import unittest

from test_utils import *
from uid2_client import *

_master_secret = bytes([139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155])
_site_secret =   bytes([32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133])
_master_key_id = 164
_site_key_id = 165
_test_site_key_id = 166
_site_id = 9000
_site_id2 = 2

_example_id = 'ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM='
_now = dt.datetime.now(tz=timezone.utc)
_master_key = EncryptionKey(_master_key_id, -1, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _master_secret, keyset_id=9999)
_site_key = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _site_secret)
_keyset_key = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _site_secret, keyset_id=20)
_test_site_key = EncryptionKey(_test_site_key_id, _site_id, dt.datetime(2020, 1, 1, tzinfo=timezone.utc), dt.datetime(2020, 1, 1, tzinfo=timezone.utc), _now + dt.timedelta(days=1), encryption_block_size * b'9')


class TestEncryptionFunctions(unittest.TestCase):

    def test_cross_platform_consistency_check_base64_url_test_cases(self):
        case1 = bytes([ 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99])
        # the Base64 equivalent is "/+CI/+6ZmQ=="
        # and we want the Base64URL encoded to remove 2 '=' paddings at the back
        self.cross_platform_consistency_check_base64_url_test(case1, "_-CI_-6ZmQ")

        # the Base64 equivalent is "/+CI/+6ZmZk=" to remove 1 padding
        case2 = bytes([0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99, 0x99])
        self.cross_platform_consistency_check_base64_url_test(case2, "_-CI_-6ZmZk")

        # the Base64 equivalent is "/+CI/+6Z" which requires no padding removal
        case3 = bytes([0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99])
        self.cross_platform_consistency_check_base64_url_test(case3, "_-CI_-6Z")


    def cross_platform_consistency_check_base64_url_test(self, raw_input, expected_base64_url_str):
        base64_url_encoded_str = Uid2Base64UrlCoder.encode(raw_input)
        self.assertEqual(expected_base64_url_str, base64_url_encoded_str)

        decoded = Uid2Base64UrlCoder.decode(base64_url_encoded_str)
        self.assertEqual(decoded, raw_input)

    def validate_advertising_token(self, advertising_token_string, identity_scope, identity_type,
                                   token_version=AdvertisingTokenVersion.ADVERTISING_TOKEN_V4):

        if token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V2:
            self.assertEqual("A", advertising_token_string[0])
            self.assertEqual("g", advertising_token_string[1])
            return

        first_char = advertising_token_string[0]
        if identity_scope == IdentityScope.UID2:
            self.assertEqual("A" if identity_type == IdentityType.Email.value else "B", first_char)
        else:
            self.assertEqual("E" if identity_type == IdentityType.Email.value else "F", first_char)

        second_char = advertising_token_string[1]
        if token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V3:
            self.assertEqual("3", second_char)
            return
        else:
            self.assertEqual("4", second_char)

            # No URL-unfriendly characters allowed
            self.assertEqual(-1, advertising_token_string.find("="))
            self.assertEqual(-1, advertising_token_string.find("+"))
            self.assertEqual(-1, advertising_token_string.find("/"))

    def generate_uid2_token_v4(self, uid, master_key, site_id, site_key, params = Params(), identity_type = IdentityType.Email, identity_scope = IdentityScope.UID2):
        if not isinstance(params.token_expiry, dt.datetime):
            params.token_expiry = dt.datetime.now(tz=timezone.utc) + params.token_expiry
        advertising_token = UID2TokenGenerator.generate_uid2_token_v4(uid, master_key, site_id, site_key, params)
        self.validate_advertising_token(advertising_token, identity_scope, identity_type)
        return advertising_token


    def test_cross_platform_consistency_decrypt(self):
        crossPlatformAdvertisingToken = "AIAAAACkOqJj9VoxXJNnuX3v-ymceRf8_Av0vA5asOj9YBZJc1kV1vHdmb0AIjlzWnFF-gxIlgXqhRFhPo3iXpugPBl3gv4GKnGkw-Zgm2QqMsDPPLpMCYiWrIUqHPm8hQiq9PuTU-Ba9xecRsSIAN0WCwKLwA_EDVdzmnLJu64dQoeYmuu3u1G2EuTkuMrevmP98tJqSUePKwnfK73-0Zdshw";
        # Sunday, 1 January 2023 1:01:01 AM UTC
        referenceTimestampMs = 1672534861000
        # 1 hour before ref timestamp
        established_ms = referenceTimestampMs - (3600 * 1000);
        last_refreshed_ms = referenceTimestampMs;
        token_created_ms = referenceTimestampMs;

        master_key_created = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc) - dt.timedelta(
            days=1)
        site_key_created = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc) - dt.timedelta(
            days=10)
        master_key_activates = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc)
        site_key_activates = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc) - dt.timedelta(
            days=1)

        # for the next ~20 years ...
        master_key_expires = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc) + dt.timedelta(
            days=1 * 365 * 20)
        site_key_expires = dt.datetime.fromtimestamp(referenceTimestampMs / 1000, tz=timezone.utc) + dt.timedelta(
            days=1 * 365 * 20)
        master_key = EncryptionKey(_master_key_id, -1, master_key_created, master_key_activates, master_key_expires,
                                   _master_secret)
        site_key = EncryptionKey(_site_key_id, -1, site_key_created, site_key_activates, site_key_expires,
                                 _site_secret)

        params = Params(dt.timedelta(days=1 * 365 * 20))

        # verify that the dynamically created ad token can be decrypted
        runtime_advertising_token = self.generate_uid2_token_v4(_example_id, master_key, _site_id, site_key, params)
        # best effort check as the token might simply just not require padding
        self.assertEqual(-1, runtime_advertising_token.find('='))
        self.assertEqual(-1, runtime_advertising_token.find('+'))
        self.assertEqual(-1, runtime_advertising_token.find('/'))

        result = decrypt(runtime_advertising_token, EncryptionKeysCollection([_master_key, _site_key]))
        self.assertEqual(_example_id, result.uid)

        # can also decrypt a known token generated from other SDK
        result = decrypt(crossPlatformAdvertisingToken, EncryptionKeysCollection([_master_key, _site_key]))
        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v4(self):
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt(token, keys)

        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v4_empty_keys(self):
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v4_no_master_key(self):
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v4_no_site_key(self):
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)

    def test_decrypt_token_v4_invalid_version(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(hours=1))
        token = UID2TokenGenerator.generate_uid2_token_with_debug_info(_example_id, _master_key, _site_id, _site_key, params, 1)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v4_expired(self):
        params = Params(dt.timedelta(seconds=-1))
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)

    def _generate_v2_token(self, expires_in_seconds):
        return UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key,
                                                         Params(dt.datetime.now(tz=timezone.utc) + expires_in_seconds))

    def _generate_v4_token(self, expires_in_seconds):
        return self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key, Params(expires_in_seconds))

    def test_decrypt_token_2_invalid_lifetime_exception(self):
        test_cases = [
            # expires 30s AFTER max
            [self._generate_v2_token(dt.timedelta(seconds=60)), 30, 3600, ClientType.BIDSTREAM],
            [self._generate_v4_token(dt.timedelta(seconds=60)), 30, 3600, ClientType.BIDSTREAM],
            [self._generate_v2_token(dt.timedelta(seconds=60)), 3600, 30, ClientType.SHARING],
            [self._generate_v4_token(dt.timedelta(seconds=60)), 3600, 30, ClientType.SHARING],
            # expires 1s AFTER max
            [self._generate_v2_token(dt.timedelta(seconds=60)), 59, 3600, ClientType.BIDSTREAM],
            [self._generate_v4_token(dt.timedelta(seconds=60)), 59, 3600, ClientType.BIDSTREAM],
            [self._generate_v2_token(dt.timedelta(seconds=60)), 3600, 59, ClientType.SHARING],
            [self._generate_v4_token(dt.timedelta(seconds=60)), 3600, 59, ClientType.SHARING],
            # expires 1 day AFTER max
            [self._generate_v2_token(dt.timedelta(days=3)), dt.timedelta(days=2).seconds, dt.timedelta(days=4).seconds,
             ClientType.BIDSTREAM],
            [self._generate_v4_token(dt.timedelta(days=3)), dt.timedelta(days=2).seconds,
             dt.timedelta(days=4).seconds, ClientType.BIDSTREAM],
            [self._generate_v2_token(dt.timedelta(days=3)), dt.timedelta(days=4).seconds, dt.timedelta(days=2).seconds,
             ClientType.SHARING],
            [self._generate_v4_token(dt.timedelta(days=3)), dt.timedelta(days=4).seconds,
             dt.timedelta(days=2).seconds, ClientType.SHARING]
        ]
        for token, max_bidstream_lifetime_seconds, max_sharing_lifetime_seconds, client_type in test_cases:
            with self.subTest(token=token,
                              max_bidstream_lifetime_seconds=max_bidstream_lifetime_seconds,
                              max_sharing_lifetime_seconds=max_sharing_lifetime_seconds, client_type=client_type):
                key_collection = EncryptionKeysCollection([_master_key, _site_key], IdentityScope.UID2, None, None,
                                                          None, None,
                                                          max_sharing_lifetime_seconds, max_bidstream_lifetime_seconds,
                                                          None)
                decrypted_token = decrypt_token(token, key_collection, "", client_type)
                self.assertEqual(decrypted_token.status, DecryptionStatus.INVALID_TOKEN_LIFETIME)

    def test_decrypt_token_invalid_lifetime_pass(self):
        seconds_since_established = 3600  # from UID2TokenGenerator.generate_uid2_token_v4
        test_cases = [
            # expires 30s before max
            [self._generate_v2_token(dt.timedelta(seconds=30)), seconds_since_established + 60, 60, ClientType.BIDSTREAM],
            [self._generate_v4_token(dt.timedelta(seconds=30)), seconds_since_established + 60, 60, ClientType.BIDSTREAM],
            [self._generate_v2_token(dt.timedelta(seconds=30)), 30, seconds_since_established + 30, ClientType.SHARING],
            [self._generate_v4_token(dt.timedelta(seconds=30)), 30, seconds_since_established + 30, ClientType.SHARING],
            # expires exactly at max
            [self._generate_v2_token(dt.timedelta(seconds=30)), seconds_since_established + 30, 30, ClientType.BIDSTREAM],
            [self._generate_v4_token(dt.timedelta(seconds=30)), seconds_since_established + 30, 30, ClientType.BIDSTREAM],
            [self._generate_v2_token(dt.timedelta(seconds=30)), 60, seconds_since_established + 60, ClientType.SHARING],
            [self._generate_v4_token(dt.timedelta(seconds=30)), 60, seconds_since_established + 60, ClientType.SHARING]
        ]
        for token, max_bidstream_lifetime_seconds, max_sharing_lifetime_seconds, client_type in test_cases:
            with self.subTest(token=token,
                              max_bidstream_lifetime_seconds=max_bidstream_lifetime_seconds,
                              max_sharing_lifetime_seconds=max_sharing_lifetime_seconds, client_type=client_type):

                key_collection = EncryptionKeysCollection([_master_key, _site_key], IdentityScope.UID2, None, None,
                                                          None, None,
                                                          max_sharing_lifetime_seconds, max_bidstream_lifetime_seconds,
                                                          None)
                decrypt_token(token, key_collection, "", client_type)

    def test_decrypt_token_v4_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        params = Params(expiry)
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys, now=expiry + dt.timedelta(seconds=1))

        result = decrypt(token, keys, now=expiry - dt.timedelta(seconds=1))
        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v4_invalid_payload(self):
        params = Params(dt.timedelta(seconds=-1))
        token = self.generate_uid2_token_v4(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token[:-3], keys)


    def test_decrypt_token_v3(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt(token, keys)

        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v3_empty_keys(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v3_no_master_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v3_no_site_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)

    def test_decrypt_token_v3_invalid_version(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(hours=1))
        token = UID2TokenGenerator.generate_uid2_token_with_debug_info(_example_id, _master_key, _site_id, _site_key, params, 1)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v3_expired(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=-1))
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v3_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        params = Params(expiry)
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys, now=expiry + dt.timedelta(seconds=1))

        result = decrypt(token, keys, now=expiry - dt.timedelta(seconds=1))
        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v3_invalid_payload(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=-1))
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token[:-3], keys)


    def test_decrypt_token_v2(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt(token, keys)

        self.assertEqual(_example_id, result.uid)


    def test_decrypt_token_v2_empty_keys(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v2_no_master_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v2_no_site_key(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v2_invalid_version(self):
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key, version=1)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v2_expired(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=-1))
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys)


    def test_decrypt_token_v2_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        params = Params(expiry)
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token, keys, now=expiry + dt.timedelta(seconds=1))

        result = decrypt(token, keys, now=expiry - dt.timedelta(seconds=1))
        self.assertEqual(_example_id, result.uid)

    def test_smoke_token_v3(self):
        uid2 = _example_id
        identity_scope = IdentityScope.UID2
        now = dt.datetime.now(tz=timezone.utc)

        keys = EncryptionKeysCollection([_master_key, _site_key, _keyset_key], default_keyset_id=20,
                                        master_keyset_id=9999, caller_site_id=20)
        token_expiry = now + dt.timedelta(days=30) if keys.get_token_expiry_seconds() is None \
            else now + dt.timedelta(seconds=int(keys.get_token_expiry_seconds()))
        result = UID2TokenGenerator.generate_uid2_token_v3(uid2, _master_key, _site_id, _site_key,
                                                           Params(expiry=token_expiry, token_generated=now))
        final = decrypt(result, keys, now=now)

        self.assertEqual(uid2, final.uid)

    def test_smoke_token_v4(self):
        uid2 = _example_id
        identity_scope = IdentityScope.UID2
        now = dt.datetime.now(tz=timezone.utc)

        keys = EncryptionKeysCollection([_master_key, _site_key, _keyset_key], default_keyset_id=20,
                                        master_keyset_id=9999, caller_site_id=20)

        result = encrypt(uid2, identity_scope, keys, now=now)
        final = decrypt(result.encrypted_data, keys, now=now)

        self.assertEqual(uid2, final.uid)

    def test_decrypt_token_v2_invalid_payload(self):
        params = Params(dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=-1))
        token = UID2TokenGenerator.generate_uid2_token_v2(_example_id, _master_key, _site_id, _site_key, params)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt(token[:-3], keys)


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
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, key.site_id, key)
        encrypted = encrypt_data(data, IdentityScope.UID2, advertising_token=token, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_site_id_from_token_custom_site_key_site_id(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id2, key)
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
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, key.site_id, key)
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
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, _site_id, key)
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
        params = Params(expiry)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, key.site_id, key, params)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token=token)


    def test_encrypt_data_expired_token_custom_now(self):
        data = b'123456'
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2, tzinfo=timezone.utc)
        params = Params(expiry)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = UID2TokenGenerator.generate_uid2_token_v3(_example_id, _master_key, key.site_id, key, params)

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


    # TODO - deduplicate the logic in test_sharing.py that has been copied from this file
    def test_raw_uid_produces_correct_identity_type_in_token(self):
        #v2 +12345678901. Although this was generated from a phone number, it's a v2 raw UID which doesn't encode this
        # information, so token assumes email by default.
        self.verify_identity_type("Q4bGug8t1xjsutKLCNjnb5fTlXSvIQukmahYDJeLBtk=",
                                                      IdentityType.Email.value)
        self.verify_identity_type("BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ",
                                                      IdentityType.Phone.value) #v3 +12345678901
        self.verify_identity_type("oKg0ZY9ieD/CGMEjAA0kcq+8aUbLMBG0MgCT3kWUnJs=",
                                                      IdentityType.Email.value) #v2 test@example.com
        self.verify_identity_type("AKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb",
                                                      IdentityType.Email.value) #v3 test@example.com
        self.verify_identity_type("EKCoNGWPYng/whjBIwANJHKvvGlGyzARtDIAk95FlJyb",
                                                      IdentityType.Email.value) #v3 EUID test@example.com

    def verify_identity_type(self, raw_uid, expected_identity_type):
        token = self.generate_uid2_token_v4(raw_uid, _master_key, _site_id, _site_key, Params(), expected_identity_type)
        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt(token, keys)
        self.assertEqual(raw_uid, result.uid)
        self.assertEqual(expected_identity_type, get_identity_type(token))


def format_time(t):
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    return s[:-3]
