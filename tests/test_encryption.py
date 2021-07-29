# Copyright (c) 2021 The Trade Desk, Inc
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import base64
import datetime as dt
import unittest
from Crypto.Cipher import AES

from uid2_client import decrypt_token, encrypt_data, decrypt_data, encryption_block_size, EncryptionError
from uid2_client.encryption import _encrypt_data_v1
from uid2_client.keys import *


_master_secret = bytes([139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155])
_site_secret =   bytes([32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133])
_master_key_id = 164
_site_key_id = 165
_test_site_key_id = 166
_site_id = 2001

_uid2 = 'ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM='
_now = dt.datetime.utcnow()
_master_key = EncryptionKey(_master_key_id, -1, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _master_secret)
_site_key = EncryptionKey(_site_key_id, _site_id, _now - dt.timedelta(days=-1), _now, _now + dt.timedelta(days=1), _site_secret)
_test_site_key = EncryptionKey(_test_site_key_id, _site_id, dt.datetime(2020, 1, 1, 0, 0, 0), dt.datetime(2021, 1, 1, 0, 0, 0), _now + dt.timedelta(days=1), encryption_block_size * b'9')


class TestEncryptionFunctions(unittest.TestCase):

    def test_decrypt_token(self):
        token = _encrypt_token(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key, _site_key])
        result = decrypt_token(token, keys)

        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_empty_keys(self):
        token = _encrypt_token(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_no_master_key(self):
        token = _encrypt_token(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_no_site_key(self):
        token = _encrypt_token(_uid2, _master_key, _site_key)

        keys = EncryptionKeysCollection([_master_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_invalid_version(self):
        token = _encrypt_token(_uid2, _master_key, _site_key, version=1)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_expired(self):
        token = _encrypt_token(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys)


    def test_decrypt_token_custom_now(self):
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2)
        token = _encrypt_token(_uid2, _master_key, _site_key, expiry=expiry)

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token, keys, now=expiry+dt.timedelta(seconds=1))

        result = decrypt_token(token, keys, now=expiry-dt.timedelta(seconds=1))
        self.assertEqual(_uid2, result.uid2)


    def test_decrypt_token_invalid_payload(self):
        token = _encrypt_token(_uid2, _master_key, _site_key, expiry=dt.timedelta(seconds=-1))

        keys = EncryptionKeysCollection([_master_key, _site_key])

        with self.assertRaises(EncryptionError):
            result = decrypt_token(token[:-3], keys)


    def test_encrypt_data_specific_key_and_iv(self):
        data = b'123456'
        iv = encryption_block_size * b'0'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, iv=iv, key=key)
        self.assertTrue(len(data) + len(iv) < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_specific_key_and_generated_iv(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, key=key)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_specific_site_id(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, site_id=key.site_id, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_site_id_from_token(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = _encrypt_token(_uid2, _master_key, key, site_id=key.site_id)
        encrypted = encrypt_data(data, advertising_token=token, keys=keys)
        self.assertTrue(len(data) + encryption_block_size < len(encrypted))
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)


    def test_encrypt_data_keys_and_specific_key_set(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(ValueError):
            encrypt_data(data, key=key, keys=keys)


    def test_encrypt_data_site_id_and_token_set(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = _encrypt_token(_uid2, _master_key, key, site_id=key.site_id)
        with self.assertRaises(ValueError):
            encrypt_data(data, keys=keys, site_id=key.site_id, advertising_token=token)


    def test_encrypt_data_token_decrypt_failed(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, _test_site_key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, advertising_token="bogus-token")


    def test_encrypt_data_key_expired(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now - dt.timedelta(days=2), _now - dt.timedelta(days=1), encryption_block_size * b'9')
        with self.assertRaises(EncryptionError):
            encrypt_data(data, key=key)


    def test_encrypt_data_key_inactive(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now + dt.timedelta(days=2), _now + dt.timedelta(days=3), encryption_block_size * b'9')
        with self.assertRaises(EncryptionError):
            encrypt_data(data, key=key)


    def test_encrypt_data_key_expired_custom_now(self):
        data = b'123456'
        key = _test_site_key
        now = _test_site_key.expires
        with self.assertRaises(EncryptionError):
            encrypt_data(data, key=key, now=now)


    def test_encrypt_data_key_inactive_custom_now(self):
        data = b'123456'
        key = _test_site_key
        now = _test_site_key.activates - dt.timedelta(seconds=1)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, key=key, now=now)


    def test_encrypt_data_no_site_key(self):
        data = b'123456'
        keys = EncryptionKeysCollection([_master_key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, site_id=205)


    def test_encrypt_data_site_key_expired(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now - dt.timedelta(days=2), _now - dt.timedelta(days=1), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, site_id=site_id)


    def test_encrypt_data_site_key_inactive(self):
        data = b'123456'
        site_id = 205
        key = EncryptionKey(101, site_id, _now - dt.timedelta(days=2), _now + dt.timedelta(days=2), _now + dt.timedelta(days=3), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, site_id=site_id)


    def test_encrypt_data_site_key_expired_custom_now(self):
        data = b'123456'
        site_id = 205
        now = dt.datetime.utcnow() - dt.timedelta(days=1)
        key = EncryptionKey(101, site_id, now, now, now + dt.timedelta(seconds=1), encryption_block_size * b'9')
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, site_id=site_id, keys=keys, now=now)
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)
        self.assertEqual(format_time(now), format_time(decrypted.encrypted_at))


    def test_encrypt_data_expired_token(self):
        data = b'123456'
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = _encrypt_token(_uid2, _master_key, key, site_id=key.site_id, expiry=expiry)
        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, advertising_token=token)


    def test_encrypt_data_expired_token_custom_now(self):
        data = b'123456'
        expiry = dt.datetime(2021, 3, 22, 9, 1, 2)
        key = _test_site_key
        keys = EncryptionKeysCollection([_master_key, key])
        token = _encrypt_token(_uid2, _master_key, key, site_id=key.site_id, expiry=expiry)

        with self.assertRaises(EncryptionError):
            encrypt_data(data, keys=keys, advertising_token=token, now=expiry+dt.timedelta(seconds=1))

        now = expiry-dt.timedelta(seconds=1)
        encrypted = encrypt_data(data, keys=keys, advertising_token=token, now=now)
        decrypted = decrypt_data(encrypted, keys)
        self.assertEqual(data, decrypted.data)
        self.assertEqual(format_time(now), format_time(decrypted.encrypted_at))


    def test_decrypt_data_bad_payload_type(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, key=key)
        encrypted_bytes = base64.b64decode(encrypted)
        encrypted = base64.b64encode(bytes([0]) + encrypted_bytes[1:]).decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)


    def test_decrypt_data_bad_version(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, key=key)
        encrypted_bytes = base64.b64decode(encrypted)
        encrypted = base64.b64encode(encrypted_bytes[0:1] + bytes([0]) + encrypted_bytes[2:]).decode('ascii')
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, keys)


    def test_decrypt_data_bad_payload(self):
        data = b'123456'
        key = _test_site_key
        keys = EncryptionKeysCollection([key])
        encrypted = encrypt_data(data, key=key)
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
        encrypted = encrypt_data(data, key=key)
        dkeys = EncryptionKeysCollection([_master_key])
        with self.assertRaises(EncryptionError):
            decrypt_data(encrypted, dkeys)


def _encrypt_token(id_str, master_key, site_key, version=2, expiry=dt.timedelta(hours=1), site_id=0, privacy_bits=0):
    id = bytes(id_str, 'utf-8')
    identity = int.to_bytes(site_id, 4, 'big')
    identity += int.to_bytes(len(id), 4, 'big')
    identity += id
    identity += int.to_bytes(privacy_bits, 4, 'big')
    identity += int.to_bytes(int((dt.datetime.utcnow() - dt.timedelta(hours=1)).timestamp()) * 1000, 8, 'big')
    identity_iv = bytes([10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9])

    if not isinstance(expiry, dt.datetime):
        expiry = dt.datetime.utcnow() + expiry
    master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
    master_payload += _encrypt_data_v1(identity, key=site_key, iv=identity_iv)
    master_iv = bytes([21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36])

    token = int.to_bytes(version, 1, 'big')
    token += _encrypt_data_v1(master_payload, key=master_key, iv=master_iv)

    return base64.b64encode(token).decode('ascii')


def format_time(t):
    s = t.strftime('%Y-%m-%d %H:%M:%S.%f')
    return s[:-3]
