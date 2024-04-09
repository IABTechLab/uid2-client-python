import base64
import os
from enum import Enum

from Crypto.Cipher import AES
from datetime import timezone
import datetime as dt
from uid2_client.identity_scope import IdentityScope


from uid2_client.advertising_token_version import AdvertisingTokenVersion
from uid2_client.identity_type import IdentityType
from uid2_client.uid2_base64_url_coder import Uid2Base64UrlCoder

encryption_block_size = AES.block_size
"""int: block size for encryption routines

This determines the size of initialization vectors (IV), required data padding, etc.
"""


class _PayloadType(Enum):
    """Enum for types of payload that can be encoded in opaque strings"""
    ENCRYPTED_DATA = 128
    ENCRYPTED_DATA_V3 = 96


def _add_pkcs7_padding(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _encrypt_gcm(data, iv, secret):
    if iv is None:
        iv = os.urandom(12)
    elif len(iv) != 12:
        raise ValueError("iv must be 12 bytes")
    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ciphertext + tag


def _encrypt(data, iv, key):
    cipher = AES.new(key.secret, AES.MODE_CBC, IV=iv)
    return cipher.encrypt(_add_pkcs7_padding(data, AES.block_size))


def _encrypt_data_v1(data, key, iv):
    return int.to_bytes(key.key_id, 4, 'big') + iv + _encrypt(data, iv, key)


class Params:
    def __init__(self, expiry=dt.datetime.now(tz=timezone.utc) + dt.timedelta(hours=1),
                 identity_scope=IdentityScope.UID2.value, token_created_at=dt.datetime.now(tz=timezone.utc)):
        self.identity_scope = identity_scope
        self.token_expiry = expiry
        self.token_created_at = token_created_at
        if not isinstance(expiry, dt.datetime):
            self.token_expiry = dt.datetime.now(tz=timezone.utc) + expiry


def default_params():
    return Params()


class UID2TokenGenerator:

    @staticmethod
    def generate_uid2_token_v2(id_str, master_key, site_id, site_key, params = default_params(), version=2):
        id = bytes(id_str, 'utf-8')
        identity = int.to_bytes(site_id, 4, 'big')
        identity += int.to_bytes(len(id), 4, 'big')
        identity += id
        # old privacy_bits
        identity += int.to_bytes(0, 4, 'big')
        created = params.token_created_at
        identity += int.to_bytes(int(created.timestamp()) * 1000, 8, 'big')
        identity_iv = bytes([10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        expiry = params.token_expiry
        master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
        master_payload += _encrypt_data_v1(identity, key=site_key, iv=identity_iv)
        master_iv = bytes([21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36])

        token = int.to_bytes(version, 1, 'big')
        token += _encrypt_data_v1(master_payload, key=master_key, iv=master_iv)

        return base64.b64encode(token).decode('ascii')

    @staticmethod
    def generate_uid2_token_v3(id_str, master_key, site_id, site_key, params=default_params()):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V3.value)

    @staticmethod
    def generate_uid2_token_v4(id_str, master_key, site_id, site_key, params=default_params()):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V4.value)

    @staticmethod
    def generate_uid_token(id_str, master_key, site_id, site_key, identity_scope, token_version,
                           created_at=None, expires_at=None):
        params = default_params()
        params.identity_scope = identity_scope
        if created_at is not None:
            params.token_created_at = created_at
        if expires_at is not None:
            params.token_expiry = expires_at
        if token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V2:
            return UID2TokenGenerator.generate_uid2_token_v2(id_str, master_key, site_id, site_key, params)
        elif token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V3:
            return UID2TokenGenerator.generate_uid2_token_v3(id_str, master_key, site_id, site_key, params)
        elif token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4:
            return UID2TokenGenerator.generate_uid2_token_v4(id_str, master_key, site_id, site_key, params)
        else:
            raise Exception('invalid version')

    @staticmethod
    def generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params, version):
        id = base64.b64decode(id_str)

        site_payload = int.to_bytes(site_id, 4, 'big')
        site_payload += int.to_bytes(0, 8, 'big')  # publisher id
        site_payload += int.to_bytes(0, 4, 'big')  # client key id

        site_payload += int.to_bytes(0, 4, 'big')  # privacy bits
        created = params.token_created_at
        site_payload += int.to_bytes(int(created.timestamp()) * 1000, 8, 'big')  # established
        site_payload += int.to_bytes(int(created.timestamp()) * 1000, 8, 'big')  # refreshed
        site_payload += id

        expiry = params.token_expiry

        master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
        master_payload += int.to_bytes(int(created.timestamp()) * 1000, 8, 'big')  # created

        master_payload += int.to_bytes(0, 4, 'big')  # operator site id
        master_payload += int.to_bytes(0, 1, 'big')  # operator type
        master_payload += int.to_bytes(0, 4, 'big')  # operator version
        master_payload += int.to_bytes(0, 4, 'big')  # operator key id

        master_payload += int.to_bytes(site_key.key_id, 4, 'big')
        master_payload += _encrypt_gcm(site_payload, None, site_key.secret)

        first_char = id_str[0]
        # see UID2-79+Token+and+ID+format+v3
        identity_type = IdentityType.Email.value
        if (first_char == 'F') or (first_char == 'B'):
            identity_type = IdentityType.Phone.value

        token = int.to_bytes((params.identity_scope << 4 | identity_type << 2) | 3, 1, 'big')
        token += int.to_bytes(version, 1, 'big')
        token += int.to_bytes(master_key.key_id, 4, 'big')
        token += _encrypt_gcm(master_payload, None, master_key.secret)

        if version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4.value:
            return Uid2Base64UrlCoder.encode(token)
        else:
            return base64.b64encode(token).decode('ascii')

    @staticmethod
    def encrypt_data_v2(data, key, site_id, now):
        iv = os.urandom(encryption_block_size)
        result = int.to_bytes(_PayloadType.ENCRYPTED_DATA.value, 1, 'big')
        result += int.to_bytes(1, 1, 'big')  # version
        result += int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
        result += int.to_bytes(site_id, 4, 'big')
        result += _encrypt_data_v1(data, key, iv)
        return base64.b64encode(result).decode('ascii')
