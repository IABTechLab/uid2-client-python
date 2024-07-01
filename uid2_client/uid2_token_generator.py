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
    def __init__(self, expiry=None, identity_scope=IdentityScope.UID2.value, token_generated=None,
                 identity_established=None):
        now = dt.datetime.now(tz=timezone.utc)
        if identity_established is None:
            identity_established = now
        if token_generated is None:
            token_generated = now
        if expiry is None:
            expiry = now + dt.timedelta(hours=1)

        self.identity_established = identity_established
        self.token_generated = token_generated
        self.token_expiry = expiry
        self.identity_scope = identity_scope


class UID2TokenGenerator:

    @staticmethod
    def generate_uid2_token_v2(id_str, master_key, site_id, site_key, params=None, version=2):
        """This function is only used by tests."""
        if params is None:
            params = Params()

        id = bytes(id_str, 'utf-8')
        identity = int.to_bytes(site_id, 4, 'big')
        identity += int.to_bytes(len(id), 4, 'big')
        identity += id
        # old privacy_bits
        identity += int.to_bytes(0, 4, 'big')
        identity += int.to_bytes(int(params.identity_established.timestamp()) * 1000, 8, 'big')
        identity_iv = os.urandom(16)
        expiry = params.token_expiry
        master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
        master_payload += _encrypt_data_v1(identity, key=site_key, iv=identity_iv)
        master_iv = os.urandom(16)

        token = int.to_bytes(version, 1, 'big')
        token += _encrypt_data_v1(master_payload, key=master_key, iv=master_iv)

        return base64.b64encode(token).decode('ascii')

    @staticmethod
    def generate_uid2_token_v3(id_str, master_key, site_id, site_key, params=None):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V3.value)

    @staticmethod
    def generate_uid2_token_v4(id_str, master_key, site_id, site_key, params=None):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V4.value)

    @staticmethod
    def generate_uid_token(id_str, master_key, site_id, site_key, identity_scope, token_version,
                           identity_established=None, token_generated=None, token_expiry=None):
        params = Params(token_expiry, identity_scope, token_generated, identity_established)
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
        if params is None:
            params = Params()

        # Publisher Data
        site_payload = int.to_bytes(site_id, length=4, byteorder='big')
        site_payload += int.to_bytes(0, length=8, byteorder='big')  # publisher id
        site_payload += int.to_bytes(0, length=4, byteorder='big')  # client key id

        # User Identity Data
        site_payload += int.to_bytes(0, length=4, byteorder='big')  # privacy bits
        site_payload += int.to_bytes(int(params.identity_established.timestamp()) * 1000, length=8, byteorder='big')  # established
        generated_at_timestamp = int(params.token_generated.timestamp()) * 1000
        site_payload += int.to_bytes(generated_at_timestamp, length=8, byteorder='big')  # last refreshed/generated
        site_payload += base64.b64decode(id_str)

        master_payload = int.to_bytes(int(params.token_expiry.timestamp()) * 1000, length=8, byteorder='big')  # expiry
        master_payload += int.to_bytes(generated_at_timestamp, length=8, byteorder='big')  # generated

        # Operator Identity Data
        master_payload += int.to_bytes(0, length=4, byteorder='big')  # site id
        master_payload += int.to_bytes(1, length=1, byteorder='big')  # operator type
        master_payload += int.to_bytes(0, length=4, byteorder='big')  # operator version
        master_payload += int.to_bytes(0, length=4, byteorder='big')  # operator key id

        master_payload += int.to_bytes(site_key.key_id, length=4, byteorder='big')  # Site Key ID
        master_payload += _encrypt_gcm(site_payload, None, site_key.secret)

        first_char = id_str[0]
        # see UID2-79+Token+and+ID+format+v3
        identity_type = IdentityType.Email.value
        if (first_char == 'F') or (first_char == 'B'):
            identity_type = IdentityType.Phone.value

        token = int.to_bytes((params.identity_scope << 4 | identity_type << 2) | 3, length=1, byteorder='big')
        token += int.to_bytes(version, length=1, byteorder='big')
        token += int.to_bytes(master_key.key_id, length=4, byteorder='big')
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
