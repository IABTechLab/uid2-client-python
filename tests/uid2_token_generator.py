import base64

from datetime import timezone
import os
from uid2_client import encryption_block_size
from uid2_client.advertising_token_version import AdvertisingTokenVersion
from uid2_client.encryption import _encrypt_data_v1, _encrypt_gcm, _PayloadType
from uid2_client.identity_scope import IdentityScope
from uid2_client.identity_type import IdentityType
from uid2_client.keys import *
from uid2_client.uid2_base64_url_coder import Uid2Base64UrlCoder


class Params:
    def __init__(self, expiry=dt.datetime.now(tz=timezone.utc) + dt.timedelta(hours=1),
                 identity_scope=IdentityScope.UID2.value, identity_type=IdentityType.Email.value):
        self.identity_scope = identity_scope
        self.identity_type = identity_type
        self.token_expiry = expiry
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
        identity += int.to_bytes(int((dt.datetime.now(tz=timezone.utc) - dt.timedelta(hours=1)).timestamp()) * 1000, 8,
                                 'big')
        identity_iv = bytes([10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        expiry = params.token_expiry
        master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
        master_payload += _encrypt_data_v1(identity, key=site_key, iv=identity_iv)
        master_iv = bytes([21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36])

        token = int.to_bytes(version, 1, 'big')
        token += _encrypt_data_v1(master_payload, key=master_key, iv=master_iv)

        return base64.b64encode(token).decode('ascii')

    @staticmethod
    def generate_uid2_token_v3(id_str, master_key, site_id, site_key, params = default_params()):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V3.value)

    @staticmethod
    def generate_uid2_token_v4(id_str, master_key, site_id, site_key, params = default_params()):
        return UID2TokenGenerator.generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params,
                                                    AdvertisingTokenVersion.ADVERTISING_TOKEN_V4.value)

    @staticmethod
    def generate_uid2_token_with_debug_info(id_str, master_key, site_id, site_key, params, version):
        id = base64.b64decode(id_str)

        site_payload = int.to_bytes(site_id, 4, 'big')
        site_payload += int.to_bytes(0, 8, 'big')  # publisher id
        site_payload += int.to_bytes(0, 4, 'big')  # client key id

        site_payload += int.to_bytes(0, 4, 'big')  # privacy bits
        site_payload += int.to_bytes(int((dt.datetime.now(tz=timezone.utc) - dt.timedelta(hours=1)).timestamp()) * 1000,
                                     8, 'big')  # established
        site_payload += int.to_bytes(int((dt.datetime.now(tz=timezone.utc) - dt.timedelta(hours=1)).timestamp()) * 1000,
                                     8, 'big')  # refreshed
        site_payload += id

        expiry = params.token_expiry
        master_payload = int.to_bytes(int(expiry.timestamp()) * 1000, 8, 'big')
        master_payload += int.to_bytes(int((dt.datetime.now(tz=timezone.utc)).timestamp()) * 1000, 8, 'big')  # created

        master_payload += int.to_bytes(0, 4, 'big')  # operator site id
        master_payload += int.to_bytes(0, 1, 'big')  # operator type
        master_payload += int.to_bytes(0, 4, 'big')  # operator version
        master_payload += int.to_bytes(0, 4, 'big')  # operator key id

        master_payload += int.to_bytes(site_key.key_id, 4, 'big')
        master_payload += _encrypt_gcm(site_payload, None, site_key.secret)

        token = int.to_bytes((params.identity_scope << 4 | params.identity_type << 2), 1, 'big')
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
