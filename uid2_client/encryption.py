"""Internal module for keeping encryption/decryption logic.

Do not use this module directly, import from uid2_client instead, e.g.
>>> from uid2_client import decrypt
"""

import base64
import datetime as dt
from datetime import timezone
import os
from Crypto.Cipher import AES
from enum import Enum

from uid2_client.advertising_token_version import AdvertisingTokenVersion
from uid2_client.uid2_base64_url_coder import Uid2Base64UrlCoder
from uid2_client.identity_type import IdentityType
from uid2_client.identity_scope import IdentityScope

encryption_block_size = AES.block_size
"""int: block size for encryption routines

This determines the size of initialization vectors (IV), required data padding, etc.
"""


class _PayloadType(Enum):
    """Enum for types of payload that can be encoded in opaque strings"""
    ENCRYPTED_DATA = 128
    ENCRYPTED_DATA_V3 = 96


base64_url_special_chars = {"-", "_"}


# DEPRECATED, DO NOT CALL DIRECTLY. PLEASE USE Uid2Client's client.decrypt()
def decrypt(token, keys, now=dt.datetime.now(tz=timezone.utc)):
    """Decrypt advertising token to extract UID2 details.

    Args:
        token (str): advertising token to decrypt
        keys (EncryptionKeysCollection): collection of keys to decrypt the token
        now (datetime): date/time to use as "now" when doing token expiration check

    Returns:
        DecryptedToken: details extracted from the advertising token

    Raises:
        EncryptionError: if token version is not supported, the token has expired,
                         or no required decryption keys present in the keys collection
    """

    try:
        return _decrypt_token(token, keys, now)
    except Exception as exc:
        if isinstance(exc, EncryptionError):
            raise
        raise EncryptionError('invalid payload') from exc


def _decrypt_token(token, keys, now):
    if not keys.valid(now):
        raise EncryptionError('no keys available or all keys have expired; refresh the latest keys from UID2 service')

    header_str = token[0:4]
    index = next((i for i, ch in enumerate(header_str) if ch in base64_url_special_chars), None)
    is_base64_url_encoding = (index is not None)
    token_bytes = Uid2Base64UrlCoder.decode(header_str) if is_base64_url_encoding else base64.b64decode(header_str)

    if token_bytes[0] == 2:
        return _decrypt_token_v2(base64.b64decode(token), keys, now)
    elif token_bytes[1] == AdvertisingTokenVersion.ADVERTISING_TOKEN_V3.value:
        return _decrypt_token_v3(base64.b64decode(token), keys, now)
    elif token_bytes[1] == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4.value:
        # same as V3 but use Base64URL encoding
        return _decrypt_token_v3(Uid2Base64UrlCoder.decode(token), keys, now)
    else:
        raise EncryptionError('token version not supported')


def _decrypt_token_v2(token_bytes, keys, now):
    master_key_id = int.from_bytes(token_bytes[1:5], 'big')
    master_key = keys.get(master_key_id)
    if master_key is None:
        raise EncryptionError("not authorized for master key")

    master_iv = token_bytes[5:21]
    master_payload = _decrypt(token_bytes[21:], master_iv, master_key)

    expires_ms = int.from_bytes(master_payload[:8], 'big')
    expires = dt.datetime.fromtimestamp(expires_ms / 1000.0, tz=timezone.utc)
    if expires < now:
        raise EncryptionError("token expired")

    site_key_id = int.from_bytes(master_payload[8:12], 'big')
    site_key = keys.get(site_key_id)
    if site_key is None:
        raise EncryptionError("not authorized for site key")

    identity_iv = master_payload[12:28]
    identity = _decrypt(master_payload[28:], identity_iv, site_key)

    site_id = int.from_bytes(identity[0:4], 'big')

    id_len = int.from_bytes(identity[4:8], 'big')
    id_str = identity[8:8 + id_len].decode('utf-8')

    idx = 8 + id_len + 4
    established_ms = int.from_bytes(identity[idx:idx + 8], 'big')
    established = dt.datetime.fromtimestamp(established_ms / 1000.0, tz=timezone.utc)

    return DecryptedToken(id_str, established, site_id, site_key.site_id)


def _decrypt_token_v3(token_bytes, keys, now):
    master_key_id = int.from_bytes(token_bytes[2:6], 'big')
    master_key = keys.get(master_key_id)
    if master_key is None:
        raise EncryptionError("not authorized for master key")

    master_payload = _decrypt_gcm(token_bytes[6:], master_key.secret)

    expires_ms = int.from_bytes(master_payload[:8], 'big')
    expires = dt.datetime.fromtimestamp(expires_ms / 1000.0, tz=timezone.utc)
    if expires < now:
        raise EncryptionError("token expired")

    # created 8:16
    # operator site id 16:20
    # operator type 20
    # operator version 21:25
    # operator key id 25:29

    site_key_id = int.from_bytes(master_payload[29:33], 'big')
    site_key = keys.get(site_key_id)
    if site_key is None:
        raise EncryptionError("not authorized for site key")

    site_payload = _decrypt_gcm(master_payload[33:], site_key.secret)

    site_id = int.from_bytes(site_payload[0:4], 'big')
    # publisher id 4:12
    # client key id 12:16
    # privacy bits 16:20
    established_ms = int.from_bytes(site_payload[20:28], 'big')
    established = dt.datetime.fromtimestamp(established_ms / 1000.0, tz=timezone.utc)
    # refreshed_ms 28:36

    id_bytes = site_payload[36:]
    id_str = base64.b64encode(id_bytes).decode('ascii')

    return DecryptedToken(id_str, established, site_id, site_key.site_id)


def _encrypt_token(uid2, identity_scope, master_key, site_key, site_id, now, token_expiry, ad_token_version):
    site_payload = bytearray(128)
    # Publisher Data
    site_payload[0:4] = int.to_bytes(site_id, byteorder='big', length=4)  # Site id
    site_payload[4:12] = int.to_bytes(0, byteorder='big', length=8)  # Publisher ID
    site_payload[12:16] = int.to_bytes(0, byteorder='big', length=4)  # Client Key ID
    # User Identity Data
    site_payload[16:20] = int.to_bytes(0, byteorder='big', length=4)  # Privacy Bits
    site_payload[20:28] = int.to_bytes(int((now - dt.timedelta(hours=1)).timestamp()) * 1000, byteorder='big',
                                       length=8)  # Established
    site_payload[28:36] = int.to_bytes(int(now.timestamp()) * 1000, byteorder='big', length=8)  # last refresh
    site_payload[36:] = bytes(base64.b64decode(uid2))

    id_payload = _encrypt_gcm(bytes(site_payload), None, site_key.secret)

    # Operator Identity Data
    master_payload = bytearray(256)
    master_payload[:8] = int.to_bytes(int(token_expiry.timestamp()) * 1000, byteorder='big', length=8)  # Expiry
    master_payload[8:16] = int.to_bytes(int(now.timestamp()), byteorder='big', length=8)  # Token Created
    master_payload[16:20] = int.to_bytes(0, byteorder='big', length=4)  # Site ID
    master_payload[20:21] = int.to_bytes(1, byteorder='big', length=1)  # Operator Type
    master_payload[21:25] = int.to_bytes(0, byteorder='big', length=4)  # Operator Version
    master_payload[25:29] = int.to_bytes(0, byteorder='big', length=4)  # Operator Key ID
    master_payload[29:33] = int.to_bytes(site_key.key_id, byteorder='big', length=4)  # Site Key ID
    master_payload[33:] = bytes(id_payload)

    encrypted_master_payload = _encrypt_gcm(bytes(master_payload), None, master_key.secret)

    root_writer = bytearray(len(encrypted_master_payload) + 6)
    first_char = uid2[0]
    identity_type = IdentityType.Phone if first_char == 'F' or first_char == 'B' else IdentityType.Email
    root_writer[0:1] = int.to_bytes((int(identity_scope) << 4 | int(identity_type) << 2), byteorder='big', length=1)
    root_writer[1:2] = int.to_bytes(ad_token_version.value, byteorder='big', length=1)
    root_writer[2:6] = int.to_bytes(master_key.key_id, byteorder='big', length=4)
    root_writer[6:] = bytes(encrypted_master_payload)

    if ad_token_version == AdvertisingTokenVersion.ADVERTISING_TOKEN_V4:
        return Uid2Base64UrlCoder.encode(root_writer)

    return base64.b64encode(root_writer)


# DEPRECATED, DO NOT CALL DIRECTLY. PLEASE USE Uid2Client's client.encrypt()
def encrypt(uid2, identity_scope, keys, keyset_id=None, **kwargs):
    """ Encrypt an UID2 into a sharing token

    Args:
        uid2: the UID2 or EUID to be encrypted
        identity_scope (IdentityScope): indicates whether the output will be for UID2 or EUID
        keys (EncryptionKeysCollection): collection of keys to choose from for encryption
        keyset_id (int) : An optional keyset id to use for the encryption. Will use default keyset if left blank

    Keyword Args:
        now (Datetime): the datettime to use for now. Defaults to utc now

    Returns (str): Sharing Token

    """
    now = kwargs.get("now")
    if now is None:
        now = dt.datetime.now(tz=timezone.utc)

    ad_token_version = AdvertisingTokenVersion.ADVERTISING_TOKEN_V4

    key = keys.get_default_keyset_key(now) if keyset_id is None else keys.get_by_keyset_key(keyset_id, now)
    master_key = keys.get_by_keyset_key(keys.get_master_keyset_id(), now)

    token_expiry = now + dt.timedelta(days=30) if keys.get_token_expiry_seconds() is None \
        else now + dt.timedelta(seconds=int(keys.get_token_expiry_seconds()))

    site_id = keys.get_caller_site_id()
    if site_id is None:
        print("No Site ID in keys")
        return

    if key is None:
        raise EncryptionError("No Keyset Key Found")

    return _encrypt_token(uid2, identity_scope, master_key, key, site_id, now, token_expiry, ad_token_version)


def encrypt_data(data, identity_scope, **kwargs):
    """Encrypt arbitrary binary data.

    The data can be decrypted with decrypt_data() function.

    Args:
        data (bytes): data to encrypt
        identity_scope (IdentityScope): scope of the unified ID
        **kwargs: additional keyword arguments as per below

    Keyword Args:
        key (EncryptionKey): key to encrypt the data with; if this is specified,
                             you should not specify keys, site_id, or advertising_token
        keys (EncryptionKeysCollection): collection of keys to choose the encryption
                                         key from; the key will be selected using site_id
        site_id (int): ID of the site for which the encryption key is to be used;
                       the key will be looked up from the keys collection;
                       if this is specified, you can't specify advertising_token
        advertising_token (str): token to decrypt in order to obtain the site_id
        now (datetime): date/time to use as "now" for checking whether advertising_token
                        or site encryption key have expired (default: UTC now) as well as
                        for timestamp of the encrypted data
        iv (bytes): custom initialization vector for the encryption; if not specified,
                    the function will generate one using urandom

    Returns:
        (str) encrypted data; this will be in opaque string format

    Raises:
        ValueError: if invalid parameter combinations are specified through **kwargs
        EncryptionError: if advertising_token cannot be decrypted, no key can be found
                         for the site_id, or the key has expired

    The keyword arguments key, keys, site_id and advertising_token can only be used in
    the following combinations:
        - key: use the specified key
        - keys and site_id: find the key for the specified site_id
        - keys and advertising_token: extract site_id from the token and find a key for it
    """
    now = kwargs.get("now")
    if now is None:
        now = dt.datetime.now(tz=timezone.utc)
    keys = kwargs.get("keys")
    key = kwargs.get("key")
    if keys is not None and key is not None:
        raise ValueError("only one of keys and key can be specified")
    if key is None:
        site_id = kwargs.get("site_id")
        site_key_site_id = site_id
        advertising_token = kwargs.get("advertising_token")
        if site_id is not None and advertising_token is not None:
            raise ValueError("only one of site_id and advertising_token can be specified")
        if advertising_token is not None:
            decrypted_token = decrypt(advertising_token, keys, now)
            site_id = decrypted_token.site_id
            site_key_site_id = decrypted_token.site_key_site_id

        key = keys.get_active_site_key(site_key_site_id, now)
        if key is None:
            raise EncryptionError("not authorized for key for the specified site")
    elif not key.is_active(now):
        raise EncryptionError("key is either expired or not active yet")
    else:
        site_id = key.site_id
        if site_id < 0:
            site_id += (1 << 32)

    iv = kwargs.get("iv")
    if iv is None:
        iv = os.urandom(12)

    payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
    payload += int.to_bytes(site_id, 4, 'big')
    payload += data

    result = int.to_bytes(_PayloadType.ENCRYPTED_DATA_V3.value | (identity_scope.value << 4) | 0xB, 1, 'big')
    result += int.to_bytes(112, 1, 'big')  # version
    result += int.to_bytes(key.key_id, 4, 'big')
    result += _encrypt_gcm(payload, iv, key.secret)

    return base64.b64encode(result).decode('ascii')


def _encrypt_data_v1(data, key, iv):
    return int.to_bytes(key.key_id, 4, 'big') + iv + _encrypt(data, iv, key)


def decrypt_data(encrypted_data, keys):
    """Decrypt data encrypted with encrypt_data().

    Args:
        encrypted_data (str): data to decrypt
        keys (EncryptionKeysCollection): collection of keys to decrypt the data

    Returns:
        DecryptedData: the decrypted data and extracted metadata

    Raises:
        EncryptionError: if encrypted_data is malformed or the required decryption
                         key is not present in the keys collection
    """
    try:
        return _decrypt_data(encrypted_data, keys)
    except Exception as exc:
        if isinstance(exc, EncryptionError):
            raise
        raise EncryptionError('invalid payload') from exc


def _decrypt_data(encrypted_data, keys):
    encrypted_bytes = base64.b64decode(encrypted_data)
    if (encrypted_bytes[0] & 224) == _PayloadType.ENCRYPTED_DATA_V3.value:
        return _decrypt_data_v3(encrypted_bytes, keys)
    else:
        return _decrypt_data_v2(encrypted_bytes, keys)


def _decrypt_data_v2(encrypted_bytes, keys):
    if encrypted_bytes[0] != _PayloadType.ENCRYPTED_DATA.value:
        raise EncryptionError("incorrect content type")

    version = encrypted_bytes[1]
    if version != 1:
        raise EncryptionError("unsupported encrypted data format/version")
    key_id = int.from_bytes(encrypted_bytes[14:18], 'big')
    key = keys.get(key_id)
    if key is None:
        raise EncryptionError("not authorized for key")
    iv = encrypted_bytes[18:34]
    data = _decrypt(encrypted_bytes[34:], iv, key)
    encrypted_ms = int.from_bytes(encrypted_bytes[2:10], 'big')
    encrypted_at = dt.datetime.fromtimestamp(encrypted_ms / 1000.0, tz=timezone.utc)
    return DecryptedData(data, encrypted_at)


def _decrypt_data_v3(encrypted_bytes, keys):
    version = encrypted_bytes[1]
    if version != 112:
        raise EncryptionError("unsupported encrypted data format/version")

    key_id = int.from_bytes(encrypted_bytes[2:6], 'big')
    key = keys.get(key_id)
    if key is None:
        raise EncryptionError("not authorized for key")

    payload = _decrypt_gcm(encrypted_bytes[6:], key.secret)
    encrypted_ms = int.from_bytes(payload[:8], 'big')
    encrypted_at = dt.datetime.fromtimestamp(encrypted_ms / 1000.0, tz=timezone.utc)

    # site id 8:12

    return DecryptedData(payload[12:], encrypted_at)


def _add_pkcs7_padding(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _encrypt(data, iv, key):
    cipher = AES.new(key.secret, AES.MODE_CBC, IV=iv)
    return cipher.encrypt(_add_pkcs7_padding(data, AES.block_size))


def _decrypt(encrypted, iv, key):
    cipher = AES.new(key.secret, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(encrypted)
    # remove pkcs7 padding
    pad_len = data[-1]
    return data[:-pad_len]


def _encrypt_gcm(data, iv, secret):
    if iv is None:
        iv = os.urandom(12)
    elif len(iv) != 12:
        raise ValueError("iv must be 12 bytes")
    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ciphertext + tag


def _decrypt_gcm(encrypted, secret):
    cipher = AES.new(secret, AES.MODE_GCM, nonce=encrypted[:12])
    return cipher.decrypt_and_verify(encrypted[12:-16], encrypted[-16:])


class EncryptionError(Exception):
    """Raised for problems encountered while decrypting an advertising id."""


class DecryptedToken:
    """Details extracted from a decrypted advertising token.

    Attrs:
        uid2 (str): universal ID string
        established (datetime): UTC date/time for when the token was first generated
        site_id (int): site ID which the token is originating from
        site_key_site_id (int): site ID of the site key which the token is encrypted with
    """

    def __init__(self, uid2, established, site_id, site_key_site_id):
        self.uid2 = uid2
        self.established = established
        self.site_id = site_id
        self.site_key_site_id = site_key_site_id


class DecryptedData:
    """Details extracted from the encrypted data string.

    Attrs:
        data (bytes): data decrypted from the string
        encrypted_at (datetime): UTC date/time for when the data was encrypted
    """

    def __init__(self, data, encrypted_at):
        self.data = data
        self.encrypted_at = encrypted_at
