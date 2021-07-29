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

"""Internal module for keeping encryption/decryption logic.

Do not use this module directly, import from uid2_client instead, e.g.
>>> from uid2_client import decrypt_token
"""


import base64
import datetime as dt
import os
from Crypto.Cipher import AES
from enum import Enum


encryption_block_size = AES.block_size
"""int: block size for encryption routines

This determines the size of initialization vectors (IV), required data padding, etc.
"""


class _PayloadType(Enum):
    """Enum for types of payload that can be encoded in opaque strings"""
    ENCRYPTED_DATA = 128


def decrypt_token(token, keys, now=dt.datetime.utcnow()):
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
        if exc is EncryptionError:
            raise
        raise EncryptionError('invalid payload') from exc


def _decrypt_token(token, keys, now):
    if not keys.valid(now):
        raise EncryptionError('no keys available or all keys have expired; refresh the latest keys from UID2 service')

    token_bytes = base64.b64decode(token)

    version = token_bytes[0]
    if version != 2:
        raise EncryptionError('token version not supported')

    master_key_id = int.from_bytes(token_bytes[1:5], 'big')
    master_key = keys.get(master_key_id)
    if master_key is None:
        raise EncryptionError("not authorized for master key")

    master_iv = token_bytes[5:21]
    master_payload = _decrypt(token_bytes[21:], master_iv, master_key)

    expires_ms = int.from_bytes(master_payload[:8], 'big')
    expires = dt.datetime.utcfromtimestamp(expires_ms / 1000.0)
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
    id_str = identity[8:8+id_len].decode('utf-8')

    idx = 8 + id_len + 4
    established_ms = int.from_bytes(identity[idx:idx+8], 'big')
    established = dt.datetime.utcfromtimestamp(established_ms / 1000.0)

    return DecryptedToken(id_str, established, site_id)


def encrypt_data(data, **kwargs):
    """Encrypt arbitrary binary data.

    The data can be decrypted with decrypt_data() function.

    Args:
        data (bytes): data to encrypt
        **kwargs: additional keyword arguments as per below

    Keyword Args:
        key (EncryptionKey): key to encrypt the data with; if this is specified,
                             you should not specify keys, site_id, or advertising_token
        keys (EncryptionKeysCollection): collection of keys to choose the encryption
                                         key from; the key will be selected using site_id
        site_id (int): ID of the site for which the encryption key is to be used;
                       the key will be looked up from the keys collection;
                       if this is specified, you can't specificy advertising_token
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
        - key: use the specied key
        - keys and site_id: find the key for the specified site_id
        - keys and advertising_token: extract site_id from the token and find a key for it
    """
    now = kwargs.get("now")
    if now is None:
        now = dt.datetime.utcnow()
    keys = kwargs.get("keys")
    key = kwargs.get("key")
    if keys is not None and key is not None:
        raise ValueError("only one of keys and key can be specified")
    if key is None:
        site_id = kwargs.get("site_id")
        advertising_token = kwargs.get("advertising_token")
        if site_id is not None and advertising_token is not None:
            raise ValueError("only one of site_id and advertising_token can be specified")
        if advertising_token is not None:
            decrypted_token = decrypt_token(advertising_token, keys, now)
            site_id = decrypted_token.site_id

        key = keys.get_active_site_key(site_id, now)
        if key is None:
            raise EncryptionError("no key for the specified site")
    elif not key.is_active(now):
        raise EncryptionError("key is either expired or not active yet")
    else:
        site_id = key.site_id
        if site_id < 0:
            site_id += (1 << 32)

    iv = kwargs.get("iv")
    if iv is None:
        iv = os.urandom(encryption_block_size)

    result = int.to_bytes(_PayloadType.ENCRYPTED_DATA.value, 1, 'big')  # 0
    result += int.to_bytes(1, 1, 'big') # version                 # 1
    result += int.to_bytes(int(now.timestamp() * 1000), 8, 'big') # 2-9
    result += int.to_bytes(site_id, 4, 'big')                     # 10-13
    result += _encrypt_data_v1(data, key, iv)                     # 14-
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
        if exc is EncryptionError:
            raise
        raise EncryptionError('invalid payload') from exc


def _decrypt_data(encrypted_data, keys):
    encrypted_bytes = base64.b64decode(encrypted_data)
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
    encrypted_at = dt.datetime.utcfromtimestamp(encrypted_ms / 1000.0)
    return DecryptedData(data, encrypted_at)


def _add_pkcs7_padding(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len


def _encrypt(data, iv, key):
    cipher = AES.new(key.secret, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(_add_pkcs7_padding(data, AES.block_size))


def _decrypt(encrypted, iv, key):
    cipher = AES.new(key.secret, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(encrypted)
    # remove pkcs7 padding
    pad_len = data[-1]
    return data[:-pad_len]


class EncryptionError(Exception):
    """Raised for problems encountered while decrypting an advertising id."""


class DecryptedToken:
    """Details extracted from a decrypted advertising token.

    Attrs:
        uid2 (str): universal ID string
        site_id (int): site ID which the token is originating from
        established (datetime): UTC date/time for when the token was first generated
    """
    def __init__(self, uid2, established, site_id):
        self.uid2 = uid2
        self.established = established
        self.site_id = site_id


class DecryptedData:
    """Details extracted from the encrypted data string.

    Attrs:
        data (bytes): data decrypted from the string
        encrypted_at (datetime): UTC date/time for when the data was encrypted
    """
    def __init__(self, data, encrypted_at):
        self.data = data
        self.encrypted_at = encrypted_at
