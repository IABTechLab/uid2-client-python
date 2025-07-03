import base64
import os
from datetime import datetime
from typing import Dict, Optional
from urllib import request

import pkg_resources

from uid2_client.encryption import _encrypt_gcm, _decrypt_gcm
from .envelope import Envelope
from .uid2_response import Uid2Response

BINARY = 'application/octet-stream'

def _make_url(base_url: str, path: str) -> str:
    return base_url + path

def auth_headers(auth_key: str) -> Dict[str, str]:
    try:
        version = pkg_resources.get_distribution("uid2_client").version
    except Exception:
        version = "non-packaged-mode"

    return {'Authorization': 'Bearer ' + auth_key,
            "X-UID2-Client-Version": "uid2-client-python-" + version}

def create_envelope(secret_key: bytes, now: datetime, data: Optional[bytes] = None) -> 'Envelope':
    payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
    nonce = os.urandom(8)
    payload += nonce
    if data:
        payload += data

    envelope = int.to_bytes(1, 1, 'big')
    envelope += _encrypt_gcm(payload, None, secret_key)
    return Envelope(envelope, nonce)

def make_request(base_url: str, path: str, headers: Dict[str, str], envelope: Envelope) -> 'Uid2Response':
    resp = post(base_url, path, headers, envelope.envelope)
    return Uid2Response.from_string(resp.read())

def make_binary_request(base_url: str, path: str, headers: Dict[str, str], envelope: Envelope) -> 'Uid2Response':
    headers['Content-Type'] = BINARY
    resp = post(base_url, path, headers, envelope.binary_envelope)
    return Uid2Response.from_bytes(resp.read())

def post(base_url: str, path: str, headers: Dict[str, str], data: bytes):
    req = request.Request(_make_url(base_url, path), headers=headers, method='POST', data=data)
    return request.urlopen(req)

def parse_response(secret_key: bytes, uid2_response: Uid2Response, nonce: bytes) -> str:
    if uid2_response.is_binary():
        as_bytes = uid2_response.as_bytes
        if as_bytes is None:
            raise ValueError("Binary response has no bytes data")
        return _decrypt_payload(secret_key, as_bytes, nonce)
    else:
        as_string = uid2_response.as_string
        if as_string is None:
            raise ValueError("String response has no string data")
        encrypted_string = base64.b64decode(as_string)
        return _decrypt_payload(secret_key, encrypted_string, nonce)

def _decrypt_payload(secret_key: bytes, encrypted: bytes, nonce: bytes) -> str:
    payload = _decrypt_gcm(encrypted, secret_key)
    if nonce != payload[8:16]:
        raise ValueError("nonce mismatch")
    return payload[16:]
