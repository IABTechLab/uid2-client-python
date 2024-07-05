import base64
import os
import threading
from importlib.metadata import version
from typing import Optional

import requests

from uid2_client.encryption import _decrypt_gcm, _encrypt_gcm


def _make_url(base_url, path):
    return base_url + path


def auth_headers(auth_key):
    try:
        client_version = version("uid2_client")
    except Exception:
        client_version = "non-packaged-mode"

    return {'Authorization': 'Bearer ' + auth_key,
            "X-UID2-Client-Version": "uid2-client-python-" + client_version}


def make_v2_request(secret_key, now, data=None):
    payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
    nonce = os.urandom(8)
    payload += nonce
    if data:
        payload += data

    envelope = int.to_bytes(1, 1, 'big')
    envelope += _encrypt_gcm(payload, None, secret_key)

    return base64.b64encode(envelope), nonce


def parse_v2_response(secret_key, encrypted, nonce):
    payload = _decrypt_gcm(base64.b64decode(encrypted), secret_key)
    if nonce != payload[8:16]:
        raise ValueError("nonce mismatch")
    return payload[16:]


def __default_new_session(threadlocal=threading.local()):
    if getattr(threadlocal, 'session', None) is None:
        threadlocal.session = requests.Session()

    return threadlocal.session


def post(base_url, path, headers, data, session: Optional[requests.Session] = None):
    session = session or __default_new_session()

    return session.post(_make_url(base_url, path), data=data, headers=headers, timeout=5)
