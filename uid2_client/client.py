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

"""Internal module for holding the Uid2Client class.

Do not use this module directly, import through uid2_client module instead, e.g.

>>> from uid2_client import Uid2Client
"""


import base64
import datetime as dt
import json
import os
import urllib.request as request

from .keys import EncryptionKey, EncryptionKeysCollection
from .encryption import _decrypt_gcm, _encrypt_gcm


def _make_dt(timestamp):
    return dt.datetime.utcfromtimestamp(timestamp)


class Uid2Client:
    """Client for interacting with UID2 services.

    You will need to have the base URL of the endpoint and a client key pair (auth/secret)
    to consume web services.

    Methods:
        refresh_keys: get the latest encryption keys for decrypting advertising tokens

    Examples:
        Connect to the UID2 service and obtain the latest encryption keys:
        >>> from uid2_client import *
        >>> client = Uid2Client('https://prod.uidapi.com', 'my-authorization-key', 'my-secret-key')
        >>> keys = client.refresh_keys()
        >>> uid2 = decrypt_token('some-ad-token', keys).uid2
    """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new Uid2Client client.

        Args:
            base_url (str): base URL for all requests to UID2 services (e.g. 'https://prod.uidapi.com')
            auth_key (str): authorization key for consuming the UID2 services
            secret_key (str): secret key for consuming the UID2 services

        Note:
            Your authorization key will determine which UID2 services you are allowed to use.
        """
        self._base_url = base_url
        self._auth_key = auth_key
        self._secret_key = base64.b64decode(secret_key)


    def refresh_keys(self):
        """Get the latest encryption keys for advertising tokens.

        This will synchronously connect to the corresponding UID2 service and fetch the latest
        set of encryption keys which can then be used to decrypt advertising tokens using
        the decrypt_token function.

        Returns:
            EncryptionKeysCollection containing the keys
        """
        req, nonce = self._make_v2_request(dt.datetime.utcnow())
        print(req)
        resp = self._post('/v2/key/latest', headers=self._auth_headers(), data=req)
        keys = [EncryptionKey(k['id'], k.get('site_id', -1), _make_dt(k['created']), _make_dt(k['activates']), _make_dt(k['expires']), base64.b64decode(k['secret']))
            for k in json.loads(self._parse_v2_response(resp.read(), nonce)).get('body')]
        return EncryptionKeysCollection(keys)


    def _make_url(self, path):
        return self._base_url + path


    def _auth_headers(self):
        return {'Authorization': 'Bearer ' + self._auth_key}


    def _make_v2_request(self, now):
        payload = int.to_bytes(int(now.timestamp() * 1000), 8, 'big')
        nonce = os.urandom(8)
        payload += nonce

        envelope = int.to_bytes(1, 1, 'big')
        envelope += _encrypt_gcm(payload, None, self._secret_key)

        return base64.b64encode(envelope), nonce


    def _parse_v2_response(self, encrypted, nonce):
        payload = _decrypt_gcm(base64.b64decode(encrypted), self._secret_key)
        if nonce != payload[8:16]:
            raise ValueError("nonce mismatch")
        return payload[16:]


    def _post(self, path, headers, data):
        req = request.Request(self._make_url(path), headers=headers, method='POST', data=data)
        return request.urlopen(req)


class Uid2ClientError(Exception):
    """Raised for problems encountered while interacting with UID2 services."""
