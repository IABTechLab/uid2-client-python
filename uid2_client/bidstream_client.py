"""Usage
>>> from uid2_client import BidstreamClient
"""
import base64
import datetime as dt
import json

from .client_type import ClientType
from .encryption import decrypt_token
from .refresh_keys_util import refresh_bidstream_keys, parse_keys_json


class BidstreamClient:
    """Client for interacting with UID2 Bidstream services

        You will need to have the base URL of the endpoint and a client API key
        and secret to consume web services.

        Methods:
            refresh_keys: Refresh encryption keys from UID2 servers
            decrypt_token_into_raw_uid: decrypt an advertising token
    """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new BidstreamClient client.

        Args:
            base_url (str): base URL for all requests to UID2 services (e.g. 'https://prod.uidapi.com')
            auth_key (str): authorization key for consuming the UID2 services
            secret_key (str): secret key for consuming the UID2 services

        Note:
            Your authorization key will determine which UID2 services you are allowed to use.
        """
        self._keys = None
        self._base_url = base_url
        self._auth_key = auth_key
        self._secret_key = base64.b64decode(secret_key)

    def _decrypt_token_into_raw_uid(self, token, domain_name, now=None):
        return decrypt_token(token, self._keys, domain_name, ClientType.BIDSTREAM, now)

    def decrypt_token_into_raw_uid(self, token, domain_name):
        """Decrypt advertising token to extract UID2 details.

            Args:
                token (str): advertising token to decrypt
                domain_name (str) : domain name from bid request

            Returns:
                DecryptedToken: details extracted from the advertising token

            Raises:
                EncryptionError: if token version is not supported, the token has expired,
                                 or no required decryption keys present in the keys collection
        """
        return self._decrypt_token_into_raw_uid(token, domain_name, dt.datetime.now(tz=dt.timezone.utc))

    def refresh(self):
        """Get the latest encryption keys for advertising tokens.

        This will synchronously connect to the corresponding UID2 service and fetch the latest
        set of encryption keys which can then be used to decrypt advertising tokens using
        the decrypt_token_into_raw_uid() function.

        Returns:
            EncryptionKeysCollection containing the keys
        """
        refresh_response = refresh_bidstream_keys(self._base_url, self._auth_key, self._secret_key)
        if refresh_response.success:
            self._keys = refresh_response.keys

        return refresh_response

    def _refresh_json(self, json_str):
        body = json.loads(json_str)
        refresh_response = parse_keys_json(body['body'])
        if refresh_response.success:
            self._keys = refresh_response.keys

        return refresh_response
