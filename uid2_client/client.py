"""Internal module for holding the Uid2Client class.

Do not use this module directly, import through uid2_client module instead, e.g.

>>> from uid2_client import Uid2Client
"""

import json

from .encryption import *
from .identity_scope import IdentityScope
from .refresh_keys_util import refresh_sharing_keys, parse_keys_json
from .request_response_util import *


def _make_dt(timestamp):
    return dt.datetime.fromtimestamp(timestamp, tz=timezone.utc)


# DO NOT INSTANTIATE THIS CLASS DIRECTLY, USE Uid2ClientFactory OR EuidClientFactory
class Uid2Client:
    """Client for interacting with UID2 services.

    You will need to have the base URL of the endpoint and a client key pair (auth/secret)
    to consume web services.

    Methods:
        refresh_keys: get the latest encryption keys for decrypting advertising tokens
        refresh_json: parse json to get encryption keys
        encrypt: encrypt a uid to a token
        decrypt: decrypt a token to a uid

    Examples:
        Connect to the UID2 service and obtain the latest encryption keys:
        >>> from uid2_client import *
        >>> client = Uid2Client('https://prod.uidapi.com', 'my-authorization-key', 'my-secret-key')
        >>> keys = client.refresh_keys()
        >>> uid2 = decrypt('some-ad-token', keys).uid
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
        self._identity_scope = None
        self._keys = None

    @classmethod
    def create_uid2(cls, base_url, auth_key, secret_key):
        client = cls(base_url, auth_key, secret_key)
        client._identity_scope = IdentityScope.UID2
        return client

    @classmethod
    def create_euid(cls, base_url, auth_key, secret_key):
        client = cls(base_url, auth_key, secret_key)
        client._identity_scope = IdentityScope.EUID
        return client

    def refresh_keys(self):
        """Get the latest encryption keys for advertising tokens.

        This will synchronously connect to the corresponding UID2 service and fetch the latest
        set of encryption keys which can then be used to decrypt advertising tokens using
        the decrypt_token function.

        Returns:
            EncryptionKeysCollection containing the keys
        """
        refresh_response = refresh_sharing_keys(self._base_url, self._auth_key, self._secret_key)
        if refresh_response.success:
            self._keys = refresh_response.keys
            return self._keys
        else:
            raise Exception(refresh_response.reason)

    def refresh_json(self, json_str):
        body = json.loads(json_str)
        refresh_response = parse_keys_json(body['body'])
        if refresh_response.success:
            self._keys = refresh_response.keys
            return refresh_response.keys
        else:
            raise Exception(refresh_response.reason)

    def encrypt(self, uid2, keyset_id=None):
        """ Encrypt an UID2 into a sharing token

            Args:
                uid2: the UID2 or EUID to be encrypted
                keyset_id (int) : An optional keyset id to use for the encryption. Will use default keyset if left blank

            Returns (str): Sharing Token
            """
        result = encrypt(uid2, self._identity_scope, self._keys, keyset_id)
        if result.status == EncryptionStatus.SUCCESS:
            return result.encrypted_data
        else:
            raise EncryptionError(result.status.value)

    def decrypt(self, token):
        """Decrypt advertising token to extract UID2 details.

            Args:
                token (str): advertising token to decrypt

            Returns:
                DecryptedToken: details extracted from the advertising token

            Raises:
                EncryptionError: if token version is not supported, the token has expired,
                                 or no required decryption keys present in the keys collection
        """
        return decrypt(token, self._keys)


class Uid2ClientError(Exception):
    """Raised for problems encountered while interacting with UID2 services."""
