"""Usage
>>> from uid2_client import BidStreamClient
"""
import base64

from .encryption import decrypt_token
from .client_type import ClientType
from .refresh_keys_util import refresh_bidstream_keys


class BidStreamClient:
    """Client for interacting with UID2 BidStream services

        You will need to have the base URL of the endpoint and a client key pair (auth/secret)
        to consume web services.

        Methods:
            refresh_keys: Refresh encryption keys from UID2 servers
            decrypt_ad_token_into_raw_uid: decrypt an advertising token
    """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new BidStreamClient client.

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

    def decrypt_ad_token_into_raw_uid(self, token, domain_name):
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
        return decrypt_token(token, self._keys, domain_name, ClientType.Bidstream)

    def refresh_keys(self):
        """Get the latest encryption keys for advertising tokens.

        This will synchronously connect to the corresponding UID2 service and fetch the latest
        set of encryption keys which can then be used to decrypt advertising tokens using
        the decrypt_token function.

        Returns:
            EncryptionKeysCollection containing the keys
        """
        self._keys = refresh_bidstream_keys(self._base_url, self._auth_key, self._secret_key)
