"""Usage
>>> from uid2_client import SharingClient
"""

from uid2_client import encryption
from .refresh_keys_util import *
class SharingClient:
    """Client for interacting with UID2 Sharing services

        You will need to have the base URL of the endpoint and a client key pair (auth/secret)
        to consume web services.

        Methods:
            refresh_keys: Refresh encryption keys from UID2 servers
            encrypt_raw_uid_into_sharing_token: encrypt a raw UID2 into a sharing token
            decrypt_sharing_token_into_raw_uid: decrypt a sharing token
        """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new SharingClient client.

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
    def encrypt_raw_uid_into_sharing_token(self, uid2, keyset_id=None):
        """ Encrypt a UID2 into a sharing token

            Args:
                uid2: the UID2 or EUID to be encrypted
                keys (EncryptionKeysCollection): collection of keys to choose from for encryption
                keyset_id (int) : An optional keyset id to use for the encryption. Will use default keyset if left blank

            Returns (str): Sharing Token
            """
        return encryption.encrypt(uid2, None, self._keys, keyset_id)

    def decrypt_sharing_token_into_raw_uid(self, token):
        """Decrypt sharing token to extract UID2 details.

            Args:
                token (str): sharing token to decrypt

            Returns:
                DecryptedToken: details extracted from the sharing token

            Raises:
                EncryptionError: if token version is not supported, the token has expired,
                                 or no required decryption keys present in the keys collection
        """
        return encryption.decrypt(token, self._keys, None)

    def refresh_keys(self):
        """Get the latest encryption keys for advertising tokens.

        This will synchronously connect to the corresponding UID2 service and fetch the latest
        set of encryption keys which can then be used to decrypt advertising tokens using
        the decrypt_token function.

        Returns:
            EncryptionKeysCollection containing the keys
        """
        self._keys = refresh_keys(self._base_url, self._auth_key, self._secret_key)