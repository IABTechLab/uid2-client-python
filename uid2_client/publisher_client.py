"""Usage
>>> from uid2_client import Uid2PublisherClient
"""

import datetime as dt
from datetime import timezone


from .encryption import _decrypt_gcm
from .request_response_util import *
from .token_generate_response import TokenGenerateResponse
from .token_refresh_response import TokenRefreshResponse
from .input_util import base64_to_byte_array


class Uid2PublisherClient:
    """Client for interacting with UID2 publisher services.

        You will need to have the base URL of the endpoint and a client key pair (auth/secret)
        to consume web services.

        Methods:
            generate_token: generate an advertising token from an email, phone #, or hash
            refresh_token: refresh an advertising token

        Examples:
            Connect to the UID2 service and obtain the latest encryption keys:
            >>> from uid2_client import *
            >>> client = Uid2PublisherClient('https://prod.uidapi.com', 'my-authorization-key', 'my-secret-key')
            >>> response = client.generate_token(TokenGenerateInput.from_email("test@email.com"))
            >>> new_token = client.refresh_token(response.get_identity())
    """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new Uid2PublisherClient client.

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

    def generate_token(self, token_generate_input):
        req, nonce = make_v2_request(self._secret_key, dt.datetime.now(tz=timezone.utc),
                                     token_generate_input.get_as_json_string().encode())
        resp = post(self._base_url, '/v2/token/generate', headers=auth_headers(self._auth_key), data=req)
        resp_body = parse_v2_response(self._secret_key, resp.read(), nonce)
        return TokenGenerateResponse(resp_body)

    def refresh_token(self, current_identity):
        resp = post(self._base_url, '/v2/token/refresh', headers=auth_headers(self._auth_key),
                    data=current_identity.get_refresh_token().encode())
        resp_bytes = base64_to_byte_array(resp.read())
        decrypted = _decrypt_gcm(resp_bytes, base64_to_byte_array(current_identity.get_refresh_response_key()))
        return TokenRefreshResponse(decrypted.decode(), dt.datetime.now(tz=timezone.utc))
