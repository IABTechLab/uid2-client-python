import base64
import datetime as dt
from datetime import timezone

from .identity_map_response import IdentityMapResponse

from uid2_client import auth_headers, make_v2_request, post, parse_v2_response


class IdentityMapClient:
    """Client for interacting with UID2 Identity Map services

        You will need to have the base URL of the endpoint and a client API key
        and secret to consume web services.

        Methods:
            generate_identity_map: Generate identity map
    """

    def __init__(self, base_url, auth_key, secret_key):
        """Create a new IdentityMapClient client.

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

    def generate_identity_map(self, identity_map_input):
        req, nonce = make_v2_request(self._secret_key, dt.datetime.now(tz=timezone.utc),
                                     identity_map_input.get_identity_map_input_as_json_string().encode())
        resp = post(self._base_url, '/v2/identity/map', headers=auth_headers(self._auth_key), data=req)
        resp_body = parse_v2_response(self._secret_key, resp.read(), nonce)
        return IdentityMapResponse(resp_body, identity_map_input)
