import datetime as dt
from datetime import timezone

from .request_response_util import *
from .identity_map_v3_input import IdentityMapV3Input
from .identity_map_v3_response import IdentityMapV3Response


class IdentityMapV3Client:
    """Client for interacting with UID2 Identity Map v3 services

    You will need to have the base URL of the endpoint and a client API key
    and secret to consume web services.

    Methods:
        generate_identity_map: Generate identity map
    """

    def __init__(self, base_url: str, api_key: str, client_secret: str):
        """Create a new IdentityMapV3Client.

        Args:
            base_url (str): base URL for all requests to UID services (e.g. 'https://prod.uidapi.com')
            api_key (str): api key for consuming the UID services
            client_secret (str): client secret for consuming the UID services

        Note:
            Your authorization key will determine which UID2 services you are allowed to use.
        """
        self._base_url = base_url
        self._api_key = api_key
        self._client_secret = base64.b64decode(client_secret)

    def generate_identity_map(self, identity_map_input: IdentityMapV3Input) -> IdentityMapV3Response:
        envelope = create_envelope(
            self._client_secret, 
            dt.datetime.now(tz=timezone.utc),
            identity_map_input.get_identity_map_input_as_json_string().encode()
        )
        uid2_response = make_binary_request(self._base_url, '/v3/identity/map', headers=auth_headers(self._api_key), envelope=envelope)
        decrypted_response = parse_response(self._client_secret, uid2_response, envelope.nonce)
        return IdentityMapV3Response(decrypted_response, identity_map_input)
