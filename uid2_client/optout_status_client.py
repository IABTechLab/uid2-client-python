import base64
import datetime as dt
from datetime import timezone
import json

from uid2_client import auth_headers, make_v2_request, post, parse_v2_response


class OptOutStatusClient:
    """Client for interacting with UID Optout status

        You will need to have the base URL of the endpoint and a client API key
        and secret to consume web services.

        Methods:
            get_optout_status: Get Opt Out Status of advertising_ids
    """

    def __init__(self, base_url, api_key, client_secret):
        """Create a new OptOutStatusClient client.

        Args:
            base_url (str): base URL for all requests to UID services (e.g. 'https://prod.uidapi.com')
            api_key (str): api key for consuming the UID services
            client_secret (str): client secret for consuming the UID services

        Note:
            Your authorization key will determine which UID services you are allowed to use.
        """
        self._base_url = base_url
        self._api_key = api_key
        self._client_secret = base64.b64decode(client_secret)

    def get_optout_status(self, advertising_ids):
        request_payload = {
            'advertising_ids': advertising_ids
        }
        req, nonce = make_v2_request(self._client_secret, dt.datetime.now(tz=timezone.utc),
                                     json.dumps(request_payload).encode())
        resp = post(self._base_url, '/v2/optout/status', headers=auth_headers(self._api_key), data=req)
        return parse_v2_response(self._client_secret, resp.read(), nonce)
