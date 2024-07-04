import base64
import datetime as dt
import json
from datetime import timezone

from .identity_buckets_response import IdentityBucketsResponse
from .identity_map_response import IdentityMapResponse

from uid2_client import auth_headers, make_v2_request, post, parse_v2_response, get_datetime_utc_iso_format


class IdentityMapClient:
    """Client for interacting with UID Identity Map services

        You will need to have the base URL of the endpoint and a client API key
        and secret to consume web services.

        Methods:
            generate_identity_map: Generate identity map
    """

    def __init__(self, base_url, api_key, client_secret):
        """Create a new IdentityMapClient client.

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

    def generate_identity_map(self, identity_map_input):
        req, nonce = make_v2_request(self._client_secret, dt.datetime.now(tz=timezone.utc),
                                     identity_map_input.get_identity_map_input_as_json_string().encode())
        resp = post(self._base_url, '/v2/identity/map', headers=auth_headers(self._api_key), data=req)
        resp_body = parse_v2_response(self._client_secret, resp.read(), nonce)
        return IdentityMapResponse(resp_body, identity_map_input)

    def get_identity_buckets(self, since_timestamp):
        req, nonce = make_v2_request(self._client_secret, dt.datetime.now(tz=timezone.utc),
                                     json.dumps({"since_timestamp": get_datetime_utc_iso_format(since_timestamp)}).encode())
        resp = post(self._base_url, '/v2/identity/buckets', headers=auth_headers(self._api_key), data=req)
        resp_body = parse_v2_response(self._client_secret, resp.read(), nonce)
        return IdentityBucketsResponse(resp_body)
