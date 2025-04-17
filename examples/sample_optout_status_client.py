import json
import sys

from uid2_client import OptOutStatusClient


def _usage():
    print(
        'Usage: python3 sample_optout_status_client.py <base_url> <api_key> <client_secret> <advertising_id_1> <advertising_id_2> ... <advertising_id_3>'
        , file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
api_key = sys.argv[2]
client_secret = sys.argv[3]
advertising_ids = sys.argv[4:]

optout_status_client = OptOutStatusClient(base_url, api_key, client_secret)

response_json = json.loads(optout_status_client.get_optout_status(advertising_ids))
print(json.dumps(response_json, indent=2))
