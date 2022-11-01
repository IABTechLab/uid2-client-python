import sys

from uid2_client import Uid2Client
from uid2_client import decrypt_token


def _usage():
    print('Usage: python3 sample_client.py <base_url> <auth_key> <secret_key> <ad_token>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
ad_token = sys.argv[4]

client = Uid2Client(base_url, auth_key, secret_key)
keys = client.refresh_keys()
result = decrypt_token(ad_token, keys)

print('UID2 =', result.uid2)
print('Established =', result.established)
print('Site ID =', result.site_id)
print('Site Key Site ID =', result.site_key_site_id)
