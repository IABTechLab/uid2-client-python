# THIS FILE IS DEPRECATED!
# To learn how to decrypt a UID2 advertising token for DSPs, see sample_bidstream_client.py

import sys

from uid2_client.euid_client_factory import EuidClientFactory
from uid2_client.uid2_client_factory import Uid2ClientFactory


# this sample client decrypts an advertising token into a raw UID2
# to demonstrate decryption for DSPs

def _usage():
    print('Usage: python3 sample_client.py <base_url> <auth_key> <secret_key> <ad_token>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
ad_token = sys.argv[4]

# for EUID use:
# client = EuidClientFactory.create(base_url, auth_key, secret_key)
# for UID2 use:
client = Uid2ClientFactory.create(base_url, auth_key, secret_key)
client.refresh_keys()
decrypt_result = client.decrypt(ad_token)

print('UID =', decrypt_result.uid)
print('Established =', decrypt_result.established)
print('Site ID =', decrypt_result.site_id)
print('Site Key Site ID =', decrypt_result.site_key_site_id)
