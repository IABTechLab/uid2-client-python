import sys

from uid2_client import Uid2Client
from uid2_client import decrypt
from uid2_client import encrypt

# this sample client will decrypt a given advertising token into raw UID2
# and then encrypt into a new advertising token
# in order to show the decryption (for DSPs and Sharers) and encryption (Sharers only) functionalities

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
decrypt_result = decrypt(ad_token, keys)

print('UID2 =', decrypt_result.uid2)
print('Established =', decrypt_result.established)
print('Site ID =', decrypt_result.site_id)
print('Site Key Site ID =', decrypt_result.site_key_site_id)

# Not required for DSPs but if you are using UID2 Sharing functionality then this is how to encrypt raw UID2 into
# a new advertising token
new_ad_token = encrypt(ad_token, decrypt_result.uid2)
print('New Ad Token =', new_ad_token)
