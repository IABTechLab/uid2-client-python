import sys

from uid2_client import Uid2Client
from uid2_client import decrypt
from uid2_client import encrypt
from uid2_client.identity_scope import IdentityScope

# this sample client decrypts an advertising token into a raw UID2
# and then encrypts it into a new advertising token
# to demonstrate decryption (for DSPs and sharers) and encryption (sharers only).

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

# Not required for DSPs, but for those using UID2 sharing functionality this shows how to encrypt a raw UID2 into
# a new advertising token.
# IdentityScope could be UID2 or EUID
new_ad_token = encrypt(decrypt_result.uid2, IdentityScope.UID2, keys)
print('New Ad Token =', new_ad_token)
