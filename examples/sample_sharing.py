import sys

from uid2_client import EuidClientFactory
from uid2_client import Uid2ClientFactory


# this sample client encrypts and decrypts a uid2 to a sharing token
# to demonstrate encryption and decryption for sharers

def _usage():
    print('Usage: python3 sample_encryption.py <base_url> <auth_key> <secret_key> <raw_uid>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
raw_uid = sys.argv[4]

# for EUID use:
# client = EuidClientFactory.create(base_url, auth_key, secret_key)
# for UID2 use:
client = Uid2ClientFactory.create(base_url, auth_key, secret_key)
client.refresh_keys()
new_ad_token = client.encrypt(raw_uid)

print('New Ad Token =', new_ad_token)

decrypt_result = client.decrypt(new_ad_token)

print('Decrypted UID2 =', decrypt_result.uid2)
print('Established =', decrypt_result.established)
print('Site ID =', decrypt_result.site_id)
print('Site Key Site ID =', decrypt_result.site_key_site_id)
