import base64
import sys

from uid2_client import Uid2Client, IdentityScope
from uid2_client import encrypt_data, decrypt_data

# THIS FILE IS DEPRECATED!
# To learn how to encrypt and decrypt a UID2 sharing token, see sample_sharing_client.py (For sharers. See sample_bidstream_client.py for DSPs)

def _usage():
    print('Usage: python3 sample_encryption.py <base_url> <auth_key> <secret_key> <ad_token> <data>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 5:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
ad_token = sys.argv[4]
str_data = sys.argv[5]

client = Uid2Client(base_url, auth_key, secret_key)
keys = client.refresh_keys()

data = bytes(str_data, 'utf-8')
encrypted = encrypt_data(data, IdentityScope.UID2, keys=keys, advertising_token=ad_token)
decrypted = decrypt_data(encrypted, keys)

print('Encrypted =', encrypted)
print('Decrypted =', decrypted.data)
print('Encrypted at (UTC) =', decrypted.encrypted_at)
