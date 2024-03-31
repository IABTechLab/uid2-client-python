import sys

from uid2_client import SharingClient


# this sample client encrypts and decrypts a raw uid to a sharing token
# to demonstrate encryption and decryption for sharers

def _usage():
    print('Usage: python3 sample_sharing_client.py <base_url> <auth_key> <secret_key> <raw_uid>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
raw_uid = sys.argv[4]

client = SharingClient(base_url, auth_key, secret_key)
client.refresh()
encryption_data_response = client.encrypt_raw_uid_into_token(raw_uid)

print('New Sharing Token =', encryption_data_response.encrypted_data)

decrypt_result = client.decrypt_token_into_raw_uid(encryption_data_response.encrypted_data)

print('Decrypted UID =', decrypt_result.uid)
print('Established =', decrypt_result.established)
print('Site ID =', decrypt_result.site_id)
