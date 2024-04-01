import sys

from uid2_client import BidstreamClient


# this sample client decrypts an advertising token into a raw UID2
# to demonstrate decryption for DSPs

def _usage():
    print('Usage: python3 sample_bidstream_client.py <base_url> <auth_key> <secret_key> <domain_name> <ad_token>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) < 6:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
domain_name = sys.argv[4]
ad_token = sys.argv[5]

client = BidstreamClient(base_url, auth_key, secret_key)
refresh_response = client.refresh()
if not refresh_response.success:
    print('Failed to refresh keys due to =', refresh_response.reason)
    sys.exit(1)

decrypt_result = client.decrypt_token_into_raw_uid(ad_token, domain_name)

print('Status =', decrypt_result.status)
print('UID =', decrypt_result.uid)
print('Established =', decrypt_result.established)
print('Site ID =', decrypt_result.site_id)
print('Identity Scope =', decrypt_result.identity_scope)
print('Identity Type =', decrypt_result.identity_type)
print('Advertising Token Version =', decrypt_result.advertising_token_version)
print('Is Client Side Generated =', decrypt_result.is_client_side_generated)
