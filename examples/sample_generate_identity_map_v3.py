import sys

from uid2_client import IdentityMapV3Client, IdentityMapV3Input

# !! Note: This is for the newest version of identity map. For the previous version, see sample_generate_identity_map.py
# this sample client takes email addresses as input and generates an IdentityMapV3Response object which contains raw uid
# or the reason why it is unmapped

def _usage():
    print('Usage: python3 sample_generate_identity_map_v3.py <base_url> <api_key> <client_secret> <email_1> <email_2> ... <email_n>'
          , file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
api_key = sys.argv[2]
client_secret = sys.argv[3]
email_list = sys.argv[4:]
first_email = sys.argv[4]

client = IdentityMapV3Client(base_url, api_key, client_secret)

identity_map_response = client.generate_identity_map(IdentityMapV3Input.from_emails(email_list))

mapped_identities = identity_map_response.mapped_identities
unmapped_identities = identity_map_response.unmapped_identities

mapped_identity = mapped_identities.get(first_email)
if mapped_identity is not None:
    current_uid = mapped_identity.current_raw_uid
    previous_uid = mapped_identity.previous_raw_uid
    refresh_from = mapped_identity.refresh_from
    print('current_uid =', current_uid)
    print('previous_uid =', previous_uid)
    print('refresh_from =', refresh_from)
else:
    unmapped_identity = unmapped_identities.get(first_email)
    reason = unmapped_identity.reason
    print('reason =', reason)
