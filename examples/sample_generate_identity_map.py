import sys

from uid2_client import IdentityMapClient, IdentityMapInput

# !! Note: This is for an older version of identity map. For the latest version, see sample_generate_identity_map_v3.py
# this sample client takes email addresses as input and generates an IdentityMapResponse object which contains raw uid
# or the reason why it is unmapped

def _usage():
    print('Usage: python3 sample_generate_identity_map.py <base_url> <api_key> <client_secret> <email_1> <email_2> ... <email_n>'
          , file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
api_key = sys.argv[2]
client_secret = sys.argv[3]
email_list = sys.argv[4:]
first_email = sys.argv[4]

client = IdentityMapClient(base_url, api_key, client_secret)

identity_map_response = client.generate_identity_map(IdentityMapInput.from_emails(email_list))

mapped_identities = identity_map_response.mapped_identities
unmapped_identities = identity_map_response.unmapped_identities

mapped_identity = mapped_identities.get(first_email)
if mapped_identity is not None:
    raw_uid = mapped_identity.get_raw_uid()
    print('raw_uid =', raw_uid)
else:
    unmapped_identity = unmapped_identities.get(first_email)
    reason = unmapped_identity.get_reason()
    print('reason =', reason)
