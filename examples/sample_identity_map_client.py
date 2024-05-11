import sys

from uid2_client import IdentityMapClient, IdentityMapInput


# this sample client takes email addresses or phone numbers as input and generates an IdentityMapResponse object
# which contains raw uid or the reason why it is unmapped

def _usage():
    print('Usage: python3 sample_sharing_client.py <base_url> <auth_key> <secret_key> <email_list>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
email_list = sys.argv[4:]
first_email = sys.argv[4]

client = IdentityMapClient(base_url, auth_key, secret_key)

identity_map_response = client.generate_identity_map(IdentityMapInput.from_emails(email_list))

mapped_identities = identity_map_response.mapped_identities
unmapped_identities = identity_map_response.unmapped_identities

mapped_identity = mapped_identities.get(first_email)
if mapped_identity is not None:
    raw_uid = mapped_identity.get_raw_id()
    print('raw_uid =', raw_uid)
else:
    unmapped_identity = unmapped_identities.get(first_email)
    reason = unmapped_identity.get_reason()
    print('reason =', reason)

