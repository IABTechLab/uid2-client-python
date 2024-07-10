import sys
from datetime import datetime

from uid2_client import IdentityMapClient


# this sample client takes timestamp string as input and generates an IdentityBucketsResponse object which contains
# a list of buckets, the timestamp string in the format YYYY-MM-DD[*HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]],
# for example: local timezone: 2024-07-02, UTC: 2024-07-02T14:30:15.123456+00:00, EST: 2024-07-02T14:30:15.123456-05:00

def _usage():
    print('Usage: python3 sample_get_identity_buckets.py <base_url> <api_key> <client_secret> <timestamp>'
          , file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
api_key = sys.argv[2]
client_secret = sys.argv[3]
timestamp = sys.argv[4]

client = IdentityMapClient(base_url, api_key, client_secret)

identity_buckets_response = client.get_identity_buckets(datetime.fromisoformat(timestamp))

if identity_buckets_response.buckets:
    for bucket in identity_buckets_response.buckets:
        print("The bucket id of the bucket: ", bucket.get_bucket_id())
        print("The last updated timestamp of the bucket: ", bucket.get_last_updated())
else:
    print("No bucket was returned")
