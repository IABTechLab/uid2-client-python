import datetime
import sys

from uid2_client import IdentityMapClient


# this sample client takes date time as input and generates an IdentityBucketsResponse object which contains
# a list of buckets

def _usage():
    print('Usage: python3 sample_get_identity_buckets.py <base_url> <api_key> <client_secret> <year> <month> <day> <hour> <minute> <second>'
          , file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 9:
    _usage()

base_url = sys.argv[1]
api_key = sys.argv[2]
client_secret = sys.argv[3]
year = int(sys.argv[4])
month = int(sys.argv[5])
day = int(sys.argv[6])
hour = int(sys.argv[7])
minute = int(sys.argv[8])
second = int(sys.argv[9])

client = IdentityMapClient(base_url, api_key, client_secret)

identity_buckets_response = client.get_identity_buckets(datetime.datetime(year, month, day, hour, minute, second))

bucket = identity_buckets_response.buckets[0]
print("The bucket id of the first bucket: ", bucket.get_bucket_id())
print("The last updated timestamp of the first bucket: ", bucket.get_last_updated())
