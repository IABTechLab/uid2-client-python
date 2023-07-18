import datetime as dt
import sys
import time

from uid2_client import EncryptionKeysAutoRefresher
from uid2_client import EuidClientFactory
from uid2_client import Uid2ClientFactory


def _usage():
    print('Usage: python3 sample_auto_refresh.py <base_url> <auth_key> <secret_key> <ad_token>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 4:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
ad_token = sys.argv[4]

# for EUID
client = EuidClientFactory.create(base_url, auth_key, secret_key)
# for UID2
client = Uid2ClientFactory.create(base_url, auth_key, secret_key)
with EncryptionKeysAutoRefresher(client, dt.timedelta(seconds=4), dt.timedelta(seconds=7)) as refresher:
    for i in range(0, 20):
        refresh_result = refresher.current_result()
        if refresh_result.ready:
            print('Keys are ready, last refreshed (UTC):', refresh_result.last_success_time, flush=True)
            result = client.decrypt(ad_token)
            print('UID2 =', result.uid2, flush=True)
        else:
            print('Keys are not ready yet, last error:', refresh_result.last_error[1], flush=True)
        time.sleep(1)
