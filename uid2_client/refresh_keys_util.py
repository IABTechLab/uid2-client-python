import datetime as dt
import json
from datetime import timezone

from .keys import EncryptionKey, EncryptionKeysCollection
from .request_response_util import *
from .identity_scope import IdentityScope

def _make_dt(timestamp):
    return dt.datetime.fromtimestamp(timestamp, tz=timezone.utc)


def parse_keys_json(resp_body):
    keys = []
    for key in resp_body["keys"]:
        keyset_id = None
        if "keyset_id" in key:
            keyset_id = key["keyset_id"]
        key = EncryptionKey(key['id'],
                            key.get('site_id', -1),
                            _make_dt(key['created']),
                            _make_dt(key['activates']),
                            _make_dt(key['expires']),
                            base64.b64decode(key['secret']),
                            keyset_id)
        keys.append(key)
        identity_scope = IdentityScope.UID2
        if resp_body["identity_scope"] == "EUID":
            identity_scope = IdentityScope.EUID
    return EncryptionKeysCollection(keys, identity_scope, resp_body["caller_site_id"], resp_body["master_keyset_id"],
                                    resp_body.get("default_keyset_id", None), resp_body["token_expiry_seconds"])


def refresh_keys(base_url, auth_key, secret_key):
    """Get the latest encryption keys for advertising tokens.

    This will synchronously connect to the corresponding UID2 service and fetch the latest
    set of encryption keys which can then be used to decrypt advertising tokens using
    the decrypt_token function.

    Returns:
        EncryptionKeysCollection containing the keys
    """
    req, nonce = make_v2_request(secret_key, dt.datetime.now(tz=timezone.utc))
    resp = post(base_url, '/v2/key/sharing', headers=auth_headers(auth_key), data=req)
    resp_body = json.loads(parse_v2_response(secret_key, resp.read(), nonce)).get('body')
    keys = parse_keys_json(resp_body)
    return keys
