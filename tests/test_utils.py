import base64
import datetime as dt
from datetime import timezone

from uid2_client import EncryptionKey, encrypt, IdentityScope, IdentityType, EncryptionKeysCollection, \
    AdvertisingTokenVersion, UID2TokenGenerator

master_secret = bytes(
    [139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168,
     16, 169, 164, 38, 139, 8, 155])
site_secret = bytes(
    [32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108,
     51, 254, 125, 65, 24, 23, 133])
master_key_id = 164
site_key_id = 165
test_site_key_id = 166
site_id = 9000
site_id2 = 2

example_id = 'ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM='
now = dt.datetime.now(tz=timezone.utc).replace(microsecond=0)
master_key = EncryptionKey(master_key_id, -1, now - dt.timedelta(days=-1), now, now + dt.timedelta(days=1),
                           master_secret, keyset_id=1)
site_key = EncryptionKey(site_key_id, site_id, now - dt.timedelta(days=-1), now, now + dt.timedelta(days=1),
                         site_secret, keyset_id=99999)

master_key2 = EncryptionKey(264, -1, now - dt.timedelta(days=-2), now - dt.timedelta(days=-1),
                            now - dt.timedelta(hours=-1),
                            master_secret, keyset_id=1)
site_key2 = EncryptionKey(site_key_id, site_id, now - dt.timedelta(days=-2), now - dt.timedelta(days=-1),
                          now - dt.timedelta(hours=-1),
                          site_secret, keyset_id=99999)

client_secret = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo="
client_secret_bytes = base64.b64decode(client_secret)
example_uid = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM="
example_email_raw_uid2_v2 = example_uid
example_phone_raw_uid2_v2 = "BFOsW2SkK0egqbfyiALtpti5G/cG+PcEvjkoHl56rEV8"
phone_uid = "BEOGxroPLdcY7LrSiwjY52+X05V0ryELpJmoWAyXiwbZ"

test_cases_all_scopes_all_versions = [
    [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V2],
    [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
    [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4],
    [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V2],
    [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
    [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4]
]

test_cases_all_scopes_v3_v4_versions = [
    [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
    [IdentityScope.UID2, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4],
    [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V3],
    [IdentityScope.EUID, AdvertisingTokenVersion.ADVERTISING_TOKEN_V4]
]

YESTERDAY = now + dt.timedelta(days=-1)
TOMORROW = now + dt.timedelta(days=1)
IN_2_DAYS = now + dt.timedelta(days=2)
IN_3_DAYS = now + dt.timedelta(days=3)


def get_identity_type(token):
    first_char = token[0]
    if 'A' == first_char or 'E' == first_char:
        return IdentityType.Email
    if 'F' == first_char or 'B' == first_char:
        return IdentityType.Phone

    raise Exception("unknown IdentityType")


def get_token_identity_type(uid2, keys):
    encrypted_data_response = encrypt(uid2, IdentityScope.UID2, keys)
    return get_identity_type(encrypted_data_response.encrypted_data)


def key_set_to_json_for_sharing(keys):
    return key_set_to_json_for_sharing_with_header("\"default_keyset_id\": 99999,", site_id, keys)


def key_set_to_json_for_sharing_with_header(default_keyset, caller_site_id, keys):
    return """{{
                    "body": {{
                        "caller_site_id": {0}, 
                        "master_keyset_id": 1,
                        "token_expiry_seconds": 86400,
                        {1}
                        "keys": [{2}        
                        ]
                    }}
                }}""".format(caller_site_id, default_keyset, ",\n".join([format_key(x) for x in keys]))


def format_key(key: EncryptionKey):
    return """
                            {{ 
                                "id": {0},
                                {1} 
                                "created": {2},
                                "activates": {3},
                                "expires": {4},
                                "secret": "{5}"
                            }}""".format(key.key_id,
                                         "" if key.keyset_id is None else '"keyset_id": ' + str(key.keyset_id) + ",",
                                         int(key.created.timestamp()),
                                         int(key.activates.timestamp()),
                                         int(key.expires.timestamp()),
                                         base64.b64encode(key.secret).decode("utf-8"))


def create_default_key_collection(key_set):
    return EncryptionKeysCollection(key_set, IdentityScope.UID2, 9000, 1,
                                    99999, 2)


def generate_uid_token(identity_scope, version, raw_uid=example_uid, identity_established_at=None, generated_at=None, expires_at=None):
    return UID2TokenGenerator.generate_uid_token(raw_uid, master_key, site_id, site_key, identity_scope, version,
                                                 identity_established_at, generated_at, expires_at)
