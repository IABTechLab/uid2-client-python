import unittest
from uid2_client import Uid2Client
import datetime as dt
import base64


def _make_dt(timestamp):
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)


class TestKeyParse(unittest.TestCase):
    def test_key_parse(self):
        s = "{ \"body\": { " + \
            "\"identity_scope\": \"UID2\", " + \
            "\"caller_site_id\": 11, " + \
            "\"master_keyset_id\": 1, " + \
            "\"default_keyset_id\": 99999, " + \
            "\"token_expiry_seconds\": 1728000, " + \
            "\"keys\": [ " + \
            "{ " + \
            "\"id\": 3, " + \
            "\"keyset_id\": 99999, " + \
            "\"created\": 1609459200, " + \
            "\"activates\": 1609459210, " + \
            "\"expires\": 1893456000, " + \
            "\"secret\": \"o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=\"" + \
            "}, " + \
            "{ " + \
            "\"id\": 2, " + \
            "\"keyset_id\": 1, " + \
            "\"created\": 1609458200, " + \
            "\"activates\": 1609459220, " + \
            "\"expires\": 1893457000, " + \
            "\"secret\": \"DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=\"" + \
            "} " + \
            "] " + \
            "}, " + \
            "\"status\": \"success\" }"

        client = Uid2Client("ep", "ak", "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=")

        now = dt.datetime.now(tz=dt.timezone.utc)

        key_containter = client.refresh_json(s)

        self.assertEqual(11, key_containter.get_caller_site_id())
        masterKey = key_containter.get_master_key(now)
        self.assertEqual(2, masterKey.key_id)

        default_key = key_containter.get_default_keyset_key(now)
        self.assertEqual(3, default_key.key_id)
        self.assertEqual(1728000, key_containter.get_token_expiry_seconds())

        key = key_containter.get(3)
        self.assertEqual(99999, key.keyset_id)
        self.assertEqual(_make_dt(1609459200), key.created)
        self.assertEqual(_make_dt(1609459210), key.activates)
        self.assertEqual(_make_dt(1893456000), key.expires)
        self.assertEqual("o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=", base64.b64encode(key.secret).decode("ascii"))

        key = key_containter.get(2)
        self.assertEqual(1, key.keyset_id)
        self.assertEqual(_make_dt(1609458200), key.created)
        self.assertEqual(_make_dt(1609459220), key.activates)
        self.assertEqual(_make_dt(1893457000), key.expires)
        self.assertEqual("DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=", base64.b64encode(key.secret).decode("ascii"))

    def test_parse_key_error(self):
        client = Uid2Client("ep", "ak", "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=")
        self.assertRaises(BaseException, client.refresh_json, "{\"status\": \"error\"}")
        self.assertRaises(BaseException, client.refresh_json, "{\"body\": \"error\"}")
        self.assertRaises(BaseException, client.refresh_json, "{\"body\": [1, 2, 3]}")
        self.assertRaises(BaseException, client.refresh_json, "{\"body\": [{}]}")
        self.assertRaises(BaseException, client.refresh_json, "{\"body\": [{\"id\": \"test\"}]}")
        self.assertRaises(BaseException, client.refresh_json, "{\"body\": [{\"id\": 5}]}")