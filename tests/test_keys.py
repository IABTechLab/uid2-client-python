import datetime as dt
from datetime import timezone
import unittest

from uid2_client.keys import *


class TestKeys(unittest.TestCase):

    def test_key_is_active(self):
        created = dt.datetime(2021, 1, 1, 0, 0, 0)
        activates = dt.datetime(2021, 3, 22, 0, 0, 0)
        expires = dt.datetime(2021, 6, 29, 0, 0, 0)
        key = EncryptionKey(101, 201, created, activates, expires, b'123456')
        self.assertFalse(key.is_active(created))
        self.assertFalse(key.is_active(activates - dt.timedelta(seconds=1)))
        self.assertTrue(key.is_active(activates))
        self.assertTrue(key.is_active(activates + dt.timedelta(seconds=1)))
        self.assertTrue(key.is_active(expires - dt.timedelta(seconds=1)))
        self.assertFalse(key.is_active(expires))
        self.assertFalse(key.is_active(expires + dt.timedelta(seconds=1)))


    def test_empty_keys_collection(self):
        keys = EncryptionKeysCollection([])
        self.assertFalse(keys.valid(dt.datetime.now(tz=timezone.utc)))
        self.assertEqual(len(keys), 0)
        self.assertEqual(len(keys.key_ids()), 0)
        self.assertEqual(len(keys.values()), 0)
        self.assertNotIn(123, keys)
        self.assertIsNone(keys.get(123))
        with self.assertRaises(KeyError):
            keys[123]
        self.assertIsNone(keys.get_active_site_key(22, dt.datetime.now(tz=timezone.utc)))


    def test_multiple_keys_in_collection(self):
        now = dt.datetime.now(tz=timezone.utc)
        keys = EncryptionKeysCollection([
            EncryptionKey(123, 201, now - dt.timedelta(days=5), now - dt.timedelta(days=4), now - dt.timedelta(days=3), b'123456'),
            EncryptionKey(124, 202, now - dt.timedelta(days=1), now, now + dt.timedelta(days=1), b'234567')])
        self.assertTrue(keys.valid(now))
        self.assertEqual(len(keys), 2)
        self.assertEqual(len(keys.key_ids()), 2)
        self.assertEqual(len(keys.values()), 2)
        self.assertIn(123, keys)
        self.assertIn(124, keys)
        self.assertNotIn(125, keys)
        self.assertIsNotNone(keys.get(123))
        self.assertIsNotNone(keys.get(124))
        self.assertIsNone(keys.get(125))
        self.assertEqual(keys[123].secret, b'123456')
        self.assertEqual(keys[124].secret, b'234567')
        self.assertIsNone(keys.get_active_site_key(201, now))
        self.assertIsNotNone(keys.get_active_site_key(202, now))
        self.assertIsNone(keys.get_active_site_key(203, now))
        self.assertIsNotNone(keys.get_active_site_key(201, now - dt.timedelta(days=4)))
        self.assertIsNone(keys.get_active_site_key(202, now - dt.timedelta(days=4)))
        self.assertIsNone(keys.get_active_site_key(203, now - dt.timedelta(days=4)))


    def test_site_keys(self):
        now = dt.datetime.now(tz=timezone.utc)
        keys = EncryptionKeysCollection([
            EncryptionKey(122, 200, now, now - dt.timedelta(days=1), now + dt.timedelta(days=3), b'000000'),
            EncryptionKey(123, 201, now, now - dt.timedelta(days=5), now + dt.timedelta(days=3), b'111111'),
            EncryptionKey(124, 201, now, now - dt.timedelta(days=2), now + dt.timedelta(days=3), b'222222'),
            EncryptionKey(125, 201, now, now - dt.timedelta(days=4), now + dt.timedelta(days=3), b'333333'),
            EncryptionKey(126, 201, now, now - dt.timedelta(days=4), now + dt.timedelta(days=7), b'444444')])
        self.assertTrue(keys.valid(now))
        self.assertEqual(len(keys), 5)
        self.assertIsNotNone(keys.get(122))
        self.assertIsNotNone(keys.get(123))
        self.assertIsNotNone(keys.get(124))
        self.assertIsNotNone(keys.get(125))
        self.assertIsNotNone(keys.get(126))
        self.assertIsNone(keys.get_active_site_key(200, now - dt.timedelta(days=2)))
        self.assertEqual(122, keys.get_active_site_key(200, now - dt.timedelta(days=1)).key_id)
        self.assertEqual(122, keys.get_active_site_key(200, now + dt.timedelta(days=0)).key_id)
        self.assertEqual(122, keys.get_active_site_key(200, now + dt.timedelta(days=2)).key_id)
        self.assertIsNone(keys.get_active_site_key(200, now + dt.timedelta(days=3)))
        self.assertIsNone(keys.get_active_site_key(201, now - dt.timedelta(days=6)))
        self.assertEqual(123, keys.get_active_site_key(201, now - dt.timedelta(days=5)).key_id)
        self.assertEqual(126, keys.get_active_site_key(201, now - dt.timedelta(days=4)).key_id)
        self.assertEqual(124, keys.get_active_site_key(201, now - dt.timedelta(days=2)).key_id)
        self.assertEqual(124, keys.get_active_site_key(201, now + dt.timedelta(days=0)).key_id)
        self.assertEqual(126, keys.get_active_site_key(201, now + dt.timedelta(days=3)).key_id)
        self.assertIsNone(keys.get_active_site_key(201, now + dt.timedelta(days=7)))
        self.assertIsNone(keys.get_active_site_key(201, now + dt.timedelta(days=8)))


    def test_non_site_keys(self):
        now = dt.datetime.now(tz=timezone.utc)
        keys = EncryptionKeysCollection([
            EncryptionKey(122, -1, now, now - dt.timedelta(days=9), now + dt.timedelta(days=3), b'000000'),
            EncryptionKey(123, -1, now, now - dt.timedelta(days=5), now + dt.timedelta(days=3), b'111111'),
            EncryptionKey(124, -1, now, now - dt.timedelta(days=8), now + dt.timedelta(days=3), b'222222')])
        self.assertTrue(keys.valid(now))
        self.assertEqual(len(keys), 3)
        self.assertIsNotNone(keys.get(122))
        self.assertIsNotNone(keys.get(123))
        self.assertIsNotNone(keys.get(124))
        self.assertIsNone(keys.get_active_site_key(-1, now))


    def test_all_keys_in_collection_expired(self):
        now = dt.datetime.now(tz=timezone.utc)
        keys = EncryptionKeysCollection([
            EncryptionKey(123, 201, now, now - dt.timedelta(days=5), now - dt.timedelta(days=3), b'123456'),
            EncryptionKey(124, 202, now, now - dt.timedelta(days=1), now - dt.timedelta(days=1), b'234567')])
        self.assertTrue(keys.valid(now - dt.timedelta(days=9)))
        self.assertTrue(keys.valid(now - dt.timedelta(days=2)))
        self.assertFalse(keys.valid(now - dt.timedelta(days=1)))
        self.assertFalse(keys.valid(now - dt.timedelta(days=0)))
