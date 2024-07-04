import unittest
import datetime as dt

from uid2_client import IdentityMapClient, get_datetime_utc_iso_format


class IdentityMapUnitTests(unittest.TestCase):
    identity_map_client = IdentityMapClient("UID2_BASE_URL", "UID2_API_KEY", "wJ0hP19QU4hmpB64Y3fV2dAed8t/mupw3sjN5jNRFzg=")

    def test_identity_buckets_invalid_timestamp(self):
        test_cases = ["1234567890",
                      1234567890,
                      2024.7,
                      "2024-7-1",
                      "2024-07-01T12:00:00",
                      [2024, 7, 1, 12, 0, 0],
                      None]
        for timestamp in test_cases:
            self.assertRaises(AttributeError, self.identity_map_client.get_identity_buckets,
                              timestamp)

    def test_get_datetime_utc_iso_format_timestamp(self):
        expected_timestamp = "2024-07-02T14:30:15.123456"
        test_cases = ["2024-07-02T14:30:15.123456+00:00", "2024-07-02 09:30:15.123456-05:00",
                      "2024-07-02T08:30:15.123456-06:00", "2024-07-02T10:30:15.123456-04:00",
                      "2024-07-02T06:30:15.123456-08:00", "2024-07-02T23:30:15.123456+09:00",
                      "2024-07-03T00:30:15.123456+10:00", "2024-07-02T20:00:15.123456+05:30"]
        for timestamp_str in test_cases:
            timestamp = dt.datetime.fromisoformat(timestamp_str)
            iso_format_timestamp = get_datetime_utc_iso_format(timestamp)
            self.assertEqual(expected_timestamp, iso_format_timestamp)

