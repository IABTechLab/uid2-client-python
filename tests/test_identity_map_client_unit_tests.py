import base64
import json
import unittest
import datetime as dt
from unittest.mock import patch, MagicMock

from uid2_client import IdentityMapClient, get_datetime_utc_iso_format


class IdentityMapUnitTests(unittest.TestCase):
    UID2_SECRET_KEY = base64.b64encode(b"UID2_CLIENT_SECRET").decode()
    identity_map_client = IdentityMapClient("UID2_BASE_URL", "UID2_API_KEY", UID2_SECRET_KEY)

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

    @patch('uid2_client.identity_map_client.make_v2_request')
    @patch('uid2_client.identity_map_client.post')
    @patch('uid2_client.identity_map_client.parse_v2_response')
    def test_identity_buckets_request(self, mock_parse_v2_response, mock_post, mock_make_v2_request):
        expected_req = b'{"since_timestamp": "2024-07-02T14:30:15.123456"}'
        test_cases = ["2024-07-02T14:30:15.123456+00:00", "2024-07-02 09:30:15.123456-05:00",
                      "2024-07-02T08:30:15.123456-06:00", "2024-07-02T10:30:15.123456-04:00",
                      "2024-07-02T06:30:15.123456-08:00", "2024-07-02T23:30:15.123456+09:00",
                      "2024-07-03T00:30:15.123456+10:00", "2024-07-02T20:00:15.123456+05:30"]
        mock_req = b'mocked_request_data'
        mock_nonce = 'mocked_nonce'
        mock_make_v2_request.return_value = (mock_req, mock_nonce)
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"mocked": "response"}'
        mock_post.return_value = mock_response
        mock_parse_v2_response.return_value = b'{"body":[],"status":"success"}'
        for timestamp in test_cases:
            self.identity_map_client.get_identity_buckets(dt.datetime.fromisoformat(timestamp))
            called_args, called_kwargs = mock_make_v2_request.call_args
            self.assertEqual(expected_req, called_args[2])
