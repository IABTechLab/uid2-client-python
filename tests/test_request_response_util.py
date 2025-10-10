import unittest
from unittest.mock import patch
from importlib.metadata import version, PackageNotFoundError

from uid2_client.request_response_util import auth_headers


class TestRequestResponseUtil(unittest.TestCase):

    def test_auth_headers_packaged_mode(self):
        """Test that the version is correctly retrieved in packaged mode."""
        try:
            # In a test environment, the package might not be fully installed.
            # We get the version directly if available.
            expected_version = version("uid2_client")
        except PackageNotFoundError:
            # If not found, we can't run this specific check, so we skip it.
            self.skipTest("uid2_client package not found, skipping packaged mode test.")

        headers = auth_headers("test_auth_key")
        self.assertEqual(headers['Authorization'], 'Bearer test_auth_key')
        self.assertEqual(headers['X-UID2-Client-Version'], f"uid2-client-python-{expected_version}")

    @patch('uid2_client.request_response_util.metadata.version')
    def test_auth_headers_non_packaged_mode(self, mock_version):
        """Test that the version is set to non-packaged-mode when the package is not found."""
        mock_version.side_effect = PackageNotFoundError
        headers = auth_headers("test_auth_key")
        self.assertEqual(headers['Authorization'], 'Bearer test_auth_key')
        self.assertEqual(headers['X-UID2-Client-Version'], "uid2-client-python-non-packaged-mode")
