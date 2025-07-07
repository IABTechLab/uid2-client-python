import unittest
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

# Import all the classes we'll be testing from the documentation samples
from uid2_client import (
    Uid2PublisherClient, IdentityMapV3Client, IdentityMapV3Input, IdentityMapV3Response,
    IdentityMapClient, IdentityMapInput, BidstreamClient, SharingClient,
    TokenGenerateInput, IdentityTokens, UnmappedIdentityReason, EncryptionStatus
)

# !!!!! Do not refactor this code if you're not intending to change the SDK docs samples !!!!!

# Tests for sample code as used in https://unifiedid.com/docs/sdks/sdk-ref-python
# The tests are designed to have sections of almost exactly copy/pasted code samples so there are
# unused variables, unnecessary comments, redundant repetition... since those are used in docs for illustration.
# If a test breaks in this file, likely the change breaks one of the samples on the docs site


@unittest.skipIf(
    os.getenv("UID2_BASE_URL") is None or 
    os.getenv("UID2_API_KEY") is None or 
    os.getenv("UID2_SECRET_KEY") is None,
    "Environment variables UID2_BASE_URL, UID2_API_KEY, and UID2_SECRET_KEY must be set"
)
class TestDocSampleCode(unittest.TestCase):

    # Test data constants
    UID2_BASE_URL = os.getenv("UID2_BASE_URL", "")
    UID2_API_KEY = os.getenv("UID2_API_KEY", "")
    UID2_SECRET_KEY = os.getenv("UID2_SECRET_KEY", "")
    
    # Test email addresses - these should be configured in your test environment
    mapped_email = "user@example.com"
    mapped_email2 = "user2@example.com"
    optout_email = "optout@example.com"
    mapped_phone = "+12345678901"
    mapped_phone2 = "+12345678902"
    
    def setUp(self):
        # Setup clients used across multiple tests
        self.identity_map_v3_client = IdentityMapV3Client(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        self.publisher_client = Uid2PublisherClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        self.identity_map_client = IdentityMapClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)

    def test_publisher_basic_usage_example(self):
        # Documentation sdk-ref-python.md Line 142: Create an instance of Uid2PublisherClient
        client = Uid2PublisherClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)

        # Documentation sdk-ref-python.md Line 147: Generate token from email
        token_generate_response = client.generate_token(TokenGenerateInput.from_email("user@example.com").do_not_generate_tokens_for_opted_out())

        self.assertIsNotNone(token_generate_response)

    def test_publisher_client_server_integration_example(self):
        """Test Publisher client-server integration from documentation"""
        client = Uid2PublisherClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        token_generate_response = client.generate_token(TokenGenerateInput.from_email("user@example.com").do_not_generate_tokens_for_opted_out())
        
        # Documentation sdk-ref-python.md Line 165: Get identity JSON string
        identity_json_string = token_generate_response.get_identity_json_string()

        self.assertIsNotNone(identity_json_string)

    def test_publisher_server_side_integration_example(self):
        """Test Publisher server-side integration from documentation"""
        client = Uid2PublisherClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        token_generate_response = client.generate_token(TokenGenerateInput.from_email(self.mapped_email).do_not_generate_tokens_for_opted_out())
        
        # Documentation sdk-ref-python.md Line 176: Store identity JSON string
        identity_json_string = token_generate_response.get_identity_json_string()

        # Documentation sdk-ref-python.md Line 182: Get identity and advertising token
        identity = token_generate_response.get_identity()
        if identity:
            advertising_token = identity.get_advertising_token()
            self.assertIsNotNone(advertising_token)
            
        # Documentation sdk-ref-python.md Line 193: Create IdentityTokens from JSON string
        identity = IdentityTokens.from_json_string(identity_json_string)
            
        # Documentation sdk-ref-python.md Line 198: Check if identity can be refreshed
        if not identity or not identity.is_refreshable():
            pass

        # Documentation sdk-ref-python.md Line 203: Check if refresh is needed
        if identity and identity.is_due_for_refresh():
            # Documentation sdk-ref-python.md Line 208: Refresh the token
            token_refresh_response = client.refresh_token(identity)
                
            # Documentation sdk-ref-python.md Line 212: Store new identity JSON string
            new_identity_json_string = token_refresh_response.get_identity_json_string()
            if new_identity_json_string is None:
                # User has opted out - documentation sdk-ref-python.md Line 214
                is_optout = token_refresh_response.is_optout()
                self.assertTrue(is_optout)

    def test_identity_map_v3_basic_usage_example(self):
        """Test IdentityMapV3Client basic usage from documentation sdk-ref-python.md Map DII to Raw UID2s section"""
        # Documentation sdk-ref-python.md Line 226: Create IdentityMapV3Client
        identity_map_v3_client = IdentityMapV3Client(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        
        # Documentation sdk-ref-python.md Line 231: Create IdentityMapV3Input with emails
        input = IdentityMapV3Input.from_emails(["user@example.com", "user2@example.com"])
        
        # Documentation sdk-ref-python.md Line 245: Generate identity map
        identity_map_response = identity_map_v3_client.generate_identity_map(input)
        
        # Documentation sdk-ref-python.md Line 249: Get mapped and unmapped results
        mapped_identities = identity_map_response.mapped_identities
        unmapped_identities = identity_map_response.unmapped_identities
        
        # Verify basic structure
        self.assertIsNotNone(mapped_identities)
        self.assertIsNotNone(unmapped_identities)
        self.assertTrue(len(mapped_identities) + len(unmapped_identities) == 2)

    def test_identity_map_v3_multi_identity_type_example(self):
        """Test IdentityMapV3Client with multiple identity types from documentation"""
        # Documentation sdk-ref-python.md Line 235: Multi-identity type input
        input = IdentityMapV3Input() \
            .with_email("user@example.com") \
            .with_phone("+12345678901") \
            .with_hashed_email("pre_hashed_email") \
            .with_hashed_phone("pre_hashed_phone")
        
        response = self.identity_map_v3_client.generate_identity_map(input)
        
        # Verify multi-identity type response
        self.assertIsNotNone(response)
        self.assertIsNotNone(response.mapped_identities)
        self.assertIsNotNone(response.unmapped_identities)

    def test_identity_map_v3_response_handling_example(self):
        """Test IdentityMapV3Response handling from documentation"""
        input = IdentityMapV3Input.from_emails([self.mapped_email])
        response = self.identity_map_v3_client.generate_identity_map(input)
        
        # Documentation sdk-ref-python.md Line 254: Process mapped identity results
        mapped_identity = response.mapped_identities.get("user@example.com")
        if mapped_identity is not None:
            current_uid = mapped_identity.current_raw_uid        # Current raw UID2
            previous_uid = mapped_identity.previous_raw_uid      # Previous raw UID2 (Optional, only available for 90 days after rotation)
            refresh_from = mapped_identity.refresh_from          # When to refresh this identity
            
            self.assertIsNotNone(current_uid)
            self.assertIsNotNone(refresh_from)
        else:
            unmapped_identity = response.unmapped_identities.get("user@example.com")
            if unmapped_identity:
                reason = unmapped_identity.reason # OPTOUT, INVALID_IDENTIFIER, or UNKNOWN
                self.assertIsNotNone(reason)

    def test_identity_map_v3_complete_usage_example(self):
        """Test complete usage example from documentation sdk-ref-python.md Usage Example section"""

        # Documentation sdk-ref-python.md Line 272: Example 1: Single identity type
        email_input = IdentityMapV3Input.from_emails(["user@example.com", "optout@example.com"])
        email_response = self.identity_map_v3_client.generate_identity_map(email_input)

        # Documentation sdk-ref-python.md Line 276: Process email results
        for email, identity in email_response.mapped_identities.items():
            print("Email: " + email)
            print("Current UID: " + identity.current_raw_uid)
            print("Previous UID: " + str(identity.previous_raw_uid))
            print("Refresh from: " + str(identity.refresh_from))

        for email, identity in email_response.unmapped_identities.items():
            unmapped_output = "Unmapped email: " + email + " - Reason: " + str(identity.reason)
            self.assertIsNotNone(unmapped_output)

        # Documentation sdk-ref-python.md Line 285: Example 2: Mixed identity types
        mixed_input = IdentityMapV3Input() \
            .with_email("user1@example.com") \
            .with_phone("+12345678901") \
            .with_hashed_email("pre_hashed_email_value") \
            .with_hashed_phone("pre_hashed_phone_value")

        # Documentation sdk-ref-python.md Line 291: Generate identity map
        mixed_response = self.identity_map_v3_client.generate_identity_map(mixed_input)
        self.assertIsNotNone(mixed_response)

    def test_migration_examples(self):
        """Test migration examples from documentation sdk-ref-python.md Required Changes section"""

        # Documentation sdk-ref-python.md Line 322: Change client class
        client = IdentityMapV3Client(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        # Documentation sdk-ref-python.md Line 334: Update input construction
        input = IdentityMapV3Input.from_emails(["user@example.com"])
        
        # Documentation sdk-ref-python.md Line 337: Mix identity types (new capability)
        input = IdentityMapV3Input() \
            .with_email("user@example.com") \
            .with_phone("+12345678901")
            
        # Documentation sdk-ref-python.md Line 346: Update response handling
        response = client.generate_identity_map(input)
        mapped = response.mapped_identities.get("user@example.com")
        current_uid = mapped.current_raw_uid
        previous_uid = mapped.previous_raw_uid
        refresh_from = mapped.refresh_from
            
        self.assertIsNotNone(current_uid)
        self.assertIsNotNone(refresh_from)

        input = IdentityMapV3Input.from_emails([self.optout_email])
        response = self.identity_map_v3_client.generate_identity_map(input)

        # Documentation sdk-ref-python.md Line 358: Update error handling
        unmapped = response.unmapped_identities.get("user@example.com")
        if unmapped:
            reason = unmapped.reason # Enum - OPTOUT, INVALID_IDENTIFIER, UNKNOWN
            raw_reason = unmapped.raw_reason # String version
            
            self.assertIsNotNone(reason)
            self.assertIsNotNone(raw_reason)

    def test_v2_legacy_identity_map_example(self):
        """Test V2 Identity Map legacy usage from documentation sdk-ref-python.md Previous Version section"""
        # Documentation sdk-ref-python.md Line 379: Create V2 IdentityMapClient
        client = IdentityMapClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        
        # Documentation sdk-ref-python.md Line 383: Generate identity map with V2 client
        identity_map_response = client.generate_identity_map(IdentityMapInput.from_emails(["email1@example.com", "email2@example.com"]))
        
        # Documentation sdk-ref-python.md Line 390: Get V2 mapped and unmapped results
        mapped_identities = identity_map_response.mapped_identities
        unmapped_identities = identity_map_response.unmapped_identities
        
        # Documentation sdk-ref-python.md Line 396: V2 response processing
        mapped_identity = mapped_identities.get("email1@example.com")
        if mapped_identity is not None:
            raw_uid = mapped_identity.get_raw_uid()
            self.assertIsNotNone(raw_uid)
        else:
            unmapped_identity = unmapped_identities.get("email1@example.com")
            reason = unmapped_identity.get_reason()
            self.assertIsNotNone(reason)

    def test_v2_salt_bucket_monitoring_example(self):
        """Test V2 salt bucket monitoring from documentation sdk-ref-python.md Monitor Rotated Salt Buckets section"""
        # Documentation sdk-ref-python.md Line 410: Create or reuse IdentityMapClient
        client = IdentityMapClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        
        # Documentation sdk-ref-python.md Line 418: Get identity buckets
        since_timestamp = '2024-08-18T14:30:15+00:00'
        identity_buckets_response = client.get_identity_buckets(datetime.fromisoformat(since_timestamp))
        
        # Documentation sdk-ref-python.md Line 424: Process bucket results
        if identity_buckets_response.buckets:
            for bucket in identity_buckets_response.buckets:
                bucket_id = bucket.get_bucket_id()         # example "bucket_id": "a30od4mNRd"
                last_updated = bucket.get_last_updated()   # example "last_updated" "2024-08-19T22:52:03.109"
                self.assertIsNotNone(bucket_id)
                self.assertIsNotNone(last_updated)
        else:
            print("No bucket was returned")

    def test_dsp_usage_example(self):
        """Test DSP client usage from documentation sdk-ref-python.md Usage for DSPs section"""
        # Documentation sdk-ref-python.md Line 451: Create BidstreamClient
        client = BidstreamClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        
        # Documentation sdk-ref-python.md Line 455: Refresh client
        client.refresh()

        uid_token = "mock_token"
        domainOrAppName = "example.com"

        # Documentation sdk-ref-python.md Line 464: Decrypt token
        decrypted = client.decrypt_token_into_raw_uid(uid_token, domainOrAppName)
        # If decryption succeeded, use the raw UID2.
        if decrypted.success:
            # Use decrypted.uid
            used_uid = decrypted.uid
            self.assertIsNotNone(used_uid)
        else:
            # Check decrypted.status for the failure reason.
            self.assertIsNotNone(decrypted.status)

    def test_sharing_client_usage_example(self):
        """Test Sharing client usage from documentation sdk-ref-python.md Usage for UID2 Sharers section"""
        # Documentation sdk-ref-python.md Line 491: Create SharingClient
        client = SharingClient(self.UID2_BASE_URL, self.UID2_API_KEY, self.UID2_SECRET_KEY)
        
        # Documentation sdk-ref-python.md Line 495: Refresh client
        client.refresh()

        raw_uid = "mock_raw_uid"

        # Documentation sdk-ref-python.md Line 499: Encrypt raw UID (sender)
        encrypted = client.encrypt_raw_uid_into_token(raw_uid)
        # If encryption succeeded, send the UID2 token to the receiver.
        if encrypted.success:
            # Send encrypted.encrypted_data to receiver
            sent_data = encrypted.encrypted_data
            self.assertIsNotNone(sent_data)
        else:
            # Check encrypted.status for the failure reason.
            self.assertIsNotNone(encrypted.status)

        uid_token = "mock_token"  # Mock token for testing

        # Documentation sdk-ref-python.md Line 508: Decrypt token (receiver)
        decrypted = client.decrypt_token_into_raw_uid(uid_token)
        # If decryption succeeded, use the raw UID2.
        if decrypted.success:
            # Use decrypted.uid
            used_uid = decrypted.uid
            self.assertIsNotNone(used_uid)
        else:
            # Check decrypted.status for the failure reason.
            self.assertIsNotNone(decrypted.status)


if __name__ == '__main__':
    unittest.main() 