import json
import unittest
from unittest.mock import patch

from uid2_client import TokenGenerateInput
from uid2_client.input_util import *
import random
import string


class InputNormalizationTests(unittest.TestCase):

    def test_invalid_email_normalization(self):
        invalid_test_cases = ["", " @", "@", "a@", "@b", "@b.com", "+", " ", "+@gmail.com", ".+@gmail.com",
                              "a@ba@z.com"]
        for s in invalid_test_cases:
            print("Negative case " + s)
            with self.assertRaises(ValueError) as context:
                TokenGenerateInput.from_email(s).get_as_json_string()
                self.assertTrue("invalid email address" in context.exception)

    def test_valid_email_normalization(self):
        valid_test_cases = [
            ["TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="],
            ["test.test@test.com", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="],
            ["test.test@gmail.com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["test+test@test.com", "test+test@test.com", "rQ4yzdOz4uG8N54326QyZD6/JwqrXn4lmy34cVCojB8="],
            ["+test@test.com", "+test@test.com", "weFizOVVWKlLfyorbBU8oxYDv4HJtTZCPMyZ4THzUQE="],
            ["test+test@gmail.com", "test@gmail.com", "h5JGBrQTGorO7q6IaFMfu5cSqqB6XTp1aybOD11spnQ="],
            ["testtest@test.com", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="],
            [" testtest@test.com", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="],
            ["testtest@test.com ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="],
            [" testtest@test.com ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="],
            ["  testtest@test.com  ", "testtest@test.com", "d1Lr/s4GLLX3SvQVMoQdIMfbQPMAGZYry+2V+0pZlQg="],
            [" test.test@gmail.com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["test.test@gmail.com ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            [" test.test@gmail.com ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["  test.test@gmail.com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEstTEst@gmail.com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEstTEst@GMail.Com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            [" TEstTEst@GMail.Com  ", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEstTEst@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEst.TEst@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEst.TEst+123@GMail.Com", "testtest@gmail.com", "LkLfFrut8Tc3h/fIvYDiBKSbaMiau/DtaLBPQYszdMw="],
            ["TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="],
            ["TEst.TEST@Test.com ", "test.test@test.com", "dvECjPKZHya0/SIhSGwP0m8SgTv1vzLxPULUOsm880M="],
            ["😊testtest@test.com", "😊testtest@test.com",
             "fAFEUqApQ0V/M9mLj/IO54CgKgtQuARKsOMqtFklD4k="],
            ["testtest@😊test.com", "testtest@😊test.com",
             "tcng5pttf7Y2z4ylZTROvIMw1+IVrMpR4D1KeXSrdiM="],
            ["testtest@test.com😊", "testtest@test.com😊",
             "0qI21FPLkuez/8RswfmircHPYz9Dtf7/Nch1rSWEQf0="],
        ]

        for test_case in valid_test_cases:
            print(f"Positive Test case {test_case[0]} Expected: {test_case[1]}")
            normalized = normalize_email_string(test_case[0])
            json_string = TokenGenerateInput.from_email(test_case[0]).get_as_json_string()
            hashed = json.loads(json_string)["email_hash"]
            self.assertEqual(test_case[1], normalized)
            self.assertEqual(test_case[2], hashed)


    def test_phone_number_is_normalized_negative(self):
        test_cases = [
            None,
            "",
            "asdaksjdakfj",
            "DH5qQFhi5ALrdqcPiib8cy0Hwykx6frpqxWCkR0uijs",
            "QFhi5ALrdqcPiib8cy0Hwykx6frpqxWCkR0uijs",
            "06a418f467a14e1631a317b107548a1039d26f12ea45301ab14e7684b36ede58",
            "0C7E6A405862E402EB76A70F8A26FC732D07C32931E9FAE9AB1582911D2E8A3B",
            "+",
            "12345678",
            "123456789",
            "1234567890",
            "+12345678",
            "+123456789",
            "+ 12345678",
            "+ 123456789",
            "+ 1234 5678",
            "+ 1234 56789",
            "+1234567890123456",
            "+1234567890A",
            "+1234567890 ",
            "+1234567890+",
            "+12345+67890",
            "555-555-5555",
            "(555) 555-5555"
        ]

        for s in test_cases:
            print(f"Testing phone number '{s}'")
            with self.assertRaises(ValueError) as context:
                TokenGenerateInput.from_phone(s).get_as_json_string()
                self.assertTrue("phone number is not normalized" in context.exception)

    def test_phone_number_is_normalized_positive(self):
        test_cases = [
            "+1234567890",
            "+12345678901",
            "+123456789012",
            "+1234567890123",
            "+12345678901234",
            "+123456789012345"
        ]

        for s in test_cases:
            print(f"Testing phone number '{s}'")
            self.assertTrue(is_phone_number_normalized(s))

