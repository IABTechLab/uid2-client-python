# Copyright (c) 2021 The Trade Desk, Inc
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import base64
import sys

from uid2_client import Uid2Client
from uid2_client import encrypt_data, decrypt_data


def _usage():
    print('Usage: python3 sample_encryption.py <base_url> <auth_key> <ad_token> <data>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 3:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
ad_token = sys.argv[3]
str_data = sys.argv[4]

client = Uid2Client(base_url, auth_key)
keys = client.refresh_keys()

data = bytes(str_data, 'utf-8')
encrypted = encrypt_data(data, keys=keys, advertising_token=ad_token)
decrypted = decrypt_data(encrypted, keys)

print('Encrypted = ', encrypted)
print('Decrypted =', decrypted.data)
print('Encrypted at (UTC) = ', decrypted.encrypted_at)
