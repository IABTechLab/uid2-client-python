import sys

from uid2_client import Uid2PublisherClient
from uid2_client import TokenGenerateResponse
from uid2_client import TokenGenerateInput


def _usage():
    print('Usage: python3 sample_token_generate_refresh.py <base_url> <auth_key> <secret_key>', file=sys.stderr)
    sys.exit(1)


if len(sys.argv) <= 3:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]


publisher_client = Uid2PublisherClient(base_url, auth_key, secret_key)
print("Generating Token")
token_generate_response = publisher_client.generate_token(TokenGenerateInput.from_email("test@email.com"))

status = token_generate_response.status
tokens = token_generate_response.get_identity()
advertising_token = tokens.get_advertising_token()
refresh_token = tokens.get_refresh_token()
refresh_response_key = tokens.get_refresh_response_key()
refresh_from = tokens.get_refresh_from()
refresh_expires = tokens.get_refresh_expires()
identity_expires = tokens.get_identity_expires()
json_string = tokens.get_json_string()

print('Status =', status)
print('Advertising Token =', advertising_token)
print('Refresh Token =', refresh_token)
print('Refresh Response Key =', refresh_response_key)
print('Refresh From =', refresh_from)
print('Refresh Expires =', refresh_expires)
print('Identity Expires =', identity_expires)
print('As Json String =', json_string, "\n")

print("Refreshing Token")
token_refresh_response = publisher_client.refresh_token(tokens)
status = token_refresh_response.status
tokens = token_refresh_response.get_identity()
advertising_token = tokens.get_advertising_token()
refresh_token = tokens.get_refresh_token()
refresh_response_key = tokens.get_refresh_response_key()
refresh_from = tokens.get_refresh_from()
refresh_expires = tokens.get_refresh_expires()
identity_expires = tokens.get_identity_expires()
json_string = tokens.get_json_string()

print('Status =', status)
print('Advertising Token =', advertising_token)
print('Refresh Token =', refresh_token)
print('Refresh Response Key =', refresh_response_key)
print('Refresh From =', refresh_from)
print('Refresh Expires =', refresh_expires)
print('Identity Expires =', identity_expires)
print('As Json String =', json_string)
