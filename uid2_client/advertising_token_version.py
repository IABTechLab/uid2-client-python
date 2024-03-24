from enum import IntEnum

class AdvertisingTokenVersion(IntEnum):
    # Not stored in token
    ADVERTISING_TOKEN_V2 = 2
    # showing as "AHA..." in the Base64 Encoding (Base64 'H' is 000111 and 112 is 01110000)
    ADVERTISING_TOKEN_V3 = 112
    # showing as "AIA..." in the Base64URL Encoding ('H' is followed by 'I' hence
    # this choice for the next token version) (Base64 'I' is 001000 and 128 is 10000000)
    ADVERTISING_TOKEN_V4 = 128

