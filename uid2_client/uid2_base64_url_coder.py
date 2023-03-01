import base64


class Uid2Base64UrlCoder:
    # always use this interface to encode/decode Base64URL standard with no padding
    # as specified on https://www.rfc-editor.org/rfc/rfc4648#section-5
    # as unit test assumes that we are testing the encoding/decoding lib used here

    @staticmethod
    def encode(input):
        encoded_token = base64.urlsafe_b64encode(input).decode('ascii')
        # urlsafe_b64encode doesn't remove the '=' padding per the spec so we should remove it
        # as '=' is a reserved char in URL spec
        count = 0
        for i in range(3):
            if encoded_token[len(encoded_token) - 1 - i] == '=':
                count = count + 1
        # encoded_token[:-0] will empty the whole string!
        if count > 0:
            return encoded_token[:-count]
        return encoded_token

    @staticmethod
    def decode(token):
        input_size_mod4 = len(token) % 4;
        if input_size_mod4 > 0:
            padding_needed = 4 - input_size_mod4
            padding = ""
            for i in range(padding_needed):
                padding = padding + "="
            padded_token = token + padding
            return base64.urlsafe_b64decode(padded_token)
        return base64.urlsafe_b64decode(token)
