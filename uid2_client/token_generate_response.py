import json

from uid2_client.identity_tokens import IdentityTokens


class TokenGenerateResponse:
    def __init__(self, response):
        response_json = json.loads(response)
        self.status = response_json['status']

        self.tokens = None

        if self.is_optout():
            return
        elif not self.is_success():
            raise ValueError("Got unexpected token generate status: " + self.status)

        self.tokens = IdentityTokens.from_json(self.get_body_as_json(response_json))

    def get_identity_json_string(self):
        return self.get_identity().get_json_string() if self.is_success() else None

    def is_success(self):
        return self.status == "success"

    def is_optout(self):
        return self.status == "optout"

    def get_identity(self):
        return self.tokens

    @staticmethod
    def get_body_as_json(json_response):
        return json_response['body']
