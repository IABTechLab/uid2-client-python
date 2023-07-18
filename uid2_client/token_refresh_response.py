import json

from uid2_client.identity_tokens import IdentityTokens


class TokenRefreshResponse:
    def __init__(self, response, timestamp):
        response_json = json.loads(response)
        self.status = response_json["status"]
        self.refreshed_identity = None

        if self.is_optout():
            return
        elif not self.is_success():
            raise Exception("Got unexpected token refresh status: " + self.status)

        self.refreshed_identity = IdentityTokens.from_json(self.get_body_as_json(response_json))
        if not self.refreshed_identity.is_refreshable_impl(timestamp) or self.refreshed_identity.has_identity_expired(timestamp):
            raise Exception("Invalid identity in token refresh response: " + response)

    def get_identity_json_string(self):
        if self.is_success():
            return self.get_identity().get_json_string()
        else:
            return None

    def is_success(self):
        return self.status == "success"

    def is_optout(self):
        return self.status == "optout"

    def get_identity(self):
        return self.refreshed_identity if self.is_success() else None

    @staticmethod
    def get_body_as_json(json_response):
        return json_response["body"]
