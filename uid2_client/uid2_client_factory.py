from uid2_client import Uid2Client


class Uid2ClientFactory:
    @staticmethod
    def create(endpoint, auth_key, secret_key):
        return Uid2Client.create_uid2(endpoint, auth_key, secret_key)
