from uid2_client import Uid2Client


class EuidClientFactory:
    @staticmethod
    def create(endpoint, auth_key, secret_key):
        return Uid2Client.create_euid(endpoint, auth_key, secret_key)
