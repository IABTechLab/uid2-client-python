from uid2_client.encryption_status import EncryptionStatus


class EncryptionDataResponse:

    def __init__(self, encryption_status, encrypted_data):
        self._encryption_status = encryption_status
        self._encrypted_data = encrypted_data

    @staticmethod
    def make_success(encrypted_data):
        return EncryptionDataResponse(EncryptionStatus.SUCCESS, encrypted_data)

    @staticmethod
    def make_error(encryption_status):
        return EncryptionDataResponse(encryption_status, None)

    @property
    def encrypted_data(self):
        return self._encrypted_data

    @property
    def status(self):
        return self._encryption_status
