from enum import Enum


class EncryptionStatus(Enum):
    SUCCESS = "success"
    NOT_AUTHORIZED_FOR_KEY = "No Keyset Key Found"
