from enum import Enum


class EncryptionStatus(Enum):
    ENCRYPTION_FAILURE = "Failed to encrypt"
    KEYS_NOT_SYNCED = "no keys available or all keys have expired; refresh the latest keys from UID2 service"
    NOT_AUTHORIZED_FOR_KEY = "No Keyset Key Found"
    NOT_AUTHORIZED_FOR_MASTER_KEY = "not authorized for master key"
    NOT_INITIALIZED = "keys not initialized"
    SUCCESS = "success"
