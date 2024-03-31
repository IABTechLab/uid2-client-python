from enum import Enum


class EncryptionStatus(Enum):
    SUCCESS = "success",
    NOT_AUTHORIZED_FOR_KEY = "No Keyset Key Found",
    # NOT_AUTHORIZED_FOR_MASTER_KEY = "not_authorized_for_master_key",
    # NOT_INITIALIZED = "not_initialized",
    # KEYS_NOT_SYNCED = "keys_not_synced",
    # TOKEN_DECRYPT_FAILURE = "token_decrypt_failure",
    # KEY_INACTIVE = "key_inactive",
    # ENCRYPTION_FAILURE = "encryption_failure"
