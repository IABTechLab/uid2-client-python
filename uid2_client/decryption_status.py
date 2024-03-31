from enum import Enum


class DecryptionStatus(Enum):
    DOMAIN_NAME_CHECK_FAILED = "domain_name_check_failed"
    INVALID_PAYLOAD = "invalid payload"
    INVALID_TOKEN_LIFETIME = "invalid_token_lifetime"
    KEYS_NOT_SYNCED = "no keys available or all keys have expired; refresh the latest keys from UID2 service"
    NOT_AUTHORIZED_FOR_KEY = "not_authorized_for_key"
    NOT_AUTHORIZED_FOR_MASTER_KEY = "not_authorized_for_master_key"
    NOT_INITIALIZED = "keys not initialized"
    SUCCESS = "success"
    TOKEN_EXPIRED = "token expired"
    VERSION_NOT_SUPPORTED = "token version not supported"
    # TOKEN_DECRYPT_FAILURE = "token_decrypt_failure",
    # KEY_INACTIVE = "key_inactive",
    # ENCRYPTION_FAILURE = "encryption_failure"
