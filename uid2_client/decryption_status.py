from enum import Enum


class DecryptionStatus(Enum):
    DOMAIN_NAME_CHECK_FAILED = "domain name check failed"
    INVALID_PAYLOAD = "invalid payload"
    INVALID_TOKEN_LIFETIME = "invalid token lifetime"
    KEYS_NOT_SYNCED = "no keys available or all keys have expired; refresh the latest keys from UID2 service"
    NOT_AUTHORIZED_FOR_KEY = "not authorized for key"
    NOT_AUTHORIZED_FOR_MASTER_KEY = "not authorized for master key"
    NOT_INITIALIZED = "keys not initialized"
    SUCCESS = "success"
    EXPIRED_TOKEN = "token expired"
    VERSION_NOT_SUPPORTED = "token version not supported"
