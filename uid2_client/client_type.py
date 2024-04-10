from enum import Enum


class ClientType(Enum):
    SHARING = 1,
    BIDSTREAM = 2,
    LEGACY_WITHOUT_DOMAIN_CHECK = 3
