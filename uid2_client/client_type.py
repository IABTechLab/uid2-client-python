from enum import Enum


class ClientType(Enum):
    Sharing = 1,
    Bidstream = 2,
    LegacyWithoutDomainCheck = 3
