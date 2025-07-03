from enum import Enum


class UnmappedIdentityReason(Enum):
    OPTOUT = "optout"
    INVALID_IDENTIFIER = "invalid identifier"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_string(cls, reason_str: str) -> 'UnmappedIdentityReason':
        try:
            return cls(reason_str)
        except ValueError:
            return cls.UNKNOWN