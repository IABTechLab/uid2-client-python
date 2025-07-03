from typing import Optional


class Uid2Response:
    def __init__(self, as_string: Optional[str], as_bytes: Optional[bytes]):
        self._as_string = as_string
        self._as_bytes = as_bytes

    @classmethod
    def from_string(cls, as_string: str) -> 'Uid2Response':
        return cls(as_string, None)

    @classmethod
    def from_bytes(cls, as_bytes: bytes) -> 'Uid2Response':
        return cls(None, as_bytes)

    @property
    def as_string(self) -> Optional[str]:
        return self._as_string

    @property
    def as_bytes(self) -> Optional[bytes]:
        return self._as_bytes

    def is_binary(self) -> bool:
        return self._as_bytes is not None