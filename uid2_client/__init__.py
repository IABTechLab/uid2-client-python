"""Client implementation and helper functions for integrating with the UID2 services.

Classes:
    Uid2Client: main API for interacting with a UID service

Functions:
    decrypt_token: decrypt and advertising token to extract advertising ID from it
"""


from .auto_refresh import *
from .client import *
from .encryption import *
from .keys import *

from enum import Enum


class IdentityScope(Enum):
    """Enum for types of unified ID"""
    UID2 = 0
    EUID = 1

class IdentityType(Enum):
    """Enum for types of ID source"""
    Email = 0
    Phone = 1
