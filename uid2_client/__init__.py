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


