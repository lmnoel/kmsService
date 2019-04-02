import base64
import re
from UserCredential import UserCredential
import time

def extract_user_credentials(auth):
    """ The method extracts user credentials from basic auth
        into dictionary containing username and password
        Args:
            auth (binary): basic auth eg. Basic amVlcmF3dXQyOmNoYW5nZW1l
        Returns:
            dict: with key username and password
    """
    raw = base64.b64decode(auth.replace('Basic ', '')).decode().split(':')
    return UserCredential(username=raw[0], password=raw[1])

def validate_password(password):
    """ The method validates password according to a set of rules
        1. Password must be equal or greater than 8 character long.
        2. Password must contain at least one digit
        3. Password must contain at least one capital alphabet
        Returns:
            Boolean: True if match with the set of rules. Otherwise, False
    """
    if len(password) < 8 or re.search('[0-9]', password) is None or re.search('[A-Z]', password) is None:
        return False
    else:
        return True