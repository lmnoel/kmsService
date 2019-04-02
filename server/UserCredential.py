class UserCredential:

    def __init__(self, username, password):
        self._username = username
        self._password = password

    @property
    def password(self):
        return self._password

    @property
    def username(self):
        return self._username

    @property
    def b_password(self):
        """
            return password in binary
        """
        return self._password.encode()