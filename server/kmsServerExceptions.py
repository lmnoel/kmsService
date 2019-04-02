class UserPermissionException(Exception):
    pass


class UnableToDecryptException(Exception):
    pass


class UserAlreadyExistsException(Exception):
    pass


class UnableToFindCertificateException(Exception):
    pass


class GroupAlreadyExistsException(Exception):
    pass


class PasswordTooWeakException(Exception):
    pass


class GroupDoesNotExistException(Exception):
    pass


class InvalidTokenException(Exception):
    pass
