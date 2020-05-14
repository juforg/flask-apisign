class SignException(Exception):
    """
    Base except which all flask_jwt_extended errors extend
    """
    pass


class InvalidSignError(SignException):
    """
    An error getting header information from a request
    """
    pass


class NoSignKeyError(SignException):
    pass


class NoAppIdError(SignException):
    """
    Error raised when request has no appid param
    """
    pass


class NoRequestIdError(SignException):
    """
    Error raised when request has no requestid param
    """
    pass


class NoSignatureError(SignException):
    """
    Error raised when request has no signature param
    """
    pass


class NoTimestampError(SignException):
    """
    Error raised when request has no timestamp param
    """
    pass


class TimestampFormatterError(SignException):
    """
    Error raised when request has no timestamp param
    """
    pass


class RequestExpiredError(SignException):
    """
    Error raised when request has no timestamp param
    """
    pass


class NotConfigedAppIdsError(SignException):
    """
    Error raised when request has no signature param
    """
    pass


class InvalidAppIdsTypeError(SignException):
    """
    Error raised when request has no signature param
    """
    pass


class NotAllowedAppIdError(SignException):
    """
    Error raised when request has no signature param
    """
    pass


class UnknowAppIdError(SignException):
    """
    Error raised when request has no signature param
    """
    pass
