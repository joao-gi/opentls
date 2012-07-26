"""OpenSSL error reporting and logging.

log_errors(func) - decorator that logs any openssl errors present when the
                    function exits using the logging module.

If a function decorated with log_errors exit normally errors are logged at the
ERROR level. If an exception was raised inside the function errors are logged
at the DEBUG level. log_errors can also be used as a function to log all
openssls errors at the ERROR level.
"""
import functools
import logging

from tls.c import api

logger = logging.getLogger(__name__)


def log_errors(func=None, level=logging.ERROR):
    """Decorate function to log all openssl errors when function exits.

    If the function returns normally errors are logged with level ERROR.
    If an exception was raised inside the function errors are logger with level
    DEBUG.
    """

    def clear_errors(level=logging.ERROR):
        "Log all openssl errors at supplied log level"
        messages = []
        errcode = api.ERR_get_error()
        while errcode != 0:
            cstring = api.ERR_error_string(errcode, api.NULL)
            errmsg = bytes(cstring)
            logger.log(level, errmsg)
            messages.append(errmsg)
            errcode = api.ERR_get_error()
        return messages

    if func is None:
        return clear_errors(level)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        "call clear_errors when func exits"
        try:
            value = func(*args, **kwargs)
        except:
            clear_errors(logging.DEBUG)
            raise
        else:
            clear_errors(logging.ERROR)
        return value

    return wrapper
