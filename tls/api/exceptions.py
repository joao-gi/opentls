"""Exception class hierarchy for OpenSSL API errors"""
import socket


class CryptError(Exception):
    "Base error for all OpenSSL errors"


class BIOError(IOError, CryptError):
    "An IO error occured with BIO"


class UnregisteredError(ValueError, CryptError):
    "The error code is unknown"


class TLSError(socket.error, CryptError):
    "A network error occured with TLS"
