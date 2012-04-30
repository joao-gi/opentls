"""Exception class hierarchy for OpenSSL API errors"""
import socket


class CryptError(Exception):
    "Base error for all OpenSSL errors"


class BIOError(IOError, CryptError):
    "An IO error occured with BIO"


class DigestError(ValueError, CryptError):
    "An error occured in digest function"


class ASNError(ValueError, CryptError):
    "An error occured with ASN.1 object"


class RANDError(EnvironmentError, CryptError):
    "An error with random numbers occured"

    
class TLSError(socket.error, CryptError):
    "A network error occured with TLS"


class UnregisteredError(ValueError, CryptError):
    "The error code is unknown"
