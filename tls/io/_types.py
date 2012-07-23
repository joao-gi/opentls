"""BIO type constants"""
from tls.c import api

__all__ = ['BIO_TYPES']


BIO_TYPES = {}


def _populate_bio_types():
    "Dynamically populate module with BIO type contants from tls.c.api"
    for name, value in api.__dict__.iteritems():
        if name.startswith('BIO_TYPE_'):
            BIO_TYPES[value] = name
            globals()[name] = value
            __all__.append(name)

_populate_bio_types()
