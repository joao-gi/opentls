"""IO stream handling using OpenSSL's buffered IO API.

wrap_io(fileobj) - returns an OpenSSL BIO object for the Python file like
                   object. The caller is required to call api.BIO_free on the
                   returned object before being garbage collected.

For example, wrapping a StringIO object:

    >>> from tls import io
    >>> from StringIO import StringIO
    >>> data = StringIO('Now for something completely different')
    >>> bio = io.wrap_io(data)
    >>> buf = api.new('char[]', 3)
    >>> api.BIO_read(bio, buf, len(buf))
    3
    >>> print buf
    Now
    >>> api.BIO_free(bio)

"""
from tls.io._base import BIOBase
from tls.io._chain import BIOChain
from tls.io._method import BIOMethod
from tls.io._sinks import BIOMemBuffer

from tls.io._types import *

wrap_io = BIOMethod.wrap_io
