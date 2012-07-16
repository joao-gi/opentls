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
from __future__ import absolute_import

import numbers
import weakref

from tls.c import api


class BIOSourceSink(object):
    """Presents an OpenSSL BIO method for a file like object.

    The new BIO method is available as the method attribute on class instances.
    The original object is the fileobj attribute. To create automatically have
    a BIO object created with the associated method retained until the BIO
    object is garbage collected, use the wrap_io class method.
    """

    BIO_ERROR = -1
    BIO_NOT_IMPLEMENTED = -2

    @classmethod
    def wrap_io(cls, fileobj):
        """Create a new BIO object for a file like Python object.

        Returns the cffi.Cdata instance for BIO pointer. The associated method
        object will be retained until the cffi.Cdata is deleted. The caller is
        required to call api.BIO_free on the pointer to release memory
        allocated by OpenSSL.
        """
        wrapper = cls(fileobj)
        bio = api.new('BIO')
        api.BIO_set(bio, wrapper.method)
        api.relate(bio, wrapper, 'method')
        return bio

    def __init__(self, fileobj):
        method = api.new('BIO_METHOD', coown=True)
        method.type = api.BIO_TYPE_SOURCE_SINK | 0xFF
        method.name = api.new('char[]', repr(fileobj).encode())
        method.bwrite = api.callback('int (*)(BIO*, const char*, int)', self.write)
        method.bread = api.callback('int (*)(BIO*, char*, int)', self.read)
        method.bputs = api.callback('int (*)(BIO*, const char*)', self.puts)
        method.bgets = api.callback('int (*)(BIO*, char*, int)', self.gets)
        method.ctrl = api.callback('long (*)(BIO*, int, long, void*)', self.ctrl)
        method.create = api.callback('int (*)(BIO*)', self.create)
        method.destroy = api.NULL
        method.callback_ctrl = api.NULL
        self.method = method._unwrap()
        self.fileobj = fileobj

    def write(self, bio, data, length):
        try:
            self.fileobj.write(api.buffer(data, length))
            return length;
        except:
            return self.BIO_ERROR

    def read(self, bio, data, length):
        try:
            buff = api.buffer(data, length)
            if hasattr(self.fileobj, 'readinto'):
                count = self.fileobj.readinto(buff)
                count = count if count is not None else 0
            else:
                tmp = self.fileobj.read(length)
                count = len(tmp)
                buff[:count] = tmp
            return count
        except:
            return self.BIO_ERROR

    def puts(self, bio, data):
        return self.BIO_NOT_IMPLEMENTED

    def gets(self, bio, data, length):
        return self.BIO_NOT_IMPLEMENTED

    def ctrl(self, bio, cmd, num, obj):
        try:
            if cmd == api.BIO_CTRL_FLUSH:
                self.fileobj.flush()
                rval = 1
            elif cmd == api.BIO_CTRL_RESET:
                self.fileobj.seek(0)
                rval = 0
            elif cmd == api.BIO_C_FILE_SEEK:
                rval = self.fileobj.seek(num)
            elif cmd == api.BIO_C_FILE_TELL:
                rval = self.fileobj.tell()
            elif cmd == api.BIO_CTRL_GET_CLOSE:
                rval = api.BIO_NOCLOSE
            elif cmd == api.BIO_CTRL_SET:
                rval = 1
            elif cmd == api.BIO_CTRL_SET_CLOSE:
                rval = 1
            elif cmd == api.BIO_CTRL_DUP:
                rval = 1
            elif cmd == api.BIO_CTRL_EOF:
                rval = 0
            elif cmd == api.BIO_CTRL_GET:
                rval = 0
            elif cmd == api.BIO_CTRL_INFO:
                rval = 0
            elif cmd == api.BIO_CTRL_PENDING:
                rval = 0
            elif cmd == api.BIO_CTRL_WPENDING:
                rval = 0
            else:
                rval = self.BIO_NOT_IMPLEMENTED
            return rval if isinstance(rval, numbers.Integral) else self.BIO_ERROR
        except Exception as err:
            return self.BIO_ERROR

    def create(self, bio):
        bio.init = 1
        bio.num = 0
        bio.ptr = api.NULL
        return 1


wrap_io = BIOSourceSink.wrap_io
