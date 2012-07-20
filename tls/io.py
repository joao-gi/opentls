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

import io
import numbers
import sys

from tls.c import api


class BIOBase(object):
    """Base class for Python BIO objects."""

    BIO_ERROR = -1
    BIO_NOT_IMPLEMENTED = -2

    def write(self, bio, data, length):
        return self.BIO_NOT_IMPLEMENTED

    def read(self, bio, data, length):
        return self.BIO_NOT_IMPLEMENTED

    def puts(self, bio, data):
        return self.BIO_NOT_IMPLEMENTED

    def gets(self, bio, data, length):
        return self.BIO_NOT_IMPLEMENTED

    def ctrl_flush(self, bio, cmd, num, obj):
        return self.BIO_ERROR

    def ctrl_reset(self, bio, cmd, num, obj):
        return self.BIO_ERROR

    def ctrl_seek(self, bio, cmd, num, obj):
        return self.BIO_ERROR

    def ctrl_tell(self, bio, cmd, num, obj):
        return self.BIO_ERROR

    def ctrl_get_close(self, bio, cmd, num, obj):
        return api.BIO_NOCLOSE

    def ctrl_set_close(self, bio, cmd, num, obj):
        return 1

    def ctrl_dup(self, bio, cmd, num, obj):
        return 1

    def ctrl_eof(self, bio, cmd, num, obj):
        return 0

    def ctrl_pending(self, bio, cmd, num, obj):
        return 0

    def ctrl_wpending(self, bio, cmd, num, obj):
        return 0

    def ctrl(self, bio, cmd, num, obj):
        try:
            if cmd == api.BIO_CTRL_FLUSH:
                rval = self.ctrl_flush(bio, cmd, num, obj)
            elif cmd == api.BIO_C_FILE_SEEK:
                rval = self.ctrl_seek(bio, cmd, num, obj)
            elif cmd == api.BIO_C_FILE_TELL:
                rval = self.ctrl_tell(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_EOF:
                rval = self.ctrl_eof(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_RESET:
                rval = self.ctrl_reset(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_PENDING:
                rval = self.ctrl_pending(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_WPENDING:
                rval = self.ctrl_wpending(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_GET_CLOSE:
                rval = self.ctrl_get_close(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_SET_CLOSE:
                rval = self.ctrl_set_close(bio, cmd, num, obj)
            elif cmd == api.BIO_CTRL_DUP:
                rval = self.ctrl_dup(bio, cmd, num, obj)
            else:
                rval = self.BIO_ERROR
            if not isinstance(rval, numbers.Integral):
                rval = self.BIO_ERROR
            return rval
        except Exception:
            return self.BIO_ERROR


class BIOMethod(BIOBase):
    """Presents an OpenSSL BIO method for a file like object.

    The new BIO method is available as the method attribute on class instances.
    The original object is the fileobj attribute. To create automatically have
    a BIO object created with the associated method retained until the BIO
    object is garbage collected, use the wrap_io class method.
    """

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
        method.bwrite = api.callback('int (*)(BIO*, const char*, int)',
                self.write)
        method.bread = api.callback('int (*)(BIO*, char*, int)',
                self.read)
        method.bputs = api.callback('int (*)(BIO*, const char*)',
                self.puts)
        method.bgets = api.callback('int (*)(BIO*, char*, int)',
                self.gets)
        method.ctrl = api.callback('long (*)(BIO*, int, long, void*)',
                self.ctrl)
        method.create = api.callback('int (*)(BIO*)',
                self.create)
        method.destroy = api.NULL
        method.callback_ctrl = api.NULL
        self.method = method._unwrap()
        self.fileobj = fileobj

    def create(self, bio):
        bio.init = 1
        bio.num = 0
        bio.ptr = api.NULL
        return 1

    def write(self, bio, data, length):
        try:
            self.fileobj.write(api.buffer(data, length))
            return length
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

    def ctrl_flush(self, bio, cmd, num, obj):
        self.fileobj.flush()
        return 1

    def ctrl_reset(self, bio, cmd, num, obj):
        self.fileobj.seek(0)
        return 0

    def ctrl_seek(self, bio, cmd, num, obj):
        return self.fileobj.seek(num)

    def ctrl_tell(self, bio, cmd, num, obj):
        return self.fileobj.tell()


class BIOChain(object):
    """Implements an io.IOBase interface for OpenSSL BIO chains.

    BIOChain instances can be used as file like objects in Python.
    """

    def __init__(self, bio):
        self._bio = bio

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @property
    def c_bio(self):
        return self._bio

    # io.IOBase

    def close(self):
        api.BIO_free_all(self._bio)
        self._bio = None

    def closed(self):
        return self._bio is None

    def fileno(self):
        raise IOError('unsupported operation')

    def flush(self):
        api.BIO_flush(self._bio)

    def isatty(self):
        raise IOError('unsupported operation')

    def readable(self):
        return True

    def readline(self, limit=-1):
        limit = sys.maxint if limit < 0 else limit
        segments = []
        while True:
            buf = api.new('char[]', min(limit, 1024))
            read = api.BIO_gets(self._bio, buf, len(buf))
            if read == len(buf):
                segments.append(bytes(buf))
                limit -= read
            elif read > 0:
                segments.append(bytes(api.cast('char[{0}]'.format(read), buf)))
                break
            else:
                raise IOError('unsupported operation')
        return ''.join(segments)

    def readlines(self, hint=-1):
        hint = sys.maxint if hint < 0 else hint
        lines = []
        while hint > 0:
            try:
                line = self.readline()
                lines.append(line)
                hint -= len(line)
            except IOError:
                if len(lines) == 0:
                    raise
                break
        return lines

    def seek(self, offset, whence=io.SEEK_SET):
        if whence != io.SEEK_SET:
            raise IOError('unsupported operation')
        rval = api.BIO_seek(self._bio, offset)
        if rval < 0:
            raise IOError('unsupported operation')
        return offset

    def seekable(self):
        return True

    def tell(self):
        return api.BIO_tell(self._bio)

    def truncate(self):
        raise IOError('unsupported operation')

    def writable(self):
        return True

    def writelines(self, lines):
        for line in lines:
            data = api.new('char[]', line)
            offset = 0
            while offset < len(line):
                ptr = data + offset
                size = len(line) - offset
                written = api.BIO_write(self._bio, ptr, size)
                if written <= 0:
                    raise IOError('unsupported operation')
                offset += written

    # io.RawIOBase

    def read(self, n=-1):
        if n < 0:
            return self.readall()
        data = api.new('char[]', n)
        rval = api.BIO_read(self._bio, data, len(data))
        if rval < 0:
            raise IOError('unsopported operation')
        return bytes(data)

    def readall(self):
        segments = []
        while True:
            data = api.new('char[]', 1024)
            rval = api.BIO_read(self._bio, data, len(data))
            if rval == len(data):
                segments.append(bytes(data))
            elif rval > 0:
                segments.append(bytes(api.cast('char[{0}]'.format(rval), data)))
            elif rval == 0:
                break
            else:
                raise IOError('unsupported operation')
        return "".join(segments)

    def readinto(self, b):
        raise IOError('unsupported operation')

    def write(self, b):
        data = api.new('char[]', b)
        writen = api.BIO_write(self._bio, data, len(data))
        if writen < 0:
            raise IOError('unsupported operation')
        return writen


io.RawIOBase.register(BIOChain)
wrap_io = BIOMethod.wrap_io
