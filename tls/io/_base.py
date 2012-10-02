"""Python BIO objects base"""
from __future__ import absolute_import, division, print_function
import numbers

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
