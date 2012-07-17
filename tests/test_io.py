"""Test Python IO API for OpenSSL BIO"""
from StringIO import StringIO

import unittest2 as unittest

from .c.test_bio_sink import BioWrite, BioRead
from tls.c import api
from tls import io


class TestStringIOWrite(BioWrite, unittest.TestCase):

    def setUp(self):
        fileobj = StringIO()
        self.bio = io.wrap_io(fileobj)

    test_eof = unittest.expectedFailure(BioWrite.test_eof)
    test_puts = unittest.expectedFailure(BioWrite.test_puts)


class TestStringIORead(BioRead, unittest.TestCase):

    def setUp(self):
        fileobj = StringIO(bytes(self.data))
        self.bio = io.wrap_io(fileobj)

    test_ctrl_pending = unittest.expectedFailure(BioRead.test_ctrl_pending)
    test_eof = unittest.expectedFailure(BioRead.test_eof)
    test_gets = unittest.expectedFailure(BioRead.test_gets)
    test_pending = unittest.expectedFailure(BioRead.test_pending)


class TestWrapperWrite(unittest.TestCase):

    def setUp(self):
        self.bio = api.BIO_new(api.BIO_s_mem())
        self.fileobj = io.BIOWrapper(self.bio)

    def tearDown(self):
        if self.fileobj._bio is not None:
            api.BIO_free(self.bio)

    def test_close(self):
        self.fileobj.close()

    def test_closed(self):
        self.assertFalse(self.fileobj.closed())
        self.fileobj.close()
        self.assertTrue(self.fileobj.closed())

    def test_fileno(self):
        self.assertRaises(IOError, self.fileobj.fileno)

    def test_flush(self):
        self.fileobj.flush()

    def test_isatty(self):
        self.assertRaises(IOError, self.fileobj.isatty)

    def test_readable(self):
        self.assertTrue(self.fileobj.readable())

    def test_readline(self):
        self.fileobj.readline()

    def test_readlines(self):
        self.fileobj.readlines()

    def test_seek(self):
        self.fileobj.seek()

    def test_seekable(self):
        self.fileobj.seekable()

    def test_tell(self):
        self.fileobj.tell()

    def test_truncate(self):
        self.fileobj.truncate()

    def test_writable(self):
        self.fileobj.writable()

    def test_read(self):
        self.fileobj.read()

    def test_readall(self):
        self.fileobj.readall()

    def test_write(self):
        self.fileobj.write()


class TestWrapperRead(unittest.TestCase):

    def setUp(self):
        self.data = api.new('char[]', 'HELLO WORLD')
        self.bio = api.BIO_new_mem_buf(self.data, len(bytes(self.data)))
        self.fileobj = io.BIOWrapper(self.bio)

    def tearDown(self):
        if self.fileobj._bio is not None:
            api.BIO_free(self.bio)

    def test_close(self):
        self.fileobj.close()

    def test_closed(self):
        self.assertFalse(self.fileobj.closed())
        self.fileobj.close()
        self.assertTrue(self.fileobj.closed())

    def test_fileno(self):
        self.assertRaises(IOError, self.fileobj.fileno)

    def test_flush(self):
        self.fileobj.flush()

    def test_isatty(self):
        self.assertRaises(IOError, self.fileobj.isatty)

    def test_readable(self):
        self.assertTrue(self.fileobj.readable())

    def test_readline(self):
        self.fileobj.readline()

    def test_readlines(self):
        self.fileobj.readlines()

    def test_seek(self):
        self.fileobj.seek()

    def test_seekable(self):
        self.fileobj.seekable()

    def test_tell(self):
        self.fileobj.tell()

    def test_truncate(self):
        self.fileobj.truncate()

    def test_writable(self):
        self.fileobj.writable()

    def test_read(self):
        self.fileobj.read()

    def test_readall(self):
        self.fileobj.readall()

    def test_write(self):
        self.fileobj.write()