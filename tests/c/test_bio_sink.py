"""Test BIO Sinks"""
import os
import tempfile
import unittest2 as unittest

from tests import expect_fail_before
from tls.c import api


class BioWrite(object):

    data = api.new('char[]', b"HELLO WORLD")

    def setUp(self):
        self.bio = api.BIO_new(self.method)

    def tearDown(self):
        api.BIO_free(self.bio)

    def test_write(self):
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))

    def test_puts(self):
        put = api.BIO_puts(self.bio, self.data)
        self.assertEqual(api.BIO_wpending(self.bio), 0)
        self.assertEqual(put, len(bytes(self.data)))

    def test_flush(self):
        api.BIO_flush(self.bio)

    def test_wpending(self):
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(api.BIO_wpending(self.bio), 0)
        self.assertEqual(written, len(self.data))

    def test_ctrl_wpending(self):
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(api.BIO_ctrl_wpending(self.bio), 0)
        self.assertEqual(written, len(self.data))

    def test_reset(self):
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertFalse(api.BIO_eof(self.bio))
        self.assertEqual(written, len(self.data))
        api.BIO_reset(self.bio)
        self.assertEqual(api.BIO_tell(self.bio), 0)

    def test_tell(self):
        start = api.BIO_tell(self.bio)
        self.assertEqual(start, 0)
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        stop = api.BIO_tell(self.bio)
        self.assertEqual(stop, len(self.data))

    def test_seek(self):
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        api.BIO_seek(self.bio, 1)
        stop = api.BIO_tell(self.bio)
        self.assertEqual(stop, 1)

    def test_eof(self):
        buf = api.new('char[]', 1)
        api.BIO_read(self.bio, buf, 1)
        self.assertTrue(api.BIO_eof(self.bio))
        written = api.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        self.assertTrue(api.BIO_flush(self.bio))
        self.assertTrue(api.BIO_eof(self.bio))


class BioRead(object):

    data = api.new('char[]', b"HELLO WORLD")

    def setUp(self):
        self.bio = api.BIO_new(self.method)

    def tearDown(self):
        api.BIO_free(self.bio)

    def test_read_all(self):
        buf = api.new('char[]', len(self.data))
        read = api.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(bytes(buf)))
        self.assertEqual(bytes(buf), bytes(self.data))

    def test_read_one(self):
        count = 0
        buf = api.new('char[]', 1)
        read = api.BIO_read(self.bio, buf, len(buf))
        while read > 0:
            self.assertEqual(read, len(buf))
            self.assertEqual(buf[0], self.data[count])
            read = api.BIO_read(self.bio, buf, len(buf))
            count += 1
        self.assertEqual(count, max(0, len(self.data)-1))

    def test_read_long(self):
        buf = api.new('char[]', 2 * len(self.data))
        size = api.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(size, len(bytes(self.data)))

    def test_gets(self):
        buf = api.new('char[]', len(self.data))
        got = api.BIO_gets(self.bio, buf, len(buf))
        self.assertEqual(got + 1, len(buf))
        self.assertEqual(bytes(buf), bytes(self.data))

    def test_pending(self):
        pending = api.BIO_pending(self.bio)
        self.assertEqual(pending, len(bytes(self.data)))

    def test_ctrl_pending(self):
        pending = api.BIO_ctrl_pending(self.bio)
        self.assertEqual(pending, len(bytes(self.data)))

    def test_tell(self):
        start = api.BIO_tell(self.bio)
        self.assertEqual(start, 0)
        buf = api.new('char[]', 1)
        read = api.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(buf))
        end = api.BIO_tell(self.bio)
        self.assertNotEqual(start, end)

    def test_seek(self):
        api.BIO_seek(self.bio, 1)
        buf = api.new('char[]', len(self.data))
        read = api.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(bytes(self.data)) - 1)
        self.assertEqual(bytes(buf), bytes(self.data)[1:])

    def test_eof(self):
        buf = api.new('char[]', len(self.data) + 1)
        read = api.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(bytes(self.data)))
        self.assertTrue(api.BIO_eof(self.bio))


# Mem buffers
class TestBioMem(unittest.TestCase):

    def test_bio_new_mem(self):
        try:
            method = api.BIO_s_mem()
            mem = api.BIO_new(method)
        finally:
            api.BIO_free(mem)

    def test_bio_new_mem_buf(self):
        try:
            data = api.new('char[]', b"Hello World")
            mem = api.BIO_new_mem_buf(data, -1)
        finally:
            api.BIO_free(mem)

    def test_bio_read_write(self):
        try:
            method = api.BIO_s_mem()
            mem = api.BIO_new(method)
            data = api.new('char[]', b"HELLO WORLD")
            api.BIO_write(mem, data, 11)
            buf = api.new('char[]', 5)
            api.BIO_read(mem, buf, len(buf))
            self.assertEqual(bytes(buf), b"HELLO")
            api.BIO_gets(mem, buf, len(buf))
            self.assertEqual(bytes(buf), b" WOR")
        finally:
            api.BIO_free(mem)


class TestBioMemWrite(BioWrite, unittest.TestCase):

    @property
    def method(self):
        return api.BIO_s_mem()

    test_tell = unittest.expectedFailure(BioRead.test_tell)
    test_seek = unittest.expectedFailure(BioRead.test_seek)
    test_eof = unittest.expectedFailure(BioWrite.test_eof)


class TestBioMemRead(BioRead, unittest.TestCase):

    def setUp(self):
        self.bio = api.BIO_new_mem_buf(self.data, -1)

    test_tell = unittest.expectedFailure(BioRead.test_tell)
    test_seek = unittest.expectedFailure(BioRead.test_seek)


# Files
class TestBioFile(unittest.TestCase):
    pass


class TestBioFileWrite(BioWrite, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fd, cls.name = tempfile.mkstemp()
        os.close(fd)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.name)

    def setUp(self):
        name = self.name.encode()
        self.bio = api.BIO_new_file(name, b'w+')

    test_eof = unittest.skipIf(api.version()[0:3] < (1, 0, 0), 'different behaviour between py2.6 and py2.7')(BioWrite.test_eof)


class TestBioFileRead(BioRead, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fd, cls.name = tempfile.mkstemp()
        os.close(fd)
        with open(cls.name, 'wb') as dest:
            dest.write(bytes(cls.data))

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.name)

    def setUp(self):
        name = self.name.encode()
        self.bio = api.BIO_new_file(name, b'r')

    test_pending = unittest.expectedFailure(BioRead.test_pending)
    test_ctrl_pending = unittest.expectedFailure(BioRead.test_ctrl_pending)


# Fd
class TestBioFd(unittest.TestCase):
    pass


class TestBioFdWrite(BioWrite, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fd, cls.name = tempfile.mkstemp()

    @classmethod
    def tearDownClass(cls):
        os.close(cls.fd)
        os.remove(cls.name)

    def setUp(self):
        self.bio = api.BIO_new_fd(self.fd, api.BIO_NOCLOSE)

    test_eof = unittest.expectedFailure(BioWrite.test_eof)
    test_tell = unittest.expectedFailure(BioWrite.test_tell)


class TestBioFdRead(BioRead, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fd, cls.name = tempfile.mkstemp()
        os.close(fd)
        with open(cls.name, 'wb') as dest:
            dest.write(bytes(cls.data))

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.name)

    def setUp(self):
        fd = os.open(self.name, os.O_RDONLY)
        self.bio = api.BIO_new_fd(fd, api.BIO_CLOSE)

    def tearDown(self):
        del self.bio

    test_ctrl_pending = unittest.expectedFailure(BioRead.test_ctrl_pending)
    test_eof = unittest.expectedFailure(BioRead.test_eof)
    test_gets = expect_fail_before(1, 0, 0)(BioRead.test_gets)
    test_pending = unittest.expectedFailure(BioRead.test_pending)
    test_read_one = unittest.expectedFailure(BioRead.test_read_one)


# Null buffers
class TestBioNullWrite(BioWrite, unittest.TestCase):

    @property
    def method(self):
        return api.BIO_s_null()

    test_reset = unittest.expectedFailure(BioWrite.test_reset)
    test_seek = unittest.expectedFailure(BioWrite.test_seek)
    test_tell = unittest.expectedFailure(BioWrite.test_tell)


class TestBioNullRead(BioRead, unittest.TestCase):

    data = b""

    @property
    def method(self):
        return api.BIO_s_null()

    test_gets = unittest.expectedFailure(BioRead.test_gets)
    test_seek = unittest.expectedFailure(BioRead.test_seek)
    test_tell = unittest.expectedFailure(BioRead.test_tell)
