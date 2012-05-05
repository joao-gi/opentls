"""Test BIO Sinks"""
import ctypes
import os
import tempfile
import unittest

from tls.api import bio, version


def expect_fail_before(major, minor, fix):
    "Decorate function with expected failure for early OpenSSL versions"
    def expect_failure(func):
        return unittest.expectedFailure(func)
    def noop(func):
        return func
    if version()[0:3] < (major, minor, fix):
        return expect_failure
    return noop


class BioWrite:

    data = b"HELLO WORLD"

    def setUp(self):
        self.bio = bio.BIO_new(self.method)

    def tearDown(self):
        bio.BIO_free(self.bio)

    def test_write(self):
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))

    def test_puts(self):
        put = bio.BIO_puts(self.bio, self.data)
        self.assertEqual(bio.BIO_wpending(self.bio), 0)
        self.assertEqual(put, len(self.data))

    def test_flush(self):
        bio.BIO_flush(self.bio)

    def test_wpending(self):
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(bio.BIO_wpending(self.bio), 0)
        self.assertEqual(written, len(self.data))

    def test_ctrl_wpending(self):
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(bio.BIO_ctrl_wpending(self.bio), 0)
        self.assertEqual(written, len(self.data))

    def test_reset(self):
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertFalse(bio.BIO_eof(self.bio))
        self.assertEqual(written, len(self.data))
        bio.BIO_reset(self.bio)
        self.assertEqual(bio.BIO_tell(self.bio), 0)

    def test_tell(self):
        start = bio.BIO_tell(self.bio)
        self.assertEqual(start, 0)
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        stop = bio.BIO_tell(self.bio)
        self.assertEqual(stop, len(self.data))

    def test_seek(self):
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        bio.BIO_seek(self.bio, 1)
        stop = bio.BIO_tell(self.bio)
        self.assertEqual(stop, 1)

    def test_eof(self):
        bio.BIO_read(self.bio, bytes(1), 1)
        self.assertTrue(bio.BIO_eof(self.bio))
        written = bio.BIO_write(self.bio, self.data, len(self.data))
        self.assertEqual(written, len(self.data))
        self.assertTrue(bio.BIO_flush(self.bio))
        self.assertTrue(bio.BIO_eof(self.bio))


class BioRead:

    data = b"HELLO WORLD"

    def setUp(self):
        self.bio = bio.BIO_new(self.method)

    def tearDown(self):
        bio.BIO_free(self.bio)

    def test_read_all(self):
        buf = bytes(len(self.data))
        read = bio.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(buf))
        self.assertEqual(buf, self.data)

    def test_read_one(self):
        count = 0
        buf = bytes(1)
        read = bio.BIO_read(self.bio, buf, len(buf))
        while read > 0:
            self.assertEqual(read, len(buf))
            self.assertEqual(ord(buf), self.data[count])
            read = bio.BIO_read(self.bio, buf, len(buf))
            count += 1
        self.assertTrue(bio.BIO_eof(self.bio))

    def test_read_long(self):
        buf = bytes(2 * len(self.data))
        size = bio.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(size, len(self.data))

    def test_gets(self):
        buf = bytes(len(self.data))
        got = bio.BIO_gets(self.bio, buf, len(buf))
        self.assertEqual(got + 1, len(buf))
        self.assertEqual(buf, self.data[:-1] + b'\x00')

    def test_pending(self):
        pending = bio.BIO_pending(self.bio)
        self.assertEqual(pending, len(self.data))

    def test_ctrl_pending(self):
        pending = bio.BIO_ctrl_pending(self.bio)
        self.assertEqual(pending, len(self.data))

    def test_tell(self):
        start = bio.BIO_tell(self.bio)
        self.assertEqual(start, 0)
        buf = bytes(1)
        read = bio.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(buf))
        end = bio.BIO_tell(self.bio)
        self.assertNotEqual(start, end)

    def test_seek(self):
        bio.BIO_seek(self.bio, 1)
        buf = bytes(len(self.data))
        read = bio.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(buf) - 1)
        self.assertEqual(buf[:read], self.data[1:1 + read])

    def test_eof(self):
        buf = bytes(len(self.data) + 1)
        read = bio.BIO_read(self.bio, buf, len(buf))
        self.assertEqual(read, len(self.data))
        self.assertTrue(bio.BIO_eof(self.bio))


# Mem buffers
class TestBioMem(unittest.TestCase):

    def test_bio_new_mem(self):
        try:
            method = bio.BIO_s_mem()
            mem = bio.BIO_new(method)
        finally:
            bio.BIO_free(mem)

    def test_bio_new_mem_buf(self):
        try:
            data = "Hello World"
            mem = bio.BIO_new_mem_buf(data, -1)
        finally:
            bio.BIO_free(mem)

    def test_bio_read_write(self):
        try:
            method = bio.BIO_s_mem()
            mem = bio.BIO_new(method)
            bio.BIO_write(mem, b"HELLO WORLD", 11)
            buf = bytes(5)
            bio.BIO_read(mem, buf, len(buf))
            self.assertEqual(buf, b"HELLO")
            bio.BIO_gets(mem, buf, len(buf))
            self.assertEqual(buf, b" WOR\x00")
        finally:
            bio.BIO_free(mem)


class TestBioMemWrite(BioWrite, unittest.TestCase):

    method = bio.BIO_s_mem()

    test_tell = unittest.expectedFailure(BioRead.test_tell)
    test_seek = unittest.expectedFailure(BioRead.test_seek)
    test_eof = unittest.expectedFailure(BioWrite.test_eof)


class TestBioMemRead(BioRead, unittest.TestCase):

    def setUp(self):
        self.bio = bio.BIO_new_mem_buf(self.data, -1)

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
        self.bio = bio.BIO_new_file(name, b'w+')

    test_eof = expect_fail_before(1, 0, 0)(BioWrite.test_eof)


class TestBioFileRead(BioRead, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fd, cls.name = tempfile.mkstemp()
        os.close(fd)
        with open(cls.name, 'wb') as dest:
            dest.write(cls.data)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.name)

    def setUp(self):
        name = self.name.encode()
        self.bio = bio.BIO_new_file(name, b'r')

    test_pending = unittest.expectedFailure(BioRead.test_pending)
    test_ctrl_pending = unittest.expectedFailure(BioRead.test_ctrl_pending)


# Null buffers
class TestBioNullWrite(BioWrite, unittest.TestCase):

    method = bio.BIO_s_null()

    test_reset = unittest.expectedFailure(BioWrite.test_reset)
    test_seek = unittest.expectedFailure(BioWrite.test_seek)
    test_tell = unittest.expectedFailure(BioWrite.test_tell)


class TestBioNullRead(BioRead, unittest.TestCase):

    data = b""
    
    method = bio.BIO_s_null()

    test_gets = unittest.expectedFailure(BioRead.test_gets)
    test_seek = unittest.expectedFailure(BioRead.test_seek)
    test_tell = unittest.expectedFailure(BioRead.test_tell)
