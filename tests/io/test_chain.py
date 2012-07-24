"""Test Python IO API for OpenSSL BIO"""
import unittest2 as unittest

from tls.c import api
from tls import io


class ChainTest(object):

    def test_getitem(self):
        self.assertEqual(self.null, self.fileobj[0])
        self.assertEqual(self.mem, self.fileobj[1])
        self.assertNotEqual(self.fileobj[0], self.fileobj[1])

    def test_getitem_negative(self):
        self.assertRaises(IndexError, self.fileobj.__getitem__, -1)

    def test_getitem_large(self):
        self.assertRaises(IndexError, self.fileobj.__getitem__, 2)

    def test_pop_push(self):
        self.assertEqual(self.null, self.fileobj.pop())
        self.assertEqual(self.mem, self.fileobj.pop())
        self.assertEqual(self.mem, self.fileobj.pop())
        self.fileobj.push(self.null)
        self.assertEqual(self.bio, self.fileobj.c_bio)

    def test_bio_property(self):
        self.assertIs(self.bio, self.fileobj.c_bio)

    def test_close(self):
        self.fileobj.close()

    def test_closed(self):
        self.assertFalse(self.fileobj.closed())
        self.fileobj.close()
        self.assertTrue(self.fileobj.closed())

    def test_contextmanager(self):
        with self.fileobj:
            pass
        self.assertTrue(self.fileobj.closed())

    def test_fileno(self):
        self.assertRaises(IOError, self.fileobj.fileno)

    def test_flush(self):
        self.fileobj.flush()

    def test_isatty(self):
        self.assertRaises(IOError, self.fileobj.isatty)

    def test_readable(self):
        self.assertTrue(self.fileobj.readable())

    def test_seek(self):
        self.assertEquals(1, self.fileobj.seek(1))

    def test_seekable(self):
        self.assertTrue(self.fileobj.seekable())

    def test_tell(self):
        self.assertGreaterEqual(0, self.fileobj.tell())

    def test_truncate(self):
        self.assertRaises(IOError, self.fileobj.truncate)

    def test_writable(self):
        self.assertTrue(self.fileobj.writable())


class TestChainWrite(ChainTest, unittest.TestCase):

    def setUp(self):
        self.null = api.BIO_new(api.BIO_f_null())
        self.mem = api.BIO_new(api.BIO_s_mem())
        self.bio = api.BIO_push(self.null, self.mem)
        self.fileobj = io.BIOChain(self.bio)

    def tearDown(self):
        if self.fileobj.c_bio is not api.NULL:
            api.BIO_free_all(self.bio)

    def test_readline(self):
        self.assertRaises(IOError, self.fileobj.readline)

    def test_readlines(self):
        self.assertRaises(IOError, self.fileobj.readlines)

    def test_writelines(self):
        self.fileobj.writelines(['a', 'b', 'c'])

    def test_read(self):
        self.assertRaises(IOError, self.fileobj.read, 1)

    def test_readall(self):
        self.assertRaises(IOError, self.fileobj.readall)

    def test_readinto(self):
        self.assertRaises(IOError, self.fileobj.readinto, bytearray(1))

    def test_write(self):
        self.fileobj.write('a')


class TestChainRead(ChainTest, unittest.TestCase):

    def setUp(self):
        self.data = api.new('char[]', 'HELLO\nWORLD\n')
        self.null = api.BIO_new(api.BIO_f_null())
        self.mem = api.BIO_new_mem_buf(self.data, len(bytes(self.data)))
        self.bio = api.BIO_push(self.null, self.mem)
        self.fileobj = io.BIOChain(self.bio)

    def tearDown(self):
        if self.fileobj.c_bio is not api.NULL:
            api.BIO_free_all(self.bio)

    def test_readline(self):
        self.assertEqual('HELLO\n', self.fileobj.readline())

    def test_readlines(self):
        self.assertEqual(['HELLO\n', 'WORLD\n'], self.fileobj.readlines())

    def test_writelines(self):
        self.assertRaises(IOError, self.fileobj.writelines, ['a', 'b', 'c'])

    def test_read(self):
        self.assertEquals('H', self.fileobj.read(1))

    def test_readall(self):
        self.assertEquals('HELLO\nWORLD\n', self.fileobj.readall())

    def test_readinto(self):
        self.assertRaises(IOError, self.fileobj.readinto, bytearray(1))

    def test_write(self):
        self.assertRaises(IOError, self.fileobj.write, 'a')
