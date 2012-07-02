"""Test OpenSSL error handling"""
import unittest2 as unittest

from tls.api import error


class TestErrorFetch(unittest.TestCase):

    first = 0x2006D080
    last = 0x140943E8

    def setUp(self):
        error.ERR_put_error(0x20, 0x6D, 0x80, None, 0)
        error.ERR_put_error(0x14, 0x94, 0x3E8, None, 0)

    def tearDown(self):
        self.count_errors_on_stack()

    def count_errors_on_stack(self):
        count = 0
        while error.ERR_get_error() != 0:
            count += 1
        return count

    @unittest.skip('needs to be ported to cffi')
    def test_error_get(self):
        self.assertEqual(error.ERR_get_error(), self.first)
        self.assertEqual(error.ERR_get_error(), self.last)
        self.assertEqual(self.count_errors_on_stack(), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_error_peek(self):
        self.assertEqual(error.ERR_peek_error(), self.first)
        self.assertEqual(self.count_errors_on_stack(), 2)

    @unittest.skip('needs to be ported to cffi')
    def test_error_peek_last(self):
        self.assertEqual(error.ERR_peek_last_error(), self.last)
        self.assertEqual(self.count_errors_on_stack(), 2)


class TestErrorParse(unittest.TestCase):

    code = 0x2006D080
    text = b'error:2006D080:BIO routines:BIO_new_file:no such file'

    @classmethod
    def setUpClass(cls):
        error.SSL_load_error_strings()

    @classmethod
    def tearDownClass(cls):
        error.ERR_free_strings()

    @unittest.skip('needs to be ported to cffi')
    def test_error_string(self):
        value = error.ERR_error_string(self.code, None)
        self.assertEqual(value, self.text)

    @unittest.skip('needs to be ported to cffi')
    def test_error_string_n(self):
        stop = len(self.text) - 1
        buf = bytes(stop)
        error.ERR_error_string_n(self.code, buf, stop)
        self.assertEqual(buf, self.text[:stop - 1] + b'\x00')

    @unittest.skip('needs to be ported to cffi')
    def test_lib_error_string(self):
        value = error.ERR_lib_error_string(self.code)
        self.assertEqual(value, self.text.split(b':')[2])

    @unittest.skip('needs to be ported to cffi')
    def test_func_error_string(self):
        value = error.ERR_func_error_string(self.code)
        self.assertEqual(value, self.text.split(b':')[3])

    @unittest.skip('needs to be ported to cffi')
    def test_reason_error_string(self):
        value = error.ERR_reason_error_string(self.code)
        self.assertEqual(value, self.text.split(b':')[4])

    @unittest.skip('needs to be ported to cffi')
    def test_code_pack(self):
        code = error.ERR_pack(0x20, 0x6D, 0x80)
        self.assertEqual(code, self.code)

    @unittest.skip('needs to be ported to cffi')
    def test_code_get_lib(self):
        code = error.ERR_get_lib(self.code)
        self.assertEqual(code, 0x20)

    @unittest.skip('needs to be ported to cffi')
    def test_code_get_func(self):
        code = error.ERR_get_func(self.code)
        self.assertEqual(code, 0x6D)

    @unittest.skip('needs to be ported to cffi')
    def test_code_get_reason(self):
        code = error.ERR_get_reason(self.code)
        self.assertEqual(code, 0x80)

    @unittest.skip('needs to be ported to cffi')
    def test_load_strings(self):
        lib = error.ERR_get_next_error_library()
        func = 1
        reason = 1
        code = error.ERR_pack(lib, func, reason)
        array = (error.ERR_STRING_DATA * 2)()
        array[0].error = code
        array[0].string = b"MY ERROR"
        array[0].error = 0
        array[0].string = None
        error.ERR_load_strings(lib, array)
