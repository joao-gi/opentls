"""Test OpenSSL error handling"""
import logging

import unittest2 as unittest
import mock

from tls.c import api
from tls import err


class TestErrorFetch(unittest.TestCase):

    first = b"error:2006D080:BIO routines:BIO_new_file:no such file"
    last = b"error:140943E8:SSL routines:SSL3_READ_BYTES:reason(1000)"

    def setUp(self):
        while api.ERR_get_error() != 0:
            pass
        api.ERR_put_error(0x20, 0x6D, 0x80, api.NULL, 0)
        api.ERR_put_error(0x14, 0x94, 0x3E8, api.NULL, 0)

    def tearDown(self):
        self.count_errors_on_stack()

    def count_errors_on_stack(self):
        count = 0
        while api.ERR_get_error() != 0:
            count += 1
        return count

    @mock.patch('tls.err.logger')
    def test_return_errors(self, logger):
        messages = err.log_errors()
        self.assertEqual(messages, [self.first, self.last])

    @mock.patch('tls.err.logger')
    def test_clear_errors_as_error(self, logger):
        err.log_errors()
        calls = [
            mock.call(logging.ERROR, self.first),
            mock.call(logging.ERROR, self.last),
        ]
        logger.log.assert_has_calls(calls)
        self.assertEqual(2, logger.log.call_count)
        self.assertEqual(0, self.count_errors_on_stack())

    @mock.patch('tls.err.logger')
    def test_clear_errors_as_debug(self, logger):
        err.log_errors(level=logging.DEBUG)
        calls = [
            mock.call(logging.DEBUG, self.first),
            mock.call(logging.DEBUG, self.last),
        ]
        logger.log.assert_has_calls(calls)
        self.assertEqual(2, logger.log.call_count)
        self.assertEqual(0, self.count_errors_on_stack())

    @mock.patch('tls.err.logger')
    def test_errors_on_exception(self, logger):
        @err.log_errors
        def func():
            raise ValueError("")
        self.assertRaises(ValueError, func)
        calls = [
            mock.call(logging.DEBUG, self.first),
            mock.call(logging.DEBUG, self.last),
        ]
        logger.log.assert_has_calls(calls)
        self.assertEqual(2, logger.log.call_count)
        self.assertEqual(0, self.count_errors_on_stack())

    @mock.patch('tls.err.logger')
    def test_errors_on_return(self, logger):
        @err.log_errors
        def func():
            pass
        func()
        calls = [
            mock.call(logging.ERROR, self.first),
            mock.call(logging.ERROR, self.last),
        ]
        logger.log.assert_has_calls(calls)
        self.assertEqual(2, logger.log.call_count)
        self.assertEqual(0, self.count_errors_on_stack())

    @mock.patch('tls.err.logger')
    def test_no_errors(self, logger):
        self.count_errors_on_stack()
        @err.log_errors
        def func():
            pass
        func()
        self.assertEqual(0, logger.log.call_count)
        self.assertEqual(0, self.count_errors_on_stack())
