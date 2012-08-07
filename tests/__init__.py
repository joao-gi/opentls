"""OpenTLS Tests"""
import functools
import logging
import operator
import unittest2 as unittest

import cffi

import tls.c

cffi.verifier.cleanup_tmpdir()

logging.basicConfig()

def expect_fail_with(major, minor, fix, comparison=operator.eq):
    "Decorate function with expected failure compared to given OpenSSL versions"
    def expect_failure(func):
        return unittest.expectedFailure(func)
    def noop(func):
        return func
    if comparison(tls.c.api.version()[0:3], (major, minor, fix)):
        return expect_failure
    return noop

expect_fail_before = functools.partial(expect_fail_with, comparison=operator.lt)
expect_fail_after = functools.partial(expect_fail_with, comparison=operator.ge)

def skip_with(major, minor, fix, comparison=operator.eq, message='incompatible OpenSSL version'):
    "Decorate function to skip compared to given OpenSSL versions"
    def skip(func):
        return unittest.skip(message)(func)
    def noop(func):
        return func
    if comparison(tls.c.api.version()[0:3], (major, minor, fix)):
        return skip
    return noop

skip_before = functools.partial(skip_with, comparison=operator.lt)
skip_after = functools.partial(skip_with, comparison=operator.ge)
