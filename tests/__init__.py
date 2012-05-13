"""OpenTLS Tests"""
import operator
import functools
import unittest

from tls.api import version

def expect_fail_with(major, minor, fix, comparison=operator.eq):
    "Decorate function with expected failure compared to given OpenSSL versions"
    def expect_failure(func):
        return unittest.expectedFailure(func)
    def noop(func):
        return func
    if comparison(version()[0:3], (major, minor, fix)):
        return expect_failure
    return noop

expect_fail_before = functools.partial(expect_fail_with, comparison=operator.le)
expect_fail_after = functools.partial(expect_fail_with, comparison=operator.ge)
