INCLUDES = [
    '#include "openssl/ssl.h"',
]

FUNCTIONS = [
    "void OpenSSL_add_all_algorithms(void);",
    "void OpenSSL_add_all_ciphers(void);",
    "void OpenSSL_add_all_digests(void);",
]
