INCLUDES = [
    '#include "openssl/ssl.h"',
]

SETUP = [
    'SSL_library_init',
]

FUNCTIONS = [
    "int SSL_library_init(void);",
]
