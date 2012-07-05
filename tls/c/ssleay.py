INCLUDES = [
    '#include "openssl/ssl.h"',
]

FUNCTIONS = [
    "long SSLeay(void);",
    "const char* SSLeay_version(int);",
]
