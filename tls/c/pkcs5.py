INCLUDES = [
    '#include "openssl/evp.h"',
]

FUNCTIONS = [
    'int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,'
        'const unsigned char *salt, int saltlen, int iter,'
        'int keylen, unsigned char *);',
]
