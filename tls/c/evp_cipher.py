INCLUDES = [
    '#include "openssl/evp.h"',
]

TYPES = [
    'typedef ... EVP_CIPHER;',
    'typedef ... EVP_CIPHER_CTX;',
]

FUNCTIONS = [
    'void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);',
]
