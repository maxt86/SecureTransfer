# SecureTransfer.Key


# distutils: sources = lib/c25519/src/f25519.c lib/c25519/src/c25519.c
# distutils: include_dirs = lib/c25519/src/


from libc.stdint cimport *

from ecc cimport *

import secrets
import sys


cdef bytes SK = b'a07485d43724023800f3eac9b7707237ee8e2ba762b9db1d2d5b0ecc5304c47c'

cdef enum: NW = 64


cdef int main(argv) except? 1:
    cdef int i, j
    
    cdef uint8_t sk[C25519_EXPONENT_SIZE]
    j = 0
    for i in range(C25519_EXPONENT_SIZE):
        sk[i] = <uint8_t>int(SK[j:j+2], 16)
        j += 2
    
    cdef bytes upb = input('User PK: ').encode('ascii')
    
    cdef uint8_t upk[F25519_SIZE]
    j = 0
    for i in range(F25519_SIZE):
       upk[i] = <uint8_t>int(upb[j:j+2], 16)
       j += 2
    
    cdef uint8_t k[F25519_SIZE]
    c25519_smult(k, upk, sk)
    
    for _ in range(NW):
        for i in range(C25519_EXPONENT_SIZE):
            sk[i] = <uint8_t>secrets.randbits(8)
    
    with open(f"{upb[:16].decode('ascii')}.bak", 'wb') as f:
        for i in range(F25519_SIZE):
            f.write(f'{k[i]:02x}'.encode('ascii'))
    
    return 0


try:
    sys.exit(main(sys.argv))
except:
    pass
