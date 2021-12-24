# SecureTransfer.Pair


# distutils: sources = lib/c25519/src/f25519.c lib/c25519/src/c25519.c
# distutils: include_dirs = lib/c25519/src/


from libc.stdint cimport *

from ecc cimport *

import secrets
import sys


cdef str KFN = 'STKEYS.txt'

cdef enum: NW = 64


cdef int main(argv) except? 1:
    cdef int i
    
    cdef uint8_t sk[C25519_EXPONENT_SIZE]
    cdef uint8_t pk[F25519_SIZE]
    
    for i in range(C25519_EXPONENT_SIZE):
        sk[i] = <uint8_t>secrets.randbits(8)
    c25519_prepare(sk)
    
    c25519_smult(pk, c25519_base_x, sk)
    
    with open(KFN, 'wb') as f:
        f.write(b'SK:\n')
        
        for i in range(C25519_EXPONENT_SIZE):
            f.write(f'{sk[i]:02x}'.encode('ascii'))
            for _ in range(NW):
                sk[i] = <uint8_t>secrets.randbits(8)
        
        f.write(b'\n\nPK:\n')
        
        for i in range(F25519_SIZE):
            f.write(f'{pk[i]:02x}'.encode('ascii'))
            for _ in range(NW):
                pk[i] = <uint8_t>secrets.randbits(8)
        
        f.write(b'\n')
    
    return 0


try:
    sys.exit(main(sys.argv))
except:
    pass
