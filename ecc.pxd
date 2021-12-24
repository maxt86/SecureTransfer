from libc.stdint cimport *


cdef extern from 'f25519.h':
    enum: F25519_SIZE


cdef extern from 'c25519.h':
    enum: C25519_EXPONENT_SIZE
    
    const uint8_t c25519_base_x[F25519_SIZE]
    
    void c25519_prepare(uint8_t* key)
    void c25519_smult(uint8_t* result, const uint8_t* q, const uint8_t* e)
