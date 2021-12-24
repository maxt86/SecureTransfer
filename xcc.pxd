from libc.stdint cimport *


cdef extern from 'xchacha20.h':
    
    ctypedef struct xchacha20_ctx:
        pass
    
    
    void xchacha20_keysetup(xchacha20_ctx* ctx, const uint8_t* key)
    
    void xchacha20_ctrsetup(xchacha20_ctx* ctx, const uint32_t ctr)
    
    void  xchacha20_noncesetup (xchacha20_ctx* ctx, const uint8_t* nonce)
    void  xchacha20_ivsetup    (xchacha20_ctx* ctx, const uint8_t* nonce)
    
    
    void xchacha20_encrypt_bytes(
                   xchacha20_ctx*         ctx,
            const  uint8_t*         plaintext,
                   uint8_t*        ciphertext,
                   uint32_t            msglen)
    
    void xchacha20_encrypt(
                   xchacha20_ctx*         ctx,
            const  uint8_t*         plaintext,
                   uint8_t*        ciphertext)
    
    
    void xchacha20_decrypt_bytes(
                   xchacha20_ctx*         ctx,
            const  uint8_t*        ciphertext,
                   uint8_t*         plaintext,
                   uint32_t            msglen)
    
    void xchacha20_decrypt(
                   xchacha20_ctx*         ctx,
            const  uint8_t*        ciphertext,
                   uint8_t*         plaintext)
    
    
    void  xchacha20_keystream_bytes (xchacha20_ctx* ctx, uint8_t* keystream, uint32_t length)
    void  xchacha20_keystream       (xchacha20_ctx* ctx, uint8_t* keystream)
