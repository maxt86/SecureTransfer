# SecureTransfer.Decrypt


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


cdef str WD = os.getcwd()

cdef str UPKFN = 'STKEY.txt'

cdef str DECFN = 'dec.html'
cdef bytes DEC = b'PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDx0aXRsZT5TZWN1cmVUcmFuc2ZlcjwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICogewogICAgICAgIG1hcmdpbjogMDsKICAgICAgICBwYWRkaW5nOiAwOwogICAgICB9CiAgICAgIAogICAgICBib2R5IHsKICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsKICAgICAgICBmb250LWZhbWlseTogbW9ub3NwYWNlOwogICAgICB9CiAgICAgIAogICAgICBtYWluIHsKICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICAgICAgdG9wOiA1MCU7CiAgICAgICAgbGVmdDogNTAlOwogICAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKC01MCUpOwogICAgICB9CiAgICAgIAogICAgICBoMiwgaDMgewogICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgICAgICBjb2xvcjogZ3JheTsKICAgICAgfQogICAgPC9zdHlsZT4KICA8L2hlYWQ+CiAgPGJvZHk+CiAgICA8bWFpbj4KICAgICAgPGgyPlNlY3VyZVRyYW5zZmVyIGlzIGRlY3J5cHRpbmcgeW91ciBmaWxlcy4uLjwvaDI+CiAgICAgIDxoMz5EbyBub3QgdHVybiBvZmYgeW91ciBQQyB1bnRpbCBub3RpZmllZC48L2gzPgogICAgPC9tYWluPgogIDwvYm9keT4KPC9odG1sPgo='

cdef str DDONEFN = 'ddone.html'
cdef bytes DDONE = b'PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDx0aXRsZT5TZWN1cmVUcmFuc2ZlcjwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICogewogICAgICAgIG1hcmdpbjogMDsKICAgICAgICBwYWRkaW5nOiAwOwogICAgICB9CiAgICAgIAogICAgICBib2R5IHsKICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiBibGFjazsKICAgICAgICBmb250LWZhbWlseTogbW9ub3NwYWNlOwogICAgICB9CiAgICAgIAogICAgICBtYWluIHsKICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICAgICAgdG9wOiA1MCU7CiAgICAgICAgbGVmdDogNTAlOwogICAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKC01MCUpOwogICAgICB9CiAgICAgIAogICAgICBoMiwgaDMgewogICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgICAgICBjb2xvcjogZ3JlZW47CiAgICAgIH0KICAgIDwvc3R5bGU+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPG1haW4+CiAgICAgIDxoMj5Eb25lLjwvaDI+CiAgICAgIDxoMz5TZWN1cmVUcmFuc2ZlciBoYXMgZmluaXNoZWQgZGVjcnlwdGluZyB5b3VyIGRhdGEuPC9oMz4KICAgICAgPGgzPllvdSBtYXkgdHVybiBvZmYgeW91ciBQQyBpZiB5b3Ugd2FudC48L2gzPgogICAgPC9tYWluPgogIDwvYm9keT4KPC9odG1sPgo='

cdef enum: KSIZE = 32
cdef enum: NSIZE = 24
cdef enum: BLKSIZE = 64


cdef void dec(str fn, uint8_t k[KSIZE]) except *:
    if not fn.endswith('.st'):
        return
    
    if not os.path.isfile(fn):
        return
    
    cdef int fs = os.path.getsize(fn)
    if fs == 0:
        return
    
    cdef int i, j
    
    cdef xchacha20_ctx x
    
    xchacha20_keysetup(&x, k)
    
    cdef uint8_t n[NSIZE]
    try:
        with open(f'{os.path.splitext(fn)[0]}.stinfo', 'rb') as f:
            for i in range(NSIZE):
                n[i] = <uint8_t>int(f.read(2), 16)
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
                xchacha20_decrypt(&x, blk, blk)
                
                f.seek(-BLKSIZE, 1)
                for j in range(BLKSIZE):
                    f.write(<bytes>blk[j])
            
            rb = fs - (i * BLKSIZE)
            
            for j in range(rb):
                blk[j] = <uint8_t>ord(f.read(1))
            
            xchacha20_ctrsetup(&x, i+1)
            xchacha20_decrypt_bytes(&x, blk, blk, rb)
            
            f.seek(-rb, 1)
            for j in range(rb):
                f.write(<bytes>blk[j])
        
        os.rename(fn, os.path.splitext(fn)[0])
        os.remove(f'{os.path.splitext(fn)[0]}.stinfo')
    except:
        pass


cdef int main(argv) except? 1:
    cdef int i
    
    os.chdir(WD)
    
    try:
        with open(UPKFN, 'rb') as f:
            bakfn = f"{f.read(16).decode('ascii')}.bak"
    except:
        return 1
    
    cdef uint8_t k[F25519_SIZE]
    try:
        with open(bakfn, 'rb') as f:
            for i in range(F25519_SIZE):
                k[i] = <uint8_t>int(f.read(2), 16)
    except:
        return 1
    
    with open(DECFN, 'wb') as f:
        f.write(base64.b64decode(DEC))
    webbrowser.open('file://' + os.path.realpath(DECFN))
    
    time.sleep(5)
    os.remove(DECFN)
    
    for root, dirs, files in os.walk(WD):
        os.chdir(root)
        with concurrent.futures.ThreadPoolExecutor() as x:
            x.map(lambda fn: dec(fn, k), files)
    
    os.chdir(WD)
    
    os.remove(UPKFN)
    os.remove(bakfn)
    
    with open(DDONEFN, 'wb') as f:
        f.write(base64.b64decode(DDONE))
    webbrowser.open('file://' + os.path.realpath(DDONEFN))
    
    time.sleep(5)
    os.remove(DDONEFN)
    
    return 0


try:
    sys.exit(main(sys.argv))
except:
    pass
