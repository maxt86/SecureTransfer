#include "chacha20.h"

#include "chacha20r.h"

void chacha20_keysetup(chacha20_ctx *x,const u8 *k)
{
  const char *constants = "expand 32-byte k";
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);

  k += 16;
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
}

void chacha20_ctrsetup(chacha20_ctx *x,const u32 ctr)
{
  x->input[12] = ctr;
}

void chacha20_noncesetup(chacha20_ctx *x,const u8 *n)
{
  x->input[13] = U8TO32_LITTLE(n + 0);
  x->input[14] = U8TO32_LITTLE(n + 4);
  x->input[15] = U8TO32_LITTLE(n + 8);
}

void chacha20_ivsetup(chacha20_ctx *x, const u8 *n)
{
  chacha20_ctrsetup(x,1);
  chacha20_noncesetup(x,n);
}

void chacha20_encrypt_bytes(chacha20_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u8 output[64];
  u32 i;

  if (!bytes) return;
  for (;;) {
    if (!x->input[12]) return;
    salsa20_wordtobyte(output,x->input);
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      x->input[12] = PLUSONE(x->input[12]);
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
    x->input[12] = PLUSONE(x->input[12]);
  }
}

void chacha20_encrypt(chacha20_ctx *x,const u8 *m,u8 *c)
{
  chacha20_encrypt_bytes(x,m,c,64);
}

void chacha20_decrypt_bytes(chacha20_ctx *x,const u8 *c,u8 *m,u32 bytes)
{
  chacha20_encrypt_bytes(x,c,m,bytes);
}

void chacha20_decrypt(chacha20_ctx *x,const u8 *c,u8 *m)
{
  chacha20_decrypt_bytes(x,c,m,64);
}

void chacha20_keystream_bytes(chacha20_ctx *x,u8 *stream,u32 bytes)
{
  u32 i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  chacha20_encrypt_bytes(x,stream,stream,bytes);
}

void chacha20_keystream(chacha20_ctx *x,u8 *stream)
{
  chacha20_keystream_bytes(x,stream,64);
}
