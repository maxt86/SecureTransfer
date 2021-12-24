#include "xchacha20.h"

#include "chacha20.h"
#include "hchacha20.h"

void xchacha20_keysetup(xchacha20_ctx *x,const u8 *k)
{
  x->input[0] = U8TO32_LITTLE(k + 0);
  x->input[1] = U8TO32_LITTLE(k + 4);
  x->input[2] = U8TO32_LITTLE(k + 8);
  x->input[3] = U8TO32_LITTLE(k + 12);

  k += 16;
  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
}

void xchacha20_ctrsetup(xchacha20_ctx *x,const u32 ctr)
{
  x->input[8] = ctr;
}

void xchacha20_noncesetup(xchacha20_ctx *x,const u8 *n)
{
  x->input[9] = U8TO32_LITTLE(n + 0);
  x->input[10] = U8TO32_LITTLE(n + 4);
  x->input[11] = U8TO32_LITTLE(n + 8);
  x->input[12] = U8TO32_LITTLE(n + 12);
  x->input[13] = U8TO32_LITTLE(n + 16);
  x->input[14] = U8TO32_LITTLE(n + 20);
}

void xchacha20_ivsetup(xchacha20_ctx *x,const u8 *n)
{
  xchacha20_ctrsetup(x,1);
  xchacha20_noncesetup(x,n);
}

void xchacha20_encrypt_bytes(xchacha20_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  hchacha20_ctx hx;
  hchacha20_keysetup(&hx,(const u8 *)(x->input));
  hchacha20_ivsetup (&hx,(const u8 *)(x->input + 9));
  
  u8 s[32];
  hchacha20(&hx, s);
  
  u8 n[12];
  n[0] = 0;
  n[1] = 0;
  n[2] = 0;
  n[3] = 0;
  memcpy(&n[4],(x->input + 13),8);
  
  chacha20_ctx cx;
  chacha20_keysetup(&cx,s);
  chacha20_ctrsetup(&cx,x->input[8]);
  chacha20_noncesetup(&cx,n);
  
  chacha20_encrypt_bytes(&cx,m,c,bytes);
}

void xchacha20_encrypt(xchacha20_ctx *x,const u8 *m,u8 *c)
{
  xchacha20_encrypt_bytes(x,m,c,64);
}

void xchacha20_decrypt_bytes(xchacha20_ctx *x,const u8 *c,u8 *m,u32 bytes)
{
  xchacha20_encrypt_bytes(x,c,m,bytes);
}

void xchacha20_decrypt(xchacha20_ctx *x,const u8 *c,u8 *m)
{
  xchacha20_decrypt_bytes(x,c,m,64);
}

void xchacha20_keystream_bytes(xchacha20_ctx *x,u8 *stream,u32 bytes)
{
  u32 i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  xchacha20_encrypt_bytes(x,stream,stream,bytes);
}

void xchacha20_keystream(xchacha20_ctx *x,u8 *stream)
{
  xchacha20_keystream_bytes(x,stream,64);
}
