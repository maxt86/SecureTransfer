#include "hchacha20.h"

#include "chacha20r.h"

void hchacha20_keysetup(hchacha20_ctx *x,const u8 *k)
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

void hchacha20_ivsetup(hchacha20_ctx *x,const u8 *iv)
{
  x->input[12] = U8TO32_LITTLE(iv + 0);
  x->input[13] = U8TO32_LITTLE(iv + 4);
  x->input[14] = U8TO32_LITTLE(iv + 8);
  x->input[15] = U8TO32_LITTLE(iv + 12);
}

void hchacha20(hchacha20_ctx *x,u8 *s)
{
  u8 output[64];
  int i;

  salsa20_wordtobyte(output,x->input);

  for (i = 0;i < 16;++i) {
    *s++ = output[i];
  }
  for (i = 48;i < 64;++i) {
    *s++ = output[i];
  }
}
