#ifndef HCHACHA20
#define HCHACHA20

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Data structures */

typedef struct
{
  u32 input[16];
} hchacha20_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key setup.
 */
void hchacha20_keysetup(
  hchacha20_ctx* ctx, 
  const u8* key);

/*
 * IV setup.
 */
void hchacha20_ivsetup(
  hchacha20_ctx* ctx, 
  const u8* iv);

/*
 * HChaCha20
 */

void hchacha20(
  hchacha20_ctx* ctx, 
  u8* subkey);

/* ------------------------------------------------------------------------- */

#endif /* HCHACHA20 */
