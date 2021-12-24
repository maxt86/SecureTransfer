#ifndef CHACHA20R
#define CHACHA20R

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/*
 * Round function and additional macros.
 */

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

void salsa20_wordtobyte(
  u8 output[64], 
  const u32 input[16]);

/* ------------------------------------------------------------------------- */

#endif /* CHACHA20R*/
