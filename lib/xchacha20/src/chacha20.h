#ifndef CHACHA20
#define CHACHA20

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Data structures */

typedef struct
{
  u32 input[16];
} chacha20_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key setup.
 */
void chacha20_keysetup(
  chacha20_ctx* ctx, 
  const u8* key);

/*
 * Counter setup.
 */
void chacha20_ctrsetup(
  chacha20_ctx* ctx, 
  const u32 ctr);

/*
 * Nonce setup.
 */
void chacha20_noncesetup(
  chacha20_ctx* ctx, 
  const u8* nonce);

/*
 * IV setup. After having called chacha20_keysetup(), the user is
 * allowed to call chacha20_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void chacha20_ivsetup(
  chacha20_ctx* ctx, 
  const u8* nonce);

/*
 * Encryption/decryption of arbitrary length messages.
 */

void chacha20_encrypt_bytes(
  chacha20_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void chacha20_encrypt(
  chacha20_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext);

void chacha20_decrypt_bytes(
  chacha20_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

void chacha20_decrypt(
  chacha20_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext);

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext.
 */

void chacha20_keystream_bytes(
  chacha20_ctx* ctx, 
  u8* keystream, 
  u32 length);                /* Length of keystream in bytes. */ 

void chacha20_keystream(
  chacha20_ctx* ctx, 
  u8* keystream);

/* ------------------------------------------------------------------------- */

#endif /* CHACHA20*/
