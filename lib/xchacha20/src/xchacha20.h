#ifndef XCHACHA20
#define XCHACHA20

#include "ecrypt-portable.h"

/* ------------------------------------------------------------------------- */

/* Data structures */

typedef struct
{
  u32 input[15];
} xchacha20_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key setup.
 */
void xchacha20_keysetup(
  xchacha20_ctx* ctx, 
  const u8* key);

/*
 * Counter setup.
 */
void xchacha20_ctrsetup(
  xchacha20_ctx* ctx, 
  const u32 ctr);

/*
 * Nonce setup.
 */
void xchacha20_noncesetup(
  xchacha20_ctx* ctx, 
  const u8* nonce);

/*
 * IV setup. After having called xchacha20_keysetup(), the user is
 * allowed to call xchacha20_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void xchacha20_ivsetup(
  xchacha20_ctx* ctx, 
  const u8* nonce);

/*
 * Encryption/decryption of arbitrary length messages.
 */

void xchacha20_encrypt_bytes(
  xchacha20_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void xchacha20_encrypt(
  xchacha20_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext);

void xchacha20_decrypt_bytes(
  xchacha20_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

void xchacha20_decrypt(
  xchacha20_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext);

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext.
 */

void xchacha20_keystream_bytes(
  xchacha20_ctx* ctx, 
  u8* keystream, 
  u32 length);                /* Length of keystream in bytes. */ 

void xchacha20_keystream(
  xchacha20_ctx* ctx, 
  u8* keystream);

/* ------------------------------------------------------------------------- */

#endif /* XCHACHA20*/
