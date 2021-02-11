#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_ECB_MODE
#define AES_CBC_MODE

#define AES128
// #define AES192
// #define AES256

#define AES_COL_SIZE 4  // AES column size is constant
#define AES_BLK_SIZE 16 // AES block  size is constant

#if defined(AES128)
	#define AES_NUM_RNDS 10       // Number of AES rounds
	#define AES_KEY_32BW 4        // Number of 32 bit words
	#define AES_KEY_SIZE 16       // Key size
	#define AES_KEY_EXPD_SIZE 176 // Key size after expansion

#elif defined(AES192)
	#define AES_NUM_RNDS 12
	#define AES_KEY_32BW 6
	#define AES_KEY_SIZE 24
	#define AES_KEY_EXPD_SIZE 208

#elif defined(AES256)
	#define AES_NUM_RNDS 14
	#define AES_KEY_32BW 8
	#define AES_KEY_SIZE 32
	#define AES_KEY_EXPD_SIZE 240

#endif

struct aes_ctx {
	uint8_t iv[AES_BLK_SIZE];
	uint8_t round_key[AES_KEY_EXPD_SIZE];
};

#if defined(AES_ECB_MODE)
void aes_ecb_init(struct aes_ctx *ctx, const uint8_t *key);

void aes_ecb_encrypt(const struct aes_ctx *ctx, void *buffer, size_t len);
void aes_ecb_decrypt(const struct aes_ctx *ctx, void *buffer, size_t len);
#endif

#if defined(AES_CBC_MODE)
void aes_cbc_init(struct aes_ctx *ctx, const uint8_t *key, const uint8_t *iv);

void aes_cbc_encrypt(struct aes_ctx *ctx, void *buffer, size_t len);
void aes_cbc_decrypt(struct aes_ctx *ctx, void *buffer, size_t len);
#endif
#endif
