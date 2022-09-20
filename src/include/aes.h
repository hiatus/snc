#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_MODE_ECB
#define AES_MODE_CBC

#define AES128
//#define AES192
//#define AES256

#define AES_SIZE_COLUMN 4
#define AES_SIZE_BLOCK 16

#if defined(AES128)
	#define AES_KEY_ROUNDS 10         // Number of AES rounds
	#define AES_KEY_32WORDS 4         // Number of 32 bit words
	#define AES_SIZE_KEY 16           // Key size
	#define AES_SIZE_KEY_EXPANDED 176 // Key size after expansion

#elif defined(AES192)
	#define AES_KEY_ROUNDS 12
	#define AES_KEY_32WORDS 6
	#define AES_SIZE_KEY 24
	#define AES_SIZE_KEY_EXPANDED 208

#elif defined(AES256)
	#define AES_KEY_ROUNDS 14
	#define AES_KEY_32WORDS 8
	#define AES_SIZE_KEY 32
	#define AES_SIZE_KEY_EXPANDED 240
#endif

// Calculate AES padding length
#define AES_SIZE_PADDING(len) (-(size_t)(len) & (AES_SIZE_BLOCK - 1))

struct AESContext {
	uint8_t iv[AES_SIZE_BLOCK];
	uint8_t round_key[AES_SIZE_KEY_EXPANDED];
};

#if defined(AES_MODE_ECB)
void aes_ecb_init(struct AESContext *ctx, const uint8_t *key);

void aes_ecb_encrypt(struct AESContext *ctx, void *buffer, size_t len);
void aes_ecb_decrypt(struct AESContext *ctx, void *buffer, size_t len);
#endif

#if defined(AES_MODE_CBC)
void aes_cbc_init(struct AESContext *ctx, const uint8_t *key, const uint8_t *iv);

void aes_cbc_encrypt(struct AESContext *ctx, void *buffer, size_t len);
void aes_cbc_decrypt(struct AESContext *ctx, void *buffer, size_t len);
#endif
#endif
