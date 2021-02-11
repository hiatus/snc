#ifndef CRYPTO_H
#define CRYPTO_H

#include "aes.h"

#include <stddef.h>
#include <stdint.h>

// Parse a key string into a AES_KEY_SIZE-byte SHA3 hash
void init_aes_key(uint8_t *key, const char *str, size_t len);

// Parse a key file into a AES_KEY_SIZE-byte SHA3 hash
int init_aes_key_file(uint8_t *key, const char *path);
#endif
