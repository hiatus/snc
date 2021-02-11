#include "aes.h"
#include "sha3.h"
#include "init.h"

#include <stdio.h>
#include <stdint.h>

#define KEY_BUFF_SIZE 32768

// Parse a key string into a AES_KEY_SIZE-byte SHA3 hash
void init_aes_key(uint8_t *key, const char *str, size_t len)
{
	sha3(str, len, key, AES_KEY_SIZE);
}

// Parse a key file into a AES_KEY_SIZE-byte SHA3 hash
int init_aes_key_file(uint8_t *key, const char *path)
{
	FILE *fp;

	size_t len;
	uint8_t buff[KEY_BUFF_SIZE];

	sha3_ctx_t ctx;

	if (! (fp = fopen(path, "rb")))
		return -1;

	if (! (len = fread(buff, 1, KEY_BUFF_SIZE, fp))) {
		fclose(fp);
		return -1;
	}

	sha3_init(&ctx, AES_KEY_SIZE);

	while ((len = fread(buff, 1, KEY_BUFF_SIZE, fp)))
		sha3_update(&ctx, buff, len);

	sha3_final(key, &ctx);

	fclose(fp);
	return 0;
}
