#include "init.h"
#include "auth.h"
#include "net.h"
#include "snc.h"
#include "sha3.h"
#include "aes.h"
#include "crc32.h"

#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <arpa/inet.h>

#define SIZE_READ 32768


// Parse a string into a key of AES_SIZE_KEY bytes
int init_key(uint8_t *key, const char *str, size_t len)
{
	sha3(str, len, key, AES_SIZE_KEY);
	return 0;
}

// Parse a file into a key of AES_SIZE_KEY bytes
int init_key_file(uint8_t *key, const char *path)
{
	size_t len;
	uint8_t buff[SIZE_READ];

	FILE *fp;
	sha3_ctx_t ctx;

	if (! (fp = fopen(path, "rb")))
		return -1;

	if (! (len = fread(buff, 1, SIZE_READ, fp))) {
		fclose(fp);
		return -1;
	}

	sha3_init(&ctx, AES_SIZE_KEY);

	while ((len = fread(buff, 1, SIZE_READ, fp)))
		sha3_update(&ctx, buff, len);

	sha3_final(key, &ctx);
	fclose(fp);

	return 0;
}

// Parse a command string into an array
int init_argv(char **argv, char *cmd, const char *delim)
{
	size_t argc;
	char *token = strtok(cmd, delim);

	for (argc = 0; token && argc < SNC_MAX_ARGV; ++argc) {
		argv[argc] = token;
		token = strtok(NULL, delim);
	}

	argv[argc] = NULL;

	return argc;
}

// Generate AES IVs and authentication challenge into a struct auth_info
void init_auth_info(struct AuthInfo *ai)
{
	getrandom(ai->eiv, AES_SIZE_BLOCK, GRND_RANDOM);
	getrandom(ai->div, AES_SIZE_BLOCK, GRND_RANDOM);
	getrandom(ai->challenge, AES_SIZE_BLOCK, 0);
}

void init_packet(struct SNCPacket *pkt, size_t len_payload)
{
	// Build header
	pkt->hdr.size  = htonl(len_payload);
	pkt->hdr.crc32 = htonl(crc32(pkt->payload, len_payload));
	getrandom(pkt->hdr.padding, HDR_SIZE_PADDING, 0);

	// Pad payload
	getrandom(&pkt->payload[len_payload], AES_SIZE_PADDING(len_payload), 0);
}