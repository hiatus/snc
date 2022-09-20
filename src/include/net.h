#ifndef NET_H
#define NET_H

#include "aes.h"
#include <stdint.h>


// Full header size
#define HDR_SIZE 16
// Make header size divisible by AES_SIZE_BLOCK
#define HDR_SIZE_PADDING 8

// Up to 32Kb per packet (also divisible by AES_SIZE_BLOCK)
#define PKT_SIZE_PAYLOAD 32768

// Size of the biggest possible IPv4 address
#define NET_MAX_IPV4 15

// The snc header data
struct SNCHeader {
	uint32_t size;
	uint32_t crc32;
	uint8_t padding[HDR_SIZE_PADDING];
};

// The snc packet data
struct SNCPacket {
	struct SNCHeader hdr;
	uint8_t payload[PKT_SIZE_PAYLOAD];
};

// Connection information
struct ConnectionInfo {
	int fd;
	int fdin;
	int fdout;
	int timeout;

	uint16_t port;

	struct AESContext ectx;
	struct AESContext dctx;

	char addr[NET_MAX_IPV4 + 1];

	uint8_t aes_iv[AES_SIZE_BLOCK];
	uint8_t aes_key[AES_SIZE_KEY];
};

// Server information
struct ServerInfo {
	int fd;
	uint16_t port;
};

int is_ipv4(const char *ip);
char *host_to_ipv4(char *ip, const char *host);

int srv_init(struct ServerInfo *srv);

int srv_conn(struct ServerInfo  *srv, struct ConnectionInfo *cli);
int cli_conn(struct ConnectionInfo *cli);

int srv_auth(struct ConnectionInfo *conn, uint8_t *key);
int cli_auth(struct ConnectionInfo *conn, uint8_t *key);

int net_async(struct ConnectionInfo *conn);
#endif