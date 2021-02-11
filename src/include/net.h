#ifndef NET_H
#define NET_H

#include "aes.h"

#include <stddef.h>
#include <stdint.h>

#define NET_CONN_MAX 1
#define NET_IPV4_MAX 15
#define NET_HOST_MAX 256
#define NET_BUFF_MAX 32768

#define NET_CLG_SIZE     AES_BLK_SIZE
#define NET_HDR_SIZE     sizeof(struct snc_header)
#define NET_HDR_PAD_SIZE (AES_BLK_SIZE - sizeof(uint32_t) - sizeof(uint32_t))

// AES_BLK_SIZE bytes
struct snc_header {
	uint32_t size;
	uint32_t crc32;
	uint8_t pad[NET_HDR_PAD_SIZE];
};

struct snc_packet {
	struct snc_header hdr;
	uint8_t data[NET_BUFF_MAX];
};

struct conn_info {
	int sock;
	int fdin;
	int fdout;
	int timeout;

	uint16_t port;

	size_t recv_bytes;
	size_t send_bytes;

	struct aes_ctx ectx;
	struct aes_ctx dctx;

	char addr[NET_IPV4_MAX + 1];

	uint8_t aes_iv [AES_BLK_SIZE];
	uint8_t aes_key[AES_KEY_SIZE];
};

struct srv_info {
	int sock;
	uint16_t port;

	struct conn_info conn;
};

int is_ipv4(const char *ip);

int srv_init(struct srv_info *srv);

int srv_conn(struct srv_info  *srv);
int cli_conn(struct conn_info *cli);

int srv_auth(struct conn_info *conn, uint8_t *key);
int cli_auth(struct conn_info *conn, uint8_t *key);

int async_io(struct conn_info *conn);

char *hostname_to_ipv4(char *ip, const char *host);
#endif
