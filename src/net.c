#include "net.h"
#include "snc.h"
#include "init.h"
#include "crc32.h"
#include "auth.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/random.h>

#define MAX_IPV4 15
#define SIZE_READ 32768


static ssize_t _recvall(int sockfd, void *buffer, size_t len)
{
	ssize_t ret;
	ssize_t total = 0;

	while (len) {
		if ((ret = recv(sockfd, (uint8_t *)buffer + total, len, 0)) <= 0)
			break;

		len -= ret;
		total += ret;
	}

	return total;
}

static ssize_t _sendall(int sock, void *buffer, size_t len)
{
	ssize_t ret;
	ssize_t total = 0;

	while (len) {
		if ((ret = send(sock, (uint8_t *)buffer + total, len, 0)) <= 0)
			break;

		len -= ret;
		total += ret;
	}

	return total;
}

int is_ipv4(const char *ip)
{
	struct sockaddr_in sa;
	return (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1);
}

char *host_to_ipv4(char *ip, const char *host)
{
	struct hostent *he;

	if (! (he = gethostbyname(host)))
		return NULL;

	memset(ip, 0x00, MAX_IPV4 + 1);
	strncpy(ip, inet_ntoa(*((struct in_addr **)he->h_addr_list)[0]), MAX_IPV4);

	return ip;
}

int srv_init(struct ServerInfo *srv)
{
	int ret;
	int reuse = 1;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(srv->port),
		.sin_addr.s_addr = INADDR_ANY
	};

	if ((srv->fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return srv->fd;

	setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

	ret = bind(
		srv->fd,
		(struct sockaddr *)&addr, sizeof(struct sockaddr_in)
	);

	if (ret < 0) {
		close(srv->fd);
		return 1;
	}

	if ((ret = listen(srv->fd, 1)) < 0) {
		close(srv->fd);
		return 1;
	}

	return 0;
}

int srv_conn(struct ServerInfo *srv, struct ConnectionInfo *conn)
{
	socklen_t addr_size;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(srv->port),
		.sin_addr.s_addr = INADDR_ANY
	};

	addr_size = sizeof(struct sockaddr_in);
	conn->fd = accept(srv->fd, (struct sockaddr *)&addr, &addr_size);

	if (conn->fd < 0) {
		conn->fd = 0;
		return 1;
	}

	memset(conn->addr, 0x00, NET_MAX_IPV4 + 1);

	conn->port = ntohs(addr.sin_port);
	strncpy(conn->addr, inet_ntoa(addr.sin_addr), NET_MAX_IPV4);

	return 0;
}

int cli_conn(struct ConnectionInfo *conn)
{
	int ret;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(conn->port),
		.sin_addr.s_addr = inet_addr(conn->addr)
	};

	if ((conn->fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		conn->fd = 0;
		return 1;
	}

	ret = connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));

	if (ret < 0) {
		close(conn->fd);
		return 1;
	}

	return 0;
}

int srv_auth(struct ConnectionInfo *conn, uint8_t *key)
{
	struct AuthInfo ai;
	uint8_t challenge[AUTH_SIZE_CHALLENGE];

	// Receive AES IVs and authentication challenge from the client
	if (_recvall(conn->fd, &ai, AUTH_SIZE) != AUTH_SIZE)
		return SNC_ESYNC;

	// Initialize AES contexts
	aes_cbc_init(&conn->ectx, key, ai.eiv);
	aes_cbc_init(&conn->dctx, key, ai.div);

	// Decrypt, store and reencrypt the challenge
	aes_cbc_decrypt(&conn->dctx, ai.challenge, AUTH_SIZE_CHALLENGE);
	memcpy(challenge, ai.challenge, AUTH_SIZE_CHALLENGE);
	aes_cbc_encrypt(&conn->ectx, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Send the challenge to the client
	if (_sendall(conn->fd, ai.challenge, AUTH_SIZE_CHALLENGE) != AUTH_SIZE_CHALLENGE)
		return SNC_ESYNC;

	// Receive the challenge decrypted and reencrypted from the client
	if (_recvall(conn->fd, ai.challenge, AUTH_SIZE_CHALLENGE) != AUTH_SIZE_CHALLENGE)
		return SNC_ESYNC;

	// Decrypt the challenge
	aes_cbc_decrypt(&conn->dctx, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Authenticate the client
	if (memcmp(challenge, ai.challenge, AUTH_SIZE_CHALLENGE))
		return SNC_EAUTH;
	
	return 0;
}

int cli_auth(struct ConnectionInfo *conn, uint8_t *key)
{
	int ret = 0;
	struct AuthInfo ai;

	uint8_t challenge[AUTH_SIZE_CHALLENGE];

	// Generate AES IVs and authentication challenge
	init_auth_info(&ai);
	memcpy(challenge, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Initialize AES contexts (reverse encryption and decryption IVs)
	aes_cbc_init(&conn->ectx, key, ai.div);
	aes_cbc_init(&conn->dctx, key, ai.eiv);

	// Encrypt the challenge
	aes_cbc_encrypt(&conn->ectx, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Send IVs and challenge to the server
	if (_sendall(conn->fd, &ai, AUTH_SIZE) != AUTH_SIZE)
		return SNC_ESYNC;

	// Receive the challenge decrypted and reencrypted from the client
	if (_recvall(conn->fd, ai.challenge, AUTH_SIZE_CHALLENGE) != AUTH_SIZE_CHALLENGE)
		return SNC_ESYNC;

	// Decrypt the challenge
	aes_cbc_decrypt(&conn->dctx, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Authenticate the server
	if (memcmp(challenge, ai.challenge, AUTH_SIZE_CHALLENGE))
		ret = SNC_EAUTH;

	// Encrypt the challenge
	aes_cbc_encrypt(&conn->ectx, ai.challenge, AUTH_SIZE_CHALLENGE);

	// Send the challenge to the server
	if (_sendall(conn->fd, ai.challenge, AUTH_SIZE_CHALLENGE) != AUTH_SIZE_CHALLENGE)
		return SNC_ESYNC;

	return ret;
}

int net_async(struct ConnectionInfo *conn)
{
	ssize_t len;

	int ret_poll, ret_txrx, ret_read;
	int timeout = (conn->timeout) ? conn->timeout * 1000 : -1;

	struct SNCPacket pkt;

	struct pollfd infds[2] = {
		{.fd = conn->fd, .events = POLLIN},
		{.fd = conn->fdin, .events = POLLIN}
	};

	struct pollfd outfds[2] = {
		{.fd = conn->fd,  .events = POLLOUT},
		{.fd = conn->fdout, .events = POLLOUT}
	};

	while ((ret_poll = poll(infds, 2, timeout)) > 0) {
		if (poll(outfds, 2, 0) <= 0)
			continue;

		if (infds[0].revents & POLLIN && outfds[1].revents & POLLOUT) {
			// Receive header
			ret_txrx = _recvall(conn->fd, &pkt.hdr, sizeof(struct SNCHeader));

			if (ret_txrx != sizeof(struct SNCHeader))
				return (ret_txrx) ? SNC_ESYNC : 0;

			// Decrypt and parse header
			aes_cbc_decrypt(&conn->dctx, &pkt.hdr, sizeof(struct SNCHeader));

			pkt.hdr.size  = ntohl(pkt.hdr.size);
			pkt.hdr.crc32 = ntohl(pkt.hdr.crc32);

			// Receive payload
			len = pkt.hdr.size + AES_SIZE_PADDING(pkt.hdr.size);

			if ((ret_txrx = _recvall(conn->fd, pkt.payload, len)) != len)
				return (ret_txrx) ? SNC_ESYNC : 0;

			// Decrypt payload
			aes_cbc_decrypt(&conn->dctx, pkt.payload, len);

			// Verify payload integrity
			if (pkt.hdr.crc32 != crc32(pkt.payload, pkt.hdr.size))
				return SNC_ECRPT;

			// Write data
			write(conn->fdout, pkt.payload, pkt.hdr.size);
		}

		if (infds[1].revents & POLLIN && outfds[0].revents & POLLOUT) {
			// Read data
			if ((ret_read = read(conn->fdin, pkt.payload, SIZE_READ)) <= 0)
				break;

			// Initialize packet header and pad it's payload
			init_packet(&pkt, ret_read);

			// Encrypt header and payload
			len = ret_read + AES_SIZE_PADDING(ret_read);

			aes_cbc_encrypt(&conn->ectx, &pkt.hdr, sizeof(struct SNCHeader));
			aes_cbc_encrypt(&conn->ectx, pkt.payload, len);

			// Send packet
			len += sizeof(struct SNCHeader);

			if ((ret_txrx = _sendall(conn->fd, &pkt, len)) != len)
				return (ret_txrx) ? SNC_ESYNC : 0;
		}
	}

	return (ret_poll) ? 0 : SNC_ETIME;
}