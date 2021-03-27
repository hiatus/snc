#include "net.h"
#include "snc.h"
#include "init.h"
#include "aes.h"
#include "sha3.h"
#include "crc32.h"

#include <poll.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/random.h>

static struct snc_packet pkt;

static ssize_t _recvall(int sock, void *buffer, size_t len)
{
	ssize_t ret;
	ssize_t total = 0;

	while (len) {
		if ((ret = recv(sock, (uint8_t *)buffer + total, len, 0)) <= 0)
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

int srv_init(struct srv_info *srv)
{
	int ret;
	int reuse = 1;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(srv->port),
		.sin_addr.s_addr = INADDR_ANY
	};

	if ((srv->sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return srv->sock;

	setsockopt(srv->sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

	ret = bind(
		srv->sock,
		(struct sockaddr *)&addr, sizeof(struct sockaddr_in)
	);

	if (ret < 0) {
		close(srv->sock);
		return SNC_ECONN;
	}

	if ((ret = listen(srv->sock, NET_CONN_MAX)) < 0) {
		close(srv->sock);
		return SNC_ECONN;
	}

	return 0;
}

int srv_conn(struct srv_info *srv)
{
	socklen_t addr_size;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(srv->port),
		.sin_addr.s_addr = INADDR_ANY
	};

	addr_size = sizeof(struct sockaddr_in);
	srv->conn.sock = accept(srv->sock, (struct sockaddr *)&addr, &addr_size);

	if (srv->conn.sock < 0) {
		srv->conn.sock = 0;
		return SNC_ECONN;
	}

	memset(srv->conn.addr, 0x00, NET_IPV4_MAX + 1);

	srv->conn.port = ntohs(addr.sin_port);
	strncpy(srv->conn.addr, inet_ntoa(addr.sin_addr), NET_IPV4_MAX);

	return 0;
}

int cli_conn(struct conn_info *conn)
{
	int ret;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(conn->port),
		.sin_addr.s_addr = inet_addr(conn->addr)
	};

	if ((conn->sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		conn->sock = 0;
		return SNC_ECONN;
	}

	ret = connect(conn->sock, (struct sockaddr *)&addr, sizeof(addr));

	if (ret < 0) {
		close(conn->sock);
		return SNC_ECONN;
	}

	return 0;
}

int srv_auth(struct conn_info *conn, uint8_t *key)
{
	ssize_t ret;

	uint8_t iv[AES_BLK_SIZE];

	uint8_t srv_challenge[NET_CLG_SIZE];
	uint8_t cli_challenge[NET_CLG_SIZE];

	// Initialize AES contexts
	getrandom(iv, AES_BLK_SIZE, 0);
	aes_cbc_init(&conn->ectx, key, iv);

	getrandom(iv, AES_BLK_SIZE, 0);
	aes_cbc_init(&conn->dctx, key, iv);

	// Send IVs to the client
	ret = _sendall(conn->sock, conn->ectx.iv, AES_BLK_SIZE);

	if (ret != AES_BLK_SIZE)
		goto err_send;

	ret = _sendall(conn->sock, conn->dctx.iv, AES_BLK_SIZE);

	if (ret != AES_BLK_SIZE)
		goto err_send;

	conn->send_bytes += AES_BLK_SIZE * 2;

	// Send the encrypted challenge
	getrandom(srv_challenge, NET_CLG_SIZE, 0);

	memcpy(pkt.data, srv_challenge, NET_CLG_SIZE);
	aes_cbc_encrypt(&conn->ectx, pkt.data, NET_CLG_SIZE);

	ret = _sendall(conn->sock, pkt.data, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_send;

	conn->send_bytes += NET_CLG_SIZE;

	// Receive the challenge decrypted and encrypted by the client's contexts
	ret = _recvall(conn->sock, cli_challenge, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_recv;

	conn->recv_bytes += NET_CLG_SIZE;

	aes_cbc_decrypt(&conn->dctx, cli_challenge, NET_CLG_SIZE);

	// Send it encrypted with the updated context
	memcpy(pkt.data, cli_challenge, NET_CLG_SIZE);
	aes_cbc_encrypt(&conn->ectx, pkt.data, NET_CLG_SIZE);

	ret = _sendall(conn->sock, pkt.data, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_send;

	conn->send_bytes += NET_CLG_SIZE;

	// Validate
	if (memcmp(srv_challenge, cli_challenge, NET_CLG_SIZE))
		return SNC_EAUTH;

	return 0;

err_recv:
	if (ret > 0)
		conn->recv_bytes += ret;

	return SNC_ESYNC;

err_send:
	if (ret > 0)
		conn->send_bytes += ret;

	return SNC_ESYNC;
}

int cli_auth(struct conn_info *conn, uint8_t *key)
{
	ssize_t ret;

	uint8_t eiv[AES_BLK_SIZE];
	uint8_t div[AES_BLK_SIZE];

	uint8_t challenge[NET_CLG_SIZE];

	// Receive IVs from the server
	if ((ret = _recvall(conn->sock, div, AES_BLK_SIZE)) != AES_BLK_SIZE)
		goto err_recv;

	if ((ret = _recvall(conn->sock, eiv, AES_BLK_SIZE)) != AES_BLK_SIZE)
		goto err_recv;

	conn->recv_bytes += AES_BLK_SIZE * 2;

	// Initialize AES contexts
	aes_cbc_init(&conn->ectx, key, eiv);
	aes_cbc_init(&conn->dctx, key, div);

	// Receive the encrypted challenge
	ret = _recvall(conn->sock, challenge, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_recv;

	conn->recv_bytes += NET_CLG_SIZE;

	// Send the challenge decrypted and encrypted with the contexts
	aes_cbc_decrypt(&conn->dctx, challenge, NET_CLG_SIZE);

	memcpy(pkt.data, challenge, NET_CLG_SIZE);
	aes_cbc_encrypt(&conn->ectx, pkt.data, NET_CLG_SIZE);

	ret = _sendall(conn->sock, pkt.data, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_send;

	conn->send_bytes += NET_CLG_SIZE;

	// Receive the challenge encrypted with the updated server context
	ret = _recvall(conn->sock, pkt.data, NET_CLG_SIZE);

	if (ret != NET_CLG_SIZE)
		goto err_recv;

	conn->recv_bytes += NET_CLG_SIZE;

	// Decrypt and validate
	aes_cbc_decrypt(&conn->dctx, pkt.data, NET_CLG_SIZE);

	if (memcmp(challenge, pkt.data, NET_CLG_SIZE))
		return SNC_EAUTH;

	return 0;

err_recv:
	if (ret > 0)
		conn->recv_bytes += ret;

	return SNC_ESYNC;

err_send:
	if (ret > 0)
		conn->send_bytes += ret;

	return SNC_ESYNC;
}

int async_io(struct conn_info *conn)
{
	uint32_t len;

	int ret = 0, ret_poll = 0;
	int timeout = (conn->timeout) ? conn->timeout * 1000 : -1;

	struct pollfd infds[2] = {
		{.fd = conn->sock, .events = POLLIN},
		{.fd = conn->fdin, .events = POLLIN},
	};

	struct pollfd outfds[2] = {
		{.fd = conn->sock,  .events = POLLOUT},
		{.fd = conn->fdout, .events = POLLOUT},
	};

	while ((ret_poll = poll(infds, 2, timeout)) > 0) {
		if (poll(outfds, 2, 0) <= 0)
			continue;

		if (infds[0].revents & POLLIN && outfds[1].revents & POLLOUT) {
			// Receive header
			ret = _recvall(conn->sock, &pkt.hdr, sizeof(struct snc_header));

			if (ret != sizeof(struct snc_header))
				goto out_recv;

			conn->recv_bytes += sizeof(struct snc_header);
			aes_cbc_decrypt(&conn->dctx, &pkt.hdr, sizeof(struct snc_header));

			pkt.hdr.size  = ntohl(pkt.hdr.size);
			pkt.hdr.crc32 = ntohl(pkt.hdr.crc32);

			len = pkt.hdr.size + AES_PAD_SIZE(pkt.hdr.size);

			// Receive packet data
			ret = _recvall(conn->sock, pkt.data, len);

			if ((uint32_t)ret != len)
				goto out_recv;

			conn->recv_bytes += len;
			aes_cbc_decrypt(&conn->dctx, pkt.data, len);

			// Check data integrity
			if (pkt.hdr.crc32 != crc32(pkt.data, pkt.hdr.size)) {
				ret = SNC_ECRPT;
				goto out_recv;
			}

			write(conn->fdout, pkt.data, pkt.hdr.size);
		}

		if (infds[1].revents & POLLIN && outfds[0].revents & POLLOUT) {
			if ((ret = read(conn->fdin, pkt.data, NET_BUFF_MAX)) <= 0)
				break;

			// Build packet header and pad buffer
			pkt.hdr.size  = htonl(ret);
			pkt.hdr.crc32 = htonl(crc32(pkt.data, ret));

			memset(&pkt.data[ret], 0x00, AES_PAD_SIZE(ret));
			
			len = ret + AES_PAD_SIZE(ret);

			aes_cbc_encrypt(&conn->ectx, &pkt.hdr, sizeof(struct snc_header));
			aes_cbc_encrypt(&conn->ectx, pkt.data, len);

			len += sizeof(struct snc_header);

			// Send packet
			ret = _sendall(conn->sock, &pkt, len);

			if ((uint32_t)ret != len)
				goto out_send;

			conn->send_bytes += len;
		}
	}

	return (ret_poll == 0) ? SNC_ETIME : 0;

out_recv:
	if (ret > 0)
		conn->recv_bytes += ret;

	return (ret != 0) ? SNC_ESYNC : 0;

out_send:
	if (ret > 0)
		conn->send_bytes += ret;

	return (ret != 0) ? SNC_ESYNC : 0;
}

char *hostname_to_ipv4(char *ip, const char *host)
{
	struct hostent *he;

	memset(ip, 0x00, NET_IPV4_MAX + 1);

	if (! (he = gethostbyname(host)))
		return NULL;

	strncpy(ip,
	        inet_ntoa(*((struct in_addr **)he->h_addr_list)[0]),
	        NET_IPV4_MAX
	);

	return ip;
}
