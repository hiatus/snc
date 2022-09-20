#ifndef INIT_H
#define INIT_H

#include "net.h"
#include "auth.h"

#include <stddef.h>
#include <stdint.h>


int init_key(uint8_t *key, const char *str, size_t len);
int init_key_file(uint8_t *key, const char *path);

int init_argv(char **argv, char *cmd, const char *delim);

void init_auth_info(struct AuthInfo *ai);

void init_packet(struct SNCPacket *pkt, size_t len_payload);
#endif