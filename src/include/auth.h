#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>

// Size of the full authentication struct
#define AUTH_SIZE 48
// Size of the authentication challenge
#define AUTH_SIZE_CHALLENGE AES_SIZE_BLOCK


// The snc authentication information
struct AuthInfo {
	uint8_t eiv[AES_SIZE_BLOCK];
	uint8_t div[AES_SIZE_BLOCK];
	uint8_t challenge[AUTH_SIZE_CHALLENGE];
};
#endif