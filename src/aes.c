#include "aes.h"
#include <string.h>

// Find the product of {02} and x mod 0x1b
#define XTIME(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

// Multiply two numbers in the Galois field 2 ^ 8
#define MULTIPLY(x, y) (\
	((y & 1) * x) ^ \
	((y >> 1 & 1) * XTIME(x)) ^ \
	((y >> 2 & 1) * XTIME(XTIME(x))) ^ \
	((y >> 3 & 1) * XTIME(XTIME(XTIME(x)))) ^ \
	((y >> 4 & 1) * XTIME(XTIME(XTIME(XTIME(x))))) \
)

typedef uint8_t state_t[4][4];


static uint8_t auxv[4];
static uint8_t aux1, aux2, aux3, aux4;

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rev_sbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constant array for the Rijndael key schedule
static const uint8_t rcon[11] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline void _expand_key(uint8_t *round_key, const uint8_t *key)
{
	// The first round is the key itself
	for (uint_fast8_t i = 0; i < AES_KEY_32BW; ++i) {
		aux1 = i << 2; // * AES_COL_SIZE

		round_key[aux1 + 0] = key[aux1 + 0];
		round_key[aux1 + 1] = key[aux1 + 1];
		round_key[aux1 + 2] = key[aux1 + 2];
		round_key[aux1 + 3] = key[aux1 + 3];
	}

	// All subsequent rounds are derived from the previous round key
	for (uint_fast8_t i = AES_KEY_32BW; i < AES_COL_SIZE * (AES_NUM_RNDS + 1); ++i) {
		aux1 = (i - 1) << 2; // * AES_COL_SIZE

		auxv[0] = round_key[aux1++];
		auxv[1] = round_key[aux1++];
		auxv[2] = round_key[aux1++];
		auxv[3] = round_key[aux1];

		if (i % AES_KEY_32BW == 0) {
			// Shift row
			aux1 = auxv[0];

			auxv[0] = auxv[1];
			auxv[1] = auxv[2];
			auxv[2] = auxv[3];
			auxv[3] = aux1;

			// Substitute bytes
			auxv[1] = sbox[auxv[1]];
			auxv[2] = sbox[auxv[2]];
			auxv[3] = sbox[auxv[3]];
			auxv[0] = sbox[auxv[0]] ^ rcon[i / AES_KEY_32BW];
		}

#if defined(AES256)
		else
		if (i % AES_KEY_32BW == AES_COL_SIZE) {
			// Substitute bytes
			auxv[0] = sbox[auxv[0]];
			auxv[1] = sbox[auxv[1]];
			auxv[2] = sbox[auxv[2]];
			auxv[3] = sbox[auxv[3]];
		}
#endif

		aux1 = i << 2; // * AES_COL_SIZE
		aux2 = (i - AES_KEY_32BW) << 2; // * AES_COL_SIZE

		round_key[aux1++] = round_key[aux2++] ^ auxv[0];
		round_key[aux1++] = round_key[aux2++] ^ auxv[1];
		round_key[aux1++] = round_key[aux2++] ^ auxv[2];
		round_key[aux1]   = round_key[aux2]   ^ auxv[3];
	}
}

static inline void _add_round_key
(uint8_t round, state_t *state , const uint8_t *round_key)
{
	aux2 = round << 4; // * AES_COL_SIZE * 4;

	(*state)[0][0] ^= round_key[aux2];
	(*state)[0][1] ^= round_key[aux2 + 1];
	(*state)[0][2] ^= round_key[aux2 + 2];
	(*state)[0][3] ^= round_key[aux2 + 3];

	aux1 = AES_COL_SIZE;

	(*state)[1][0] ^= round_key[aux1 + aux2];
	(*state)[1][1] ^= round_key[aux1 + aux2 + 1];
	(*state)[1][2] ^= round_key[aux1 + aux2 + 2];
	(*state)[1][3] ^= round_key[aux1 + aux2 + 3];

	aux1 += AES_COL_SIZE;

	(*state)[2][0] ^= round_key[aux1 + aux2];
	(*state)[2][1] ^= round_key[aux1 + aux2 + 1];
	(*state)[2][2] ^= round_key[aux1 + aux2 + 2];
	(*state)[2][3] ^= round_key[aux1 + aux2 + 3];

	aux1 += AES_COL_SIZE;

	(*state)[3][0] ^= round_key[aux1 + aux2];
	(*state)[3][1] ^= round_key[aux1 + aux2 + 1];
	(*state)[3][2] ^= round_key[aux1 + aux2 + 2];
	(*state)[3][3] ^= round_key[aux1 + aux2 + 3];
}

static inline void _sub_bytes(state_t *state)
{
	(*state)[0][0] = sbox[(*state)[0][0]];
	(*state)[1][0] = sbox[(*state)[1][0]];
	(*state)[2][0] = sbox[(*state)[2][0]];
	(*state)[3][0] = sbox[(*state)[3][0]];

	(*state)[0][1] = sbox[(*state)[0][1]];
	(*state)[1][1] = sbox[(*state)[1][1]];
	(*state)[2][1] = sbox[(*state)[2][1]];
	(*state)[3][1] = sbox[(*state)[3][1]];

	(*state)[0][2] = sbox[(*state)[0][2]];
	(*state)[1][2] = sbox[(*state)[1][2]];
	(*state)[2][2] = sbox[(*state)[2][2]];
	(*state)[3][2] = sbox[(*state)[3][2]];

	(*state)[0][3] = sbox[(*state)[0][3]];
	(*state)[1][3] = sbox[(*state)[1][3]];
	(*state)[2][3] = sbox[(*state)[2][3]];
	(*state)[3][3] = sbox[(*state)[3][3]];
}

static inline void _rev_sub_bytes(state_t *state)
{
	(*state)[0][0] = rev_sbox[(*state)[0][0]];
	(*state)[1][0] = rev_sbox[(*state)[1][0]];
	(*state)[2][0] = rev_sbox[(*state)[2][0]];
	(*state)[3][0] = rev_sbox[(*state)[3][0]];

	(*state)[0][1] = rev_sbox[(*state)[0][1]];
	(*state)[1][1] = rev_sbox[(*state)[1][1]];
	(*state)[2][1] = rev_sbox[(*state)[2][1]];
	(*state)[3][1] = rev_sbox[(*state)[3][1]];

	(*state)[0][2] = rev_sbox[(*state)[0][2]];
	(*state)[1][2] = rev_sbox[(*state)[1][2]];
	(*state)[2][2] = rev_sbox[(*state)[2][2]];
	(*state)[3][2] = rev_sbox[(*state)[3][2]];

	(*state)[0][3] = rev_sbox[(*state)[0][3]];
	(*state)[1][3] = rev_sbox[(*state)[1][3]];
	(*state)[2][3] = rev_sbox[(*state)[2][3]];
	(*state)[3][3] = rev_sbox[(*state)[3][3]];
}

static inline void _shift_rows(state_t *state)
{

	// Shift the second row 1 column to the left
	aux1 = (*state)[0][1];

	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = aux1;

	// Shift the third row 2 columns to the left
	aux1 = (*state)[0][2];

	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = aux1;

	aux1 = (*state)[1][2];

	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = aux1;

	// Shift the fourth row 3 columns to the left
	aux1 = (*state)[0][3];

	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = aux1;
}

static inline void _rev_shift_rows(state_t *state)
{
	// Shift the second row 1 column to the right
	aux1 = (*state)[3][1];

	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = aux1;

	// Shift the third row 2 columns to the right
	aux1 = (*state)[0][2];

	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = aux1;

	aux1 = (*state)[1][2];

	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = aux1;

	// Rotate the fourth row 3 columns to the right
	aux1 = (*state)[0][3];

	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = aux1;
}

static inline void _mix_columns(state_t *state)
{
	aux1 = (*state)[0][0];
	aux2 = (*state)[0][0] ^ (*state)[0][1] ^
	       (*state)[0][2] ^ (*state)[0][3];

	(*state)[0][0] ^= XTIME(((*state)[0][0] ^ (*state)[0][1])) ^ aux2;
	(*state)[0][1] ^= XTIME(((*state)[0][1] ^ (*state)[0][2])) ^ aux2;
	(*state)[0][2] ^= XTIME(((*state)[0][2] ^ (*state)[0][3])) ^ aux2;
	(*state)[0][3] ^= XTIME(((*state)[0][3] ^ aux1))           ^ aux2;

	aux1 = (*state)[1][0];
	aux2 = (*state)[1][0] ^ (*state)[1][1] ^ (*state)[1][2] ^ (*state)[1][3];

	(*state)[1][0] ^= XTIME(((*state)[1][0] ^ (*state)[1][1])) ^ aux2;
	(*state)[1][1] ^= XTIME(((*state)[1][1] ^ (*state)[1][2])) ^ aux2;
	(*state)[1][2] ^= XTIME(((*state)[1][2] ^ (*state)[1][3])) ^ aux2;
	(*state)[1][3] ^= XTIME(((*state)[1][3] ^ aux1))           ^ aux2;

	aux1 = (*state)[2][0];
	aux2 = (*state)[2][0] ^ (*state)[2][1] ^ (*state)[2][2] ^ (*state)[2][3];

	(*state)[2][0] ^= XTIME(((*state)[2][0] ^ (*state)[2][1])) ^ aux2;
	(*state)[2][1] ^= XTIME(((*state)[2][1] ^ (*state)[2][2])) ^ aux2;
	(*state)[2][2] ^= XTIME(((*state)[2][2] ^ (*state)[2][3])) ^ aux2;
	(*state)[2][3] ^= XTIME(((*state)[2][3] ^ aux1))           ^ aux2;

	aux1 = (*state)[3][0];
	aux2 = (*state)[3][0] ^ (*state)[3][1] ^ (*state)[3][2] ^ (*state)[3][3];

	(*state)[3][0] ^= XTIME(((*state)[3][0] ^ (*state)[3][1])) ^ aux2;
	(*state)[3][1] ^= XTIME(((*state)[3][1] ^ (*state)[3][2])) ^ aux2;
	(*state)[3][2] ^= XTIME(((*state)[3][2] ^ (*state)[3][3])) ^ aux2;
	(*state)[3][3] ^= XTIME(((*state)[3][3] ^ aux1))           ^ aux2;
}

static inline void _rev_mix_columns(state_t *state)
{
	aux1 = (*state)[0][0]; aux2 = (*state)[0][1];
	aux3 = (*state)[0][2]; aux4 = (*state)[0][3];

	(*state)[0][0] = MULTIPLY(aux1, 0x0e) ^ MULTIPLY(aux2, 0x0b) ^
	                 MULTIPLY(aux3, 0x0d) ^ MULTIPLY(aux4, 0x09);
	(*state)[0][1] = MULTIPLY(aux1, 0x09) ^ MULTIPLY(aux2, 0x0e) ^
	                 MULTIPLY(aux3, 0x0b) ^ MULTIPLY(aux4, 0x0d);
	(*state)[0][2] = MULTIPLY(aux1, 0x0d) ^ MULTIPLY(aux2, 0x09) ^
	                 MULTIPLY(aux3, 0x0e) ^ MULTIPLY(aux4, 0x0b);
	(*state)[0][3] = MULTIPLY(aux1, 0x0b) ^ MULTIPLY(aux2, 0x0d) ^
	                 MULTIPLY(aux3, 0x09) ^ MULTIPLY(aux4, 0x0e);

	aux1 = (*state)[1][0]; aux2 = (*state)[1][1];
	aux3 = (*state)[1][2]; aux4 = (*state)[1][3];

	(*state)[1][0] = MULTIPLY(aux1, 0x0e) ^ MULTIPLY(aux2, 0x0b) ^
	                 MULTIPLY(aux3, 0x0d) ^ MULTIPLY(aux4, 0x09);
	(*state)[1][1] = MULTIPLY(aux1, 0x09) ^ MULTIPLY(aux2, 0x0e) ^
	                 MULTIPLY(aux3, 0x0b) ^ MULTIPLY(aux4, 0x0d);
	(*state)[1][2] = MULTIPLY(aux1, 0x0d) ^ MULTIPLY(aux2, 0x09) ^
	                 MULTIPLY(aux3, 0x0e) ^ MULTIPLY(aux4, 0x0b);
	(*state)[1][3] = MULTIPLY(aux1, 0x0b) ^ MULTIPLY(aux2, 0x0d) ^
	                 MULTIPLY(aux3, 0x09) ^ MULTIPLY(aux4, 0x0e);

	aux1 = (*state)[2][0]; aux2 = (*state)[2][1];
	aux3 = (*state)[2][2]; aux4 = (*state)[2][3];

	(*state)[2][0] = MULTIPLY(aux1, 0x0e) ^ MULTIPLY(aux2, 0x0b) ^
	                 MULTIPLY(aux3, 0x0d) ^ MULTIPLY(aux4, 0x09);
	(*state)[2][1] = MULTIPLY(aux1, 0x09) ^ MULTIPLY(aux2, 0x0e) ^
	                 MULTIPLY(aux3, 0x0b) ^ MULTIPLY(aux4, 0x0d);
	(*state)[2][2] = MULTIPLY(aux1, 0x0d) ^ MULTIPLY(aux2, 0x09) ^
	                 MULTIPLY(aux3, 0x0e) ^ MULTIPLY(aux4, 0x0b);
	(*state)[2][3] = MULTIPLY(aux1, 0x0b) ^ MULTIPLY(aux2, 0x0d) ^
	                 MULTIPLY(aux3, 0x09) ^ MULTIPLY(aux4, 0x0e);

	aux1 = (*state)[3][0]; aux2 = (*state)[3][1];
	aux3 = (*state)[3][2]; aux4 = (*state)[3][3];

	(*state)[3][0] = MULTIPLY(aux1, 0x0e) ^ MULTIPLY(aux2, 0x0b) ^
	                 MULTIPLY(aux3, 0x0d) ^ MULTIPLY(aux4, 0x09);
	(*state)[3][1] = MULTIPLY(aux1, 0x09) ^ MULTIPLY(aux2, 0x0e) ^
	                 MULTIPLY(aux3, 0x0b) ^ MULTIPLY(aux4, 0x0d);
	(*state)[3][2] = MULTIPLY(aux1, 0x0d) ^ MULTIPLY(aux2, 0x09) ^
	                 MULTIPLY(aux3, 0x0e) ^ MULTIPLY(aux4, 0x0b);
	(*state)[3][3] = MULTIPLY(aux1, 0x0b) ^ MULTIPLY(aux2, 0x0d) ^
	                 MULTIPLY(aux3, 0x09) ^ MULTIPLY(aux4, 0x0e);
}

#if defined(AES_ECB_MODE)
void aes_ecb_init(struct aes_ctx *ctx, const uint8_t *key)
{
	_expand_key(ctx->round_key, key);
}

void aes_ecb_encrypt(const struct aes_ctx *ctx, void *buffer, size_t len)
{
	for (size_t i = 0; i < len; i += AES_BLK_SIZE) {
		_add_round_key(0, (state_t *)buffer, ctx->round_key);

		for (uint_fast8_t round = 1; round < AES_NUM_RNDS; ++round) {
			_sub_bytes((state_t *)buffer);
			_shift_rows((state_t *)buffer);
			_mix_columns((state_t *)buffer);
			_add_round_key(round, (state_t *)buffer, ctx->round_key);
		}

		_sub_bytes((state_t *)buffer);
		_shift_rows((state_t *)buffer);
		_add_round_key(AES_NUM_RNDS, (state_t *)buffer, ctx->round_key);

		buffer = (uint8_t *)buffer + AES_BLK_SIZE;
	}
}

void aes_ecb_decrypt(const struct aes_ctx *ctx, void *buffer, size_t len)
{
	for (size_t i = 0; i < len; i += AES_BLK_SIZE) {
		_add_round_key(AES_NUM_RNDS, (state_t *)buffer, ctx->round_key);

		for (uint_fast8_t round = AES_NUM_RNDS - 1; round; --round) {
			_rev_shift_rows((state_t *)buffer);
			_rev_sub_bytes((state_t *)buffer);
			_add_round_key(round, (state_t *)buffer, ctx->round_key);
			_rev_mix_columns((state_t *)buffer);
		}

		_rev_shift_rows((state_t *)buffer);
		_rev_sub_bytes((state_t *)buffer);
		_add_round_key(0, (state_t *)buffer, ctx->round_key);

		buffer = (uint8_t *)buffer + AES_BLK_SIZE;
	}
}
#endif

#if defined(AES_CBC_MODE)
void aes_cbc_init(struct aes_ctx *ctx, const uint8_t *key, const uint8_t *iv)
{
	_expand_key(ctx->round_key, key);
	memcpy(ctx->iv, iv, AES_BLK_SIZE);
}

void aes_cbc_encrypt(struct aes_ctx *ctx, void *buffer, size_t len)
{
	uint8_t *iv = ctx->iv;

	for (size_t i = 0; i < len; i += AES_BLK_SIZE) {
		for (uint_fast8_t j = 0; j < AES_BLK_SIZE; ++j)
			*((uint8_t *)buffer + j) ^= iv[j];

		_add_round_key(0, (state_t *)buffer, ctx->round_key);

		for (uint_fast8_t round = 1; round < AES_NUM_RNDS; ++round) {
			_sub_bytes((state_t *)buffer);
			_shift_rows((state_t *)buffer);
			_mix_columns((state_t *)buffer);
			_add_round_key(round, (state_t *)buffer, ctx->round_key);
		}

		_sub_bytes((state_t *)buffer);
		_shift_rows((state_t *)buffer);
		_add_round_key(AES_NUM_RNDS, (state_t *)buffer, ctx->round_key);

		iv = (uint8_t *)buffer;
		buffer = (uint8_t *)buffer + AES_BLK_SIZE;
	}

	memcpy(ctx->iv, iv, AES_BLK_SIZE);
}

void aes_cbc_decrypt(struct aes_ctx *ctx, void *buffer, size_t len)
{
	uint8_t next_iv[AES_BLK_SIZE];

	for (size_t i = 0; i < len; i += AES_BLK_SIZE) {
		memcpy(next_iv, buffer, AES_BLK_SIZE);

		_add_round_key(AES_NUM_RNDS, (state_t *)buffer, ctx->round_key);

		for (uint_fast8_t round = AES_NUM_RNDS - 1; round; --round) {
			_rev_shift_rows((state_t *)buffer);
			_rev_sub_bytes((state_t *)buffer);
			_add_round_key(round, (state_t *)buffer, ctx->round_key);
			_rev_mix_columns((state_t *)buffer);
		}

		_rev_shift_rows((state_t *)buffer);
		_rev_sub_bytes((state_t *)buffer);
		_add_round_key(0, (state_t *)buffer, ctx->round_key);

		for (uint_fast8_t j = 0; j < AES_BLK_SIZE; ++j)
			*((uint8_t *)buffer + j) ^= ctx->iv[j];

		memcpy(ctx->iv, next_iv, AES_BLK_SIZE);
		buffer = (uint8_t *)buffer + AES_BLK_SIZE;
	}
}
#endif
