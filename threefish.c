#include <stdlib.h> /* size_t */
#include <stdint.h>
#include <stdio.h> /* fwrite, printf */


typedef uint8_t u8;
typedef uint64_t u64;

//#define rol64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
//#define ror64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))

static inline u64 rol64(u64 x, u8 r)
{
	return (x << (r & 63)) | (x >> (64 - (r & 63)));
}

static inline u64 ror64(u64 x, u8 r)
{
	return (x >> (r & 63)) | (x << (64 - (r & 63)));
}

#include "const.c"

/* x and y may alias */
static inline void mix(u64 x[2], u64 y[2], u8 r)
{
	u64 y0 = x[0] + x[1];
	y[1] = rol64(x[1], r) ^ y0;
	y[0] = y0;
}

static inline void mixinv(u64 y[2], u64 x[2], u8 r)
{
	u64 x1 = ror64(y[0] ^ y[1], r);
	x[0] = y[0] - x1;
	x[1] = x1;
}

#define WORDS 4
#define ROUNDS 72
#define rot rot_4
#define perm perm_4
static inline void threefish256_round(u64 v[WORDS], const u8 r[WORDS])
{
	u64 tmp[WORDS];
	// mix pairs of words
	for (unsigned int i = 0; i < WORDS; i += 2) {
		mix(&v[i], &tmp[i], r[i / 2]);
	}
	// permute
	for (unsigned int i = 0; i < WORDS; i++) {
		v[i] = tmp[perm[i]];
	}
}
static inline void threefish256_roundinv(u64 v[WORDS], u64 f[WORDS], const u8 r[WORDS/2])
{
	// permute
	for (unsigned int i = 0; i < WORDS; i++) {
		f[i] = v[perminv_4[i]];
	}
	// mix pairs of words
	for (unsigned int i = 0; i < WORDS; i += 2) {
		mixinv(&f[i], &f[i], r[i / 2]);
	}
}

static int threefish256_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS])
{
	u64 subkeys[ROUNDS/4 + 1][WORDS];
	u64 t[3] = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

	key[WORDS] = C240;
	for (int i = 0; i < WORDS; i++) {
		key[WORDS] ^= key[i];
	}

	// expand the key
	for (int s = 0; s <= ROUNDS / 4; s++) {
		for (int i = 0; i < WORDS; i++) {
			subkeys[s][i] = key[(s + i) % (WORDS + 1)];
		}
		subkeys[s][WORDS - 3] += t[s % 3];
		subkeys[s][WORDS - 2] += t[(s + 1) % 3];
		subkeys[s][WORDS - 1] += s;
	}

	u64 v[WORDS];
	for (int i = 0; i < WORDS; i++) {
		v[i] = plaintext[i];
	}
	for (unsigned int d = 0; d < ROUNDS; d += 8) {
		for (unsigned int i = 0; i < WORDS; i++) {
			v[i] += subkeys[d / 4][i];
		}
		threefish256_round(v, rot[(d + 0) % 8]);
		threefish256_round(v, rot[(d + 1) % 8]);
		threefish256_round(v, rot[(d + 2) % 8]);
		threefish256_round(v, rot[(d + 3) % 8]);

		for (unsigned int i = 0; i < WORDS; i++) {
			v[i] += subkeys[d / 4 + 1][i];
		}
		threefish256_round(v, rot[(d + 4) % 8]);
		threefish256_round(v, rot[(d + 5) % 8]);
		threefish256_round(v, rot[(d + 6) % 8]);
		threefish256_round(v, rot[(d + 7) % 8]);
	}

	for (int i = 0; i < WORDS; i++) {
		ciphertext[i] = v[i] + subkeys[ROUNDS/4][i];
	}

	return 0;
}

static int threefish256_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS])
{
	u64 subkeys[ROUNDS/4 + 1][WORDS];
	u64 t[3] = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

	key[WORDS] = C240;
	for (int i = 0; i < WORDS; i++) {
		key[WORDS] ^= key[i];
	}

	// expand the key
	for (int s = 0; s <= ROUNDS / 4; s++) {
		for (int i = 0; i < WORDS; i++) {
			subkeys[s][i] = key[(s + i) % (WORDS + 1)];
		}
		subkeys[s][WORDS - 3] += t[s % 3];
		subkeys[s][WORDS - 2] += t[(s + 1) % 3];
		subkeys[s][WORDS - 1] += s;
	}

	u64 v[WORDS];
	u64 f[WORDS];
	for (int i = 0; i < WORDS; i++) {
		v[i] = ciphertext[i] - subkeys[ROUNDS / 4][i];
	}

	for (unsigned int d = ROUNDS; d > 0;) {
		d -= 4;
		threefish256_roundinv(v, f, rot[(d + 3) % 8]);
		threefish256_roundinv(f, v, rot[(d + 2) % 8]);
		threefish256_roundinv(v, f, rot[(d + 1) % 8]);
		threefish256_roundinv(f, v, rot[(d + 0) % 8]);

		for (unsigned int i = 0; i < WORDS; i++) {
			v[i] -= subkeys[d / 4][i];
		}
	}

	for (int i = 0; i < WORDS; i++) {
		plaintext[i] = v[i];
	}

	return 0;
}
/* Encrypt a block of plainetxt with the threefish cipher.
 * block_size specifies the size of both the plainetxt and the key, and 
 * must be 32, 64, or 128.
 */
static int encrypt(size_t block_size, u8 key[], u8 tweak[16], u8 plaintext[], u8 ciphertext[])
{
	switch (block_size) {
	case 32: return threefish256_encrypt((u64*)key, (u64*)tweak, (u64*)plaintext, (u64*)ciphertext);
	}
	return 0;
}
static int decrypt(size_t block_size, u8 key[], u8 tweak[16], u8 ciphertext[], u8 plaintext[])
{
	switch (block_size) {
	case 32: return threefish256_decrypt((u64*)key, (u64*)tweak, (u64*)ciphertext, (u64*)plaintext);
	}
	return 0;
}

int main() {
	u8 key[40] = "passwordpasswordpasswordpasswordandstuff";
	u8 plaintext[32] = "plaintxtplaintxtplaintxtplaintxt";
	u8 tweak[16] = {0};
	u8 ciphertext[32] = {0};

	encrypt(32, key, tweak, plaintext, ciphertext);

	for (int i = 0; i < 32; i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	decrypt(32, key, tweak, ciphertext, plaintext);

	fwrite(plaintext, 32, 1, stdout);
	printf("\n");

	return 0;
}
