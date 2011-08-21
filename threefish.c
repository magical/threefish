#include <stdlib.h> /* size_t */
#include <stdint.h>
#include <stdio.h> /* fwrite, printf */
#include <string.h> /* memcmp */

#define FORCEINLINE __attribute__((__always_inline__))

typedef uint8_t u8;
typedef uint64_t u64;

#include "const.c"

static inline u64 rol64(u64 x, u8 r)
{
	return (x << (r & 63)) | (x >> (64 - (r & 63)));
}

static inline u64 ror64(u64 x, u8 r)
{
	return (x >> (r & 63)) | (x << (64 - (r & 63)));
}

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

static FORCEINLINE void threefish_round(const unsigned nwords, u64 v[nwords], const u8 r[nwords/2], const u8 perm[nwords])
{
	u64 tmp[nwords];
	// mix pairs of words
	for (unsigned int i = 0; i < nwords; i += 2) {
		mix(&v[i], &tmp[i], r[i / 2]);
	}
	// permute
	for (unsigned int i = 0; i < nwords; i++) {
		v[i] = tmp[perm[i]];
	}
}
static FORCEINLINE void threefish_roundinv(const unsigned nwords, u64 v[nwords], const u8 r[nwords/2], const u8 perm[nwords])
{
	u64 tmp[nwords];
	// permute
	for (unsigned int i = 0; i < nwords; i++) {
		tmp[perm[i]] = v[i];
	}
	// mix pairs of words
	for (unsigned int i = 0; i < nwords; i += 2) {
		mixinv(&tmp[i], &v[i], r[i / 2]);
	}
}

static FORCEINLINE void
threefish_encrypt_generic(const unsigned nwords, const unsigned nrounds,
                          const u8 rot[8][nwords/2], const u8 perm[nwords/2],
                          u64 key[nwords+1], u64 tweak[2],
                          u64 plaintext[nwords], u64 ciphertext[nwords])
{
	u64 subkeys[nrounds/4 + 1][nwords];
	u64 t[3] = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

	key[nwords] = C240;
	for (int i = 0; i < nwords; i++) {
		key[nwords] ^= key[i];
	}

	// expand the key
	for (int s = 0; s <= nrounds / 4; s++) {
		for (int i = 0; i < nwords; i++) {
			subkeys[s][i] = key[(s + i) % (nwords + 1)];
		}
		subkeys[s][nwords - 3] += t[s % 3];
		subkeys[s][nwords - 2] += t[(s + 1) % 3];
		subkeys[s][nwords - 1] += s;
	}

	u64 v[nwords];
	for (int i = 0; i < nwords; i++) {
		v[i] = plaintext[i];
	}
	for (unsigned int d = 0; d < nrounds; d += 8) {
		for (unsigned int i = 0; i < nwords; i++) {
			v[i] += subkeys[d / 4][i];
		}
		threefish_round(nwords, v, rot[(d + 0) % 8], perm);
		threefish_round(nwords, v, rot[(d + 1) % 8], perm);
		threefish_round(nwords, v, rot[(d + 2) % 8], perm);
		threefish_round(nwords, v, rot[(d + 3) % 8], perm);

		for (unsigned int i = 0; i < nwords; i++) {
			v[i] += subkeys[d / 4 + 1][i];
		}
		threefish_round(nwords, v, rot[(d + 4) % 8], perm);
		threefish_round(nwords, v, rot[(d + 5) % 8], perm);
		threefish_round(nwords, v, rot[(d + 6) % 8], perm);
		threefish_round(nwords, v, rot[(d + 7) % 8], perm);
	}

	for (int i = 0; i < nwords; i++) {
		ciphertext[i] = v[i] + subkeys[nrounds/4][i];
	}
}

static FORCEINLINE void
threefish_decrypt_generic(const unsigned nwords, const unsigned nrounds,
                          const u8 rot[8][nwords/2], const u8 perm[nwords],
                          u64 key[nwords+1], u64 tweak[2],
                          u64 ciphertext[nwords], u64 plaintext[nwords])
{
	u64 subkeys[nrounds/4 + 1][nwords];
	u64 t[3] = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

	key[nwords] = C240;
	for (int i = 0; i < nwords; i++) {
		key[nwords] ^= key[i];
	}

	// expand the key
	for (int s = 0; s <= nrounds / 4; s++) {
		for (int i = 0; i < nwords; i++) {
			subkeys[s][i] = key[(s + i) % (nwords + 1)];
		}
		subkeys[s][nwords - 3] += t[s % 3];
		subkeys[s][nwords - 2] += t[(s + 1) % 3];
		subkeys[s][nwords - 1] += s;
	}

	u64 v[nwords];
	for (int i = 0; i < nwords; i++) {
		v[i] = ciphertext[i] - subkeys[nrounds / 4][i];
	}

	for (unsigned int d = nrounds; d > 0;) {
		d -= 4;
		threefish_roundinv(nwords, v, rot[(d + 3) % 8], perm);
		threefish_roundinv(nwords, v, rot[(d + 2) % 8], perm);
		threefish_roundinv(nwords, v, rot[(d + 1) % 8], perm);
		threefish_roundinv(nwords, v, rot[(d + 0) % 8], perm);

		for (unsigned int i = 0; i < nwords; i++) {
			v[i] -= subkeys[d / 4][i];
		}
	}

	for (int i = 0; i < nwords; i++) {
		plaintext[i] = v[i];
	}
}


#define WORDS 4
#define ROUNDS 72
static int threefish256_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS])
{
	threefish_encrypt_generic(WORDS, ROUNDS, rot_4, perm_4, key, tweak, plaintext, ciphertext);
	return 0;
}

static int threefish256_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS])
{
	threefish_decrypt_generic(WORDS, ROUNDS, rot_4, perm_4, key, tweak, ciphertext, plaintext);
	return 0;
}

#undef WORDS
#undef ROUNDS
#define WORDS 8
#define ROUNDS 72
static int threefish512_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS])
{
	threefish_encrypt_generic(WORDS, ROUNDS, rot_8, perm_8, key, tweak, plaintext, ciphertext);
	return 0;
}

static int threefish512_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS])
{
	threefish_decrypt_generic(WORDS, ROUNDS, rot_8, perm_8, key, tweak, ciphertext, plaintext);
	return 0;
}

#undef WORDS
#undef ROUNDS
#define WORDS 16
#define ROUNDS 80
static int threefish1024_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS])
{
	threefish_encrypt_generic(WORDS, ROUNDS, rot_16, perm_16, key, tweak, plaintext, ciphertext);
	return 0;
}

static int threefish1024_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS])
{
	threefish_decrypt_generic(WORDS, ROUNDS, rot_16, perm_16, key, tweak, ciphertext, plaintext);
	return 0;
}


/* Encrypt a block of plainetxt with the threefish cipher.
 * block_size specifies the size of both the plainetxt and the key, and 
 * must be 32, 64, or 128.
 */
int encrypt(size_t block_size, u8 key[], u8 tweak[16], u8 plaintext[], u8 ciphertext[])
{
	switch (block_size) {
	case 32: return threefish256_encrypt((u64*)key, (u64*)tweak, (u64*)plaintext, (u64*)ciphertext);
	case 64: return threefish512_encrypt((u64*)key, (u64*)tweak, (u64*)plaintext, (u64*)ciphertext);
	case 128: return threefish1024_encrypt((u64*)key, (u64*)tweak, (u64*)plaintext, (u64*)ciphertext);
	}
	return 0;
}

int decrypt(size_t block_size, u8 key[], u8 tweak[16], u8 ciphertext[], u8 plaintext[])
{
	switch (block_size) {
	case 32: return threefish256_decrypt((u64*)key, (u64*)tweak, (u64*)ciphertext, (u64*)plaintext);
	case 64: return threefish512_decrypt((u64*)key, (u64*)tweak, (u64*)ciphertext, (u64*)plaintext);
	case 128: return threefish1024_decrypt((u64*)key, (u64*)tweak, (u64*)ciphertext, (u64*)plaintext);
	}
	return 0;
}

static void thing(int len, u8 key[], u8 tweak[], u8 plaintext[])
{
	u8 ciphertext[len];
	encrypt(len, key, tweak, plaintext, ciphertext);

	for (int i = 0; i < len; i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	u8 plaintext2[len];
	decrypt(len, key, tweak, ciphertext, plaintext2);
	printf("%d\n", memcmp(plaintext, plaintext2, len) == 0);

	//fwrite(plaintext2, len, 1, stdout);
	//printf("\n");
}

int main() {
	u8 key[132] = "passwordpasswordpasswordpassword";
	u8 plaintext[128] = "plaintxtplaintxtplaintxtplaintxt";
	u8 tweak[16] = {0};

	thing(32, key, tweak, plaintext);
	thing(64, key, tweak, plaintext);
	thing(128, key, tweak, plaintext);

	return 0;
}
