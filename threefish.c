#include <stdlib.h> /* size_t */
#include <stdint.h>
#include <stdio.h> /* printf */


#define rol64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
#define ror64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))

typedef uint8_t u8;
typedef uint64_t u64;

#include "const.c"

struct pair64 {
	u64 a;
	u64 b;
};

static void mix(u64 x[2], u64 y[2], u64 r)
{
	y[0] = x[0] + x[1];
	y[1] = rol64(x[1], r) ^ y[0];
}

static void mixinv(u64 y[2], u64 x[2], u64 r)
{
	x[1] = ror64(y[0] ^ y[1], r);
	x[0] = y[0] - x[1];
}

#define WORDS 4
#define ROUNDS 72
#define rot rot_4
#define perm perm_4
static int encrypt_4(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS])
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

	struct pair64 y;
	u64 v[ROUNDS];
	u64 f[ROUNDS];
	for (int i = 0; i < WORDS; i++) {
		v[i] = plaintext[i];
	}
	for (unsigned int d = 0; d < ROUNDS; d++) {
		if (d % 4 == 0) {
			for (unsigned int i = 0; i < WORDS; i++) {
				v[i] += subkeys[d / 4][i];
			}
		}
		// mix pairs of words
		for (unsigned int i = 0; i < WORDS; i += 2) {
			mix(&v[i], &f[i], rot[d % 8][i / 2]);
		}
		// permute
		for (unsigned int i = 0; i < WORDS; i++) {
			v[i] = f[perm[i]];
		}
	}

	for (int i = 0; i < WORDS; i++) {
		ciphertext[i] = v[i] + subkeys[ROUNDS/4][i];
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
	case 32: return encrypt_4((u64*)key, (u64*)tweak, (u64*)plaintext, (u64*)ciphertext);
	}
	return 0;
}

int main() {
	u8 key[40] = "passwordpasswordpasswordpasswordandstuff";
	u8 plaintext[32] = "plaintxtplaintxtplaintxtplaintxt";
	u8 tweak[16] = "6teen characters";
	u8 ciphertext[32] = {0};

	encrypt(32, key, tweak, plaintext, ciphertext);

	for (int i = 0; i < 32; i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	//decrypt(32, key, tweak, ciphertext, plaintext);

	return 0;
}
