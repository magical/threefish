#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "threefish.h"

#define u64 uint64_t
#define u8 uint8_t

#undef WORDS
#define WORDS 8
static int encrypt_cbc_fp(FILE *fp, FILE *outfp, u8 key[WORDS], u64 iv[WORDS])
{
	u64 *wkey = (u64*)key;
	u64 tweak[2] = {0,0};

	u64 plaintext[2][WORDS];
	u64 ciphertext[WORDS];
	int p = 0;
	size_t plen;
	const size_t len = sizeof(plaintext[0]);

	for (int i = 0; i < WORDS; i++) {
		ciphertext[i] = iv[i];
	}

	fwrite(iv, 1, len, outfp);
	plen = fread(plaintext[p], 1, len, fp);
	if (plen != len) {
		if (ferror(fp)) {
			perror("fread");
			return 1;
		} else if (feof(fp)) {
			printf("help\n");
			return 1;
		}
	}
	p = !p;

	clearerr(fp);
	while (1) {
		plen = fread(plaintext[p], 1, len, fp);
		if (plen != len) {
			if (ferror(fp)) {
				perror("fread");
				return 1;
			} else if (feof(fp)) {
				break;
			} else {
				fputs("error\n", stderr);
				return 1;
			}
		}
		p = !p;
		for (int i = 0; i < WORDS; i++) {
			plaintext[p][i] ^= ciphertext[i];
		}
		threefish512_encrypt(wkey, tweak, plaintext[p], ciphertext);
		if (fwrite(ciphertext, 1, len, outfp) != len) {
			perror("fwrite");
			return 1;
		}
	}
	//padding
	if (plen == 0) {
		p = !p;
		threefish512_encrypt(wkey, tweak, plaintext[p], ciphertext);
		if (fwrite(ciphertext, 1, len, outfp) != len) {
			perror("fwrite");
			return 1;
		}
	} else {
		// ciphertext stealing
		u64 ciphertext2[WORDS];

		threefish512_encrypt(wkey, tweak, plaintext[!p], ciphertext);

		memset((u8*)plaintext[p] + plen, 0, len - plen);
		for (int i = 0; i < WORDS; i++) {
			plaintext[p][i] ^= ciphertext[i];
		}
		threefish512_encrypt(wkey, tweak, plaintext[p], ciphertext2);

		fwrite(ciphertext2, 1, len, outfp);
		fwrite(ciphertext, 1, plen, outfp);
		if (ferror(outfp)) {
			return 1;
		}
	}
	return 0;
}

#undef WORDS
#define WORDS 8
static int decrypt_cbc_fp(FILE *fp, FILE *outfp, u8 key[WORDS])
{
	u64 *wkey = (u64*)key;
	u64 tweak[2] = {0,0};

	u64 ciphertext[2][WORDS];
	u64 plaintext[WORDS];
	int p = 0;
	size_t plen;
	const size_t len = sizeof(ciphertext[0]);

	// read IV
	fread(ciphertext[0], 1, len, fp);

	p = !p;
	int flag = 0;
	while (1) {
		plen = fread(ciphertext[p], 1, len, fp);
		if (plen != len) {
			if (ferror(fp)) {
				perror("fread");
				return 1;
			} else if (feof(fp)) {
				//padding
				break;
			} else {
				fputs("error\n", stderr);
				return 1;
			}
		}
		if (flag) {
			fwrite(plaintext, 1, len, outfp);
		}
		threefish512_decrypt(wkey, tweak, ciphertext[p], plaintext);
		for (int i = 0; i < WORDS; i++) {
			plaintext[i] ^= ciphertext[!p][i];
		}
		p = !p;
		flag = 1;
	}
	if (plen == 0) {
		// blah
	} else {
		u64 plaintext2[WORDS];

		threefish512_decrypt(wkey, tweak, ciphertext[!p], plaintext);
		memset((u8*)ciphertext[p] + plen, 0, len - plen);
		for (int i = 0; i < WORDS; i++) {
			plaintext[i] ^= ciphertext[p][i];
		}

		memcpy((u8*)ciphertext[p] + plen, (u8*)plaintext + plen, len - plen);
		threefish512_decrypt(wkey, tweak, ciphertext[p], plaintext2);

		fwrite(plaintext2, 1, len, outfp);
		fwrite(plaintext, 1, plen, outfp);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	u8 key[64] = "password";
	u64 iv[8] = {};
	if (1 < argc && strcmp(argv[1], "-d") == 0) {
		return !!decrypt_cbc_fp(stdin, stdout, key);
	} else {
		return !!encrypt_cbc_fp(stdin, stdout, key, iv);
	}
	return 0;
}
