
#include <stdint.h>

#define u64 uint64_t

#define WORDS 4
extern int threefish256_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS]);
extern int threefish256_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS]);
#undef WORDS
#define WORDS 8
extern int threefish512_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS]);
extern int threefish512_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS]);
#undef WORDS
#define WORDS 16
extern int threefish1024_encrypt(u64 key[WORDS+1], u64 tweak[2], u64 plaintext[WORDS], u64 ciphertext[WORDS]);
extern int threefish1024_decrypt(u64 key[WORDS+1], u64 tweak[2], u64 ciphertext[WORDS], u64 plaintext[WORDS]);
#undef WORDS

#undef u64
