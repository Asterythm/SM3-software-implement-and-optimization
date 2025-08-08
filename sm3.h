#ifndef SM3_H
#define SM3_H
#include <stdint.h>
#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE 64
void sm3_hash(const uint8_t *msg, uint64_t len, uint8_t *digest);
void sm3_message_expansion(uint32_t *W, const uint8_t *msg, uint64_t len);
void sm3_compress(uint32_t *state, const uint32_t *W);
#endif