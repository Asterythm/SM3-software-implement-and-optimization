#include "sm3.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// SM3 constants (Tj for j=0 to 63)
static const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// Rotate left macro
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// FF and GG functions
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

// P0 and P1 functions
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

void sm3_message_expansion(uint32_t *W, const uint8_t *msg, uint64_t len) {
    for (int i = 0; i < 16; i++) {
        W[i] = (msg[4*i] << 24) | (msg[4*i+1] << 16) | (msg[4*i+2] << 8) | msg[4*i+3];
    }
    for (int i = 16; i < 68; i++) {
        uint32_t w_n = W[i-16] ^ W[i-9] ^ ROTL32(W[i-3], 15);
        W[i] = P1(w_n ^ ROTL32(w_n, 7) ^ W[i-13]);
    }
    for (int i = 0; i < 64; i++) {
        W[i+68] = W[i] ^ W[i+4];
    }
}

void sm3_compress(uint32_t *state, const uint32_t *W) {
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];
    
    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL32((ROTL32(A, 12) + E + ROTL32(T[j], j % 32)), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = (j < 16 ? FF0(A, B, C) : FF1(A, B, C)) + D + SS2 + W[j+68];
        uint32_t TT2 = (j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_hash(const uint8_t *msg, uint64_t len, uint8_t *digest) {
    uint32_t state[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                         0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};
    sm3_hash_with_state(msg, len, digest, state);
}

void sm3_hash_with_state(const uint8_t *msg, uint64_t len, uint8_t *digest, uint32_t *initial_state) {
    uint32_t state[8];
    memcpy(state, initial_state, 8 * sizeof(uint32_t));
    uint8_t buffer[SM3_BLOCK_SIZE];
    uint64_t total_len = len * 8;
    
    // Process complete blocks
    uint32_t W[132];
    while (len >= SM3_BLOCK_SIZE) {
        sm3_message_expansion(W, msg, SM3_BLOCK_SIZE);
        sm3_compress(state, W);
        msg += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }
    
    // Padding
    memcpy(buffer, msg, len);
    buffer[len++] = 0x80;
    if (len > 56) {
        memset(buffer + len, 0, SM3_BLOCK_SIZE - len);
        sm3_message_expansion(W, buffer, SM3_BLOCK_SIZE);
        sm3_compress(state, W);
        len = 0;
    }
    memset(buffer + len, 0, 56 - len);
    for (int i = 0; i < 8; i++) {
        buffer[56 + i] = (total_len >> (56 - 8 * i)) & 0xFF;
    }
    sm3_message_expansion(W, buffer, SM3_BLOCK_SIZE);
    sm3_compress(state, W);
    
    // Output digest
    for (int i = 0; i < 8; i++) {
        digest[4*i] = (state[i] >> 24) & 0xFF;
        digest[4*i+1] = (state[i] >> 16) & 0xFF;
        digest[4*i+2] = (state[i] >> 8) & 0xFF;
        digest[4*i+3] = state[i] & 0xFF;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file> [--with-state]\n", argv[0]);
        return 1;
    }
    
    FILE *input = fopen(argv[1], "rb");
    if (!input) {
        fprintf(stderr, "Cannot open input file\n");
        return 1;
    }
    
    fseek(input, 0, SEEK_END);
    long len = ftell(input);
    fseek(input, 0, SEEK_SET);
    
    uint8_t *msg = malloc(len);
    fread(msg, 1, len, input);
    fclose(input);
    
    uint8_t digest[SM3_DIGEST_LENGTH];
    if (argc > 2 && strcmp(argv[2], "--with-state") == 0) {
        uint32_t state[8];
        if (len < 32) {
            fprintf(stderr, "State file too short\n");
            free(msg);
            return 1;
        }
        for (int i = 0; i < 8; i++) {
            state[i] = (msg[4*i] << 24) | (msg[4*i+1] << 16) | (msg[4*i+2] << 8) | msg[4*i+3];
        }
        sm3_hash_with_state(msg + 32, len - 32, digest, state);
    } else {
        sm3_hash(msg, len, digest);
    }
    
    FILE *output = fopen("output.bin", "wb");
    fwrite(digest, 1, SM3_DIGEST_LENGTH, output);
    fclose(output);
    
    free(msg);
    return 0;
}