#include <stdio.h>
#include <string.h>
#include "sm3.h"

void print_digest(uint8_t *digest) {
    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main() {
    uint8_t msg[] = "abc";
    uint8_t digest[SM3_DIGEST_LENGTH];
    
    sm3_hash(msg, strlen((char*)msg), digest);
    printf("SM3 hash of 'abc': ");
    print_digest(digest);
    
    return 0;
}