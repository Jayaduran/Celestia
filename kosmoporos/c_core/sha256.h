#ifndef KOSMOPOROS_SHA256_H
#define KOSMOPOROS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} KosmoporosSha256Context;

void kosmoporos_sha256_init(KosmoporosSha256Context *ctx);
void kosmoporos_sha256_update(KosmoporosSha256Context *ctx, const uint8_t *data, size_t len);
void kosmoporos_sha256_final(KosmoporosSha256Context *ctx, uint8_t hash[32]);

// One-shot raw hash calculation
void kosmoporos_sha256_raw(const uint8_t *data, size_t len, uint8_t hash[32]);

// One-shot hex string hash calculation (hex_out must have space for at least 65 bytes)
void kosmoporos_sha256_hex(const uint8_t *data, size_t len, char *hex_out);

#ifdef __cplusplus
}
#endif

#endif // KOSMOPOROS_SHA256_H
