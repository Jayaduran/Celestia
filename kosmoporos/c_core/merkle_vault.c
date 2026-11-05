#include "merkle_vault.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t byte_len) {
    for (size_t i = 0; i < byte_len; ++i) {
        unsigned int val = 0;
        sscanf(hex + i * 2, "%02x", &val);
        bytes[i] = (uint8_t)val;
    }
}

static void bytes_to_hex(const uint8_t *bytes, size_t byte_len, char *hex) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < byte_len; ++i) {
        hex[i * 2]     = hex_digits[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = hex_digits[bytes[i] & 0x0f];
    }
    hex[byte_len * 2] = '\0';
}

KosmoporosMerkleBlock* kosmoporos_merkle_block_create(size_t capacity, uint32_t block_id) {
    if (capacity == 0) {
        capacity = KOSMOPOROS_DEFAULT_BLOCK_SIZE;
    }
    KosmoporosMerkleBlock *block = (KosmoporosMerkleBlock*)malloc(sizeof(KosmoporosMerkleBlock));
    if (!block) return NULL;

    block->capacity = capacity;
    block->count = 0;
    block->block_id = block_id;
    block->is_sealed = false;
    memset(block->root_hash, 0, KOSMOPOROS_HASH_SIZE);

    block->leaf_hashes = (uint8_t(*)[KOSMOPOROS_HASH_SIZE])malloc(sizeof(uint8_t[KOSMOPOROS_HASH_SIZE]) * capacity);
    if (!block->leaf_hashes) {
        free(block);
        return NULL;
    }
    return block;
}

void kosmoporos_merkle_block_free(KosmoporosMerkleBlock *block) {
    if (!block) return;
    if (block->leaf_hashes) {
        free(block->leaf_hashes);
        block->leaf_hashes = NULL;
    }
    free(block);
}

bool kosmoporos_merkle_block_append_raw(KosmoporosMerkleBlock *block, const uint8_t *payload, size_t len) {
    if (!block || block->is_sealed || block->count >= block->capacity) return false;
    kosmoporos_sha256_raw(payload, len, block->leaf_hashes[block->count]);
    block->count++;
    return true;
}

bool kosmoporos_merkle_block_append_hash(KosmoporosMerkleBlock *block, const uint8_t hash[KOSMOPOROS_HASH_SIZE]) {
    if (!block || block->is_sealed || block->count >= block->capacity) return false;
    memcpy(block->leaf_hashes[block->count], hash, KOSMOPOROS_HASH_SIZE);
    block->count++;
    return true;
}

bool kosmoporos_merkle_block_append_hex(KosmoporosMerkleBlock *block, const char *hex_hash) {
    if (!block || block->is_sealed || block->count >= block->capacity || !hex_hash) return false;
    if (strlen(hex_hash) < 64) return false;
    hex_to_bytes(hex_hash, block->leaf_hashes[block->count], KOSMOPOROS_HASH_SIZE);
    block->count++;
    return true;
}

static void combine_nodes(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    uint8_t buffer[64];
    memcpy(buffer, left, 32);
    memcpy(buffer + 32, right, 32);
    kosmoporos_sha256_raw(buffer, 64, out);
}

bool kosmoporos_merkle_block_seal(KosmoporosMerkleBlock *block) {
    if (!block || block->count == 0) return false;

    size_t current_len = block->count;
    uint8_t (*level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * current_len);
    if (!level) return false;

    memcpy(level, block->leaf_hashes, sizeof(uint8_t[32]) * current_len);

    while (current_len > 1) {
        size_t next_len = (current_len + 1) / 2;
        uint8_t (*next_level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * next_len);
        if (!next_level) {
            free(level);
            return false;
        }

        for (size_t i = 0; i < next_len; ++i) {
            size_t left_idx = i * 2;
            size_t right_idx = (left_idx + 1 < current_len) ? left_idx + 1 : left_idx;
            combine_nodes(level[left_idx], level[right_idx], next_level[i]);
        }

        free(level);
        level = next_level;
        current_len = next_len;
    }

    memcpy(block->root_hash, level[0], KOSMOPOROS_HASH_SIZE);
    free(level);
    block->is_sealed = true;
    return true;
}

void kosmoporos_merkle_block_get_root_hex(const KosmoporosMerkleBlock *block, char hex_out[KOSMOPOROS_HEX_SIZE]) {
    if (!block) {
        memset(hex_out, 0, KOSMOPOROS_HEX_SIZE);
        return;
    }
    bytes_to_hex(block->root_hash, KOSMOPOROS_HASH_SIZE, hex_out);
}

bool kosmoporos_merkle_block_get_proof(const KosmoporosMerkleBlock *block, size_t leaf_index, KosmoporosMerkleProof *proof_out) {
    if (!block || !block->is_sealed || leaf_index >= block->count || !proof_out) return false;

    proof_out->count = 0;
    size_t current_len = block->count;
    size_t current_idx = leaf_index;

    uint8_t (*level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * current_len);
    if (!level) return false;
    memcpy(level, block->leaf_hashes, sizeof(uint8_t[32]) * current_len);

    while (current_len > 1) {
        size_t sibling_idx;
        bool is_right_sibling;
        if (current_idx % 2 == 0) {
            sibling_idx = (current_idx + 1 < current_len) ? current_idx + 1 : current_idx;
            is_right_sibling = true;
        } else {
            sibling_idx = current_idx - 1;
            is_right_sibling = false;
        }

        if (proof_out->count < 16) {
            memcpy(proof_out->steps[proof_out->count].hash, level[sibling_idx], 32);
            proof_out->steps[proof_out->count].is_right = is_right_sibling;
            proof_out->count++;
        }

        size_t next_len = (current_len + 1) / 2;
        uint8_t (*next_level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * next_len);
        if (!next_level) {
            free(level);
            return false;
        }

        for (size_t i = 0; i < next_len; ++i) {
            size_t left_idx = i * 2;
            size_t right_idx = (left_idx + 1 < current_len) ? left_idx + 1 : left_idx;
            combine_nodes(level[left_idx], level[right_idx], next_level[i]);
        }

        free(level);
        level = next_level;
        current_len = next_len;
        current_idx = current_idx / 2;
    }

    free(level);
    return true;
}

bool kosmoporos_merkle_verify_proof(const uint8_t leaf_hash[KOSMOPOROS_HASH_SIZE], const KosmoporosMerkleProof *proof, const uint8_t expected_root[KOSMOPOROS_HASH_SIZE]) {
    if (!leaf_hash || !proof || !expected_root) return false;

    uint8_t current_hash[32];
    memcpy(current_hash, leaf_hash, 32);

    for (size_t i = 0; i < proof->count; ++i) {
        if (proof->steps[i].is_right) {
            combine_nodes(current_hash, proof->steps[i].hash, current_hash);
        } else {
            combine_nodes(proof->steps[i].hash, current_hash, current_hash);
        }
    }

    return memcmp(current_hash, expected_root, 32) == 0;
}

bool kosmoporos_merkle_block_verify_integrity(const KosmoporosMerkleBlock *block) {
    if (!block || !block->is_sealed || block->count == 0) return false;

    // Recalculate root from leaf_hashes and compare with stored root_hash
    size_t current_len = block->count;
    uint8_t (*level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * current_len);
    if (!level) return false;
    memcpy(level, block->leaf_hashes, sizeof(uint8_t[32]) * current_len);

    while (current_len > 1) {
        size_t next_len = (current_len + 1) / 2;
        uint8_t (*next_level)[32] = (uint8_t(*)[32])malloc(sizeof(uint8_t[32]) * next_len);
        if (!next_level) {
            free(level);
            return false;
        }

        for (size_t i = 0; i < next_len; ++i) {
            size_t left_idx = i * 2;
            size_t right_idx = (left_idx + 1 < current_len) ? left_idx + 1 : left_idx;
            combine_nodes(level[left_idx], level[right_idx], next_level[i]);
        }

        free(level);
        level = next_level;
        current_len = next_len;
    }

    int match = memcmp(level[0], block->root_hash, 32);
    free(level);
    return match == 0;
}
