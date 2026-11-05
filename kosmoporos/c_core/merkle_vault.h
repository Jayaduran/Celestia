#ifndef KOSMOPOROS_MERKLE_VAULT_H
#define KOSMOPOROS_MERKLE_VAULT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KOSMOPOROS_DEFAULT_BLOCK_SIZE 125
#define KOSMOPOROS_HASH_SIZE 32
#define KOSMOPOROS_HEX_SIZE 65

typedef struct {
    uint8_t hash[KOSMOPOROS_HASH_SIZE];
    bool is_right; // true if sibling is right, false if left
} KosmoporosMerkleProofStep;

typedef struct {
    size_t count;
    KosmoporosMerkleProofStep steps[16]; // Max tree depth for 125+ leaves is ceil(log2(128)) = 7
} KosmoporosMerkleProof;

typedef struct {
    size_t capacity;
    size_t count;
    uint32_t block_id;
    uint8_t (*leaf_hashes)[KOSMOPOROS_HASH_SIZE];
    uint8_t root_hash[KOSMOPOROS_HASH_SIZE];
    bool is_sealed;
} KosmoporosMerkleBlock;

// Constructor / Destructor
KosmoporosMerkleBlock* kosmoporos_merkle_block_create(size_t capacity, uint32_t block_id);
void kosmoporos_merkle_block_free(KosmoporosMerkleBlock *block);

// Leaf Appends
bool kosmoporos_merkle_block_append_raw(KosmoporosMerkleBlock *block, const uint8_t *payload, size_t len);
bool kosmoporos_merkle_block_append_hash(KosmoporosMerkleBlock *block, const uint8_t hash[KOSMOPOROS_HASH_SIZE]);
bool kosmoporos_merkle_block_append_hex(KosmoporosMerkleBlock *block, const char *hex_hash);

// Tree Seal & Root Computation
bool kosmoporos_merkle_block_seal(KosmoporosMerkleBlock *block);
void kosmoporos_merkle_block_get_root_hex(const KosmoporosMerkleBlock *block, char hex_out[KOSMOPOROS_HEX_SIZE]);

// Proof Generation & Verification
bool kosmoporos_merkle_block_get_proof(const KosmoporosMerkleBlock *block, size_t leaf_index, KosmoporosMerkleProof *proof_out);
bool kosmoporos_merkle_verify_proof(const uint8_t leaf_hash[KOSMOPOROS_HASH_SIZE], const KosmoporosMerkleProof *proof, const uint8_t expected_root[KOSMOPOROS_HASH_SIZE]);

// Tamper Detection Check
bool kosmoporos_merkle_block_verify_integrity(const KosmoporosMerkleBlock *block);

#ifdef __cplusplus
}
#endif

#endif // KOSMOPOROS_MERKLE_VAULT_H
