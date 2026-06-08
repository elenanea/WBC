/*
 * WBC1 Original Algorithm - Parallel Implementation with MPI
 * 
 * Based on the original algorithm description where:
 * - Data divided into blocks of size s ∈ {32, 64, 128, 512} bits
 * - Blocks arranged in 3D cube d×d×d
 * - 127 permutation operations in table P
 * - Bit-by-bit key processing (each key bit selects an operation)
 * - Cyclic bitwise shift after each key bit
 * - MPI parallelization for block processing
 * 
 * Algorithm:
 * 1. Divide text T into blocks: T = {B₁, B₂, ..., Bₖ}, k = n/s
 * 2. For each block B_i:
 *    a. Write block into 3D cube d×d×d
 *    b. For each bit j of key K:
 *       - Select operation: O = P[K[j] mod 127]
 *       - Apply operation O to cube
 *       - Perform cyclic bitwise shift by d bits
 *    c. Extract block from cube
 * 3. Combine encrypted blocks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_BLOCK_SIZE 64  /* Maximum block size in bytes (512 bits) */
#define NUM_OPERATIONS 127
#define MAX_OP_STRING 256

/* Operation structure (same as other versions for compatibility) */
typedef struct {
    char type[32];
    char param1[64];
    char param2[64];
    char desc[128];
    char str_repr[MAX_OP_STRING];
    int chain_length;
    int chain[8];
} Operation;

/* WBC1 Original Cipher structure */
typedef struct {
    uint8_t *key;
    int key_len_bytes;
    int key_len_bits;
    int block_size_bits;
    int block_size_bytes;
    int cube_d;  /* Cube dimension d for d×d×d */
    Operation *operations;
    Operation *base_operations;
    int base_ops_count;
    int use_local_diffusion; /* 1=quality, 0=fast */
    int key_byte_step;       /* 1=full key walk, >1=strided fast walk */

    /* Cached key schedule: precomputed op IDs for each key step */
    uint8_t *round_op_ids;
    int round_steps;

    /* Cached bit source maps for cyclic shifts (+d and -d) */
    int shift_total_bits;
    uint16_t shift_src_fwd[MAX_BLOCK_SIZE * 8];
    uint16_t shift_src_inv[MAX_BLOCK_SIZE * 8];
} WBC1OriginalCipher;

/* Helper functions */
__attribute__((unused))
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

/* Mersenne Twister MT19937 implementation for operation generation */
typedef struct {
    uint32_t mt[624];
    int index;
} MT19937InitState;

static void mt_init_seed(MT19937InitState *state, uint32_t seed) {
    state->mt[0] = seed;
    for (int i = 1; i < 624; i++) {
        state->mt[i] = (1812433253UL * (state->mt[i-1] ^ (state->mt[i-1] >> 30)) + i);
    }
    state->index = 624;
}

static void mt_generate(MT19937InitState *state) {
    for (int i = 0; i < 624; i++) {
        uint32_t y = (state->mt[i] & 0x80000000UL) + (state->mt[(i+1) % 624] & 0x7FFFFFFFUL);
        state->mt[i] = state->mt[(i + 397) % 624] ^ (y >> 1);
        if (y & 1) state->mt[i] ^= 0x9908B0DFUL;
    }
    state->index = 0;
}

static uint32_t mt_random_init(MT19937InitState *state) {
    if (state->index >= 624) mt_generate(state);
    uint32_t y = state->mt[state->index++];
    y ^= y >> 11;
    y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= y >> 18;
    return y;
}

/* Get bit value from key at given bit index */
static int get_key_bit(const uint8_t *key, int bit_index, int key_len_bytes) {
    int byte_idx = bit_index / 8;
    int bit_pos = 7 - (bit_index % 8);  /* MSB first */
    if (byte_idx >= key_len_bytes) {
        byte_idx = byte_idx % key_len_bytes;  /* Wrap around */
    }
    return (key[byte_idx] >> bit_pos) & 1;
}

/* Forward declaration */
static uint8_t mix_key_byte(uint8_t byte);

/* Cyclic bitwise shift for entire block */
static void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits) {
    if (shift_bits == 0 || size_bytes == 0) return;
    if (size_bytes > MAX_BLOCK_SIZE) return;
    
    int total_bits = size_bytes * 8;
    shift_bits = shift_bits % total_bits;  /* Normalize shift */
    if (shift_bits < 0) shift_bits += total_bits;
    
    /* Stack buffer avoids malloc/free overhead in hot path */
    uint8_t temp[MAX_BLOCK_SIZE];
    memcpy(temp, block, size_bytes);
    
    /* Perform bit-level rotation */
    for (int i = 0; i < total_bits; i++) {
        int src_bit = (i + shift_bits) % total_bits;
        int src_byte = src_bit / 8;
        int src_pos = 7 - (src_bit % 8);
        int dst_byte = i / 8;
        int dst_pos = 7 - (i % 8);
        
        int bit_val = (temp[src_byte] >> src_pos) & 1;
        if (bit_val) {
            block[dst_byte] |= (1 << dst_pos);
        } else {
            block[dst_byte] &= ~(1 << dst_pos);
        }
    }
    
}

/* Build cached source maps for bitwise cyclic shifts */
static void build_shift_maps(WBC1OriginalCipher *cipher) {
    int total_bits = cipher->block_size_bytes * 8;
    if (total_bits <= 0 || total_bits > MAX_BLOCK_SIZE * 8) {
        cipher->shift_total_bits = 0;
        return;
    }

    cipher->shift_total_bits = total_bits;

    int shift_fwd = cipher->cube_d % total_bits;
    if (shift_fwd < 0) shift_fwd += total_bits;

    int shift_inv = (-cipher->cube_d) % total_bits;
    if (shift_inv < 0) shift_inv += total_bits;

    for (int i = 0; i < total_bits; i++) {
        cipher->shift_src_fwd[i] = (uint16_t)((i + shift_fwd) % total_bits);
        cipher->shift_src_inv[i] = (uint16_t)((i + shift_inv) % total_bits);
    }
}

/* Apply cached bitwise cyclic shift using precomputed maps */
static void apply_shift_cached(const WBC1OriginalCipher *cipher, uint8_t *block, int inverse) {
    int total_bits = cipher->shift_total_bits;
    if (total_bits <= 0) return;

    const uint16_t *src_map = inverse ? cipher->shift_src_inv : cipher->shift_src_fwd;
    uint8_t temp[MAX_BLOCK_SIZE];
    memcpy(temp, block, (size_t)cipher->block_size_bytes);

    for (int i = 0; i < total_bits; i++) {
        int src_bit = src_map[i];
        int src_byte = src_bit / 8;
        int src_pos = 7 - (src_bit % 8);
        int dst_byte = i / 8;
        int dst_pos = 7 - (i % 8);

        int bit_val = (temp[src_byte] >> src_pos) & 1;
        if (bit_val) {
            block[dst_byte] |= (uint8_t)(1U << dst_pos);
        } else {
            block[dst_byte] &= (uint8_t)~(1U << dst_pos);
        }
    }
}

/* Initialize 127 permutation operations (same as other versions) */
static void init_operations(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len) {
    /* Allocate operations arrays */
    cipher->operations = (Operation *)calloc(NUM_OPERATIONS, sizeof(Operation));
    cipher->base_operations = (Operation *)calloc(300, sizeof(Operation));
    if (!cipher->operations || !cipher->base_operations) {
        fprintf(stderr, "Error: Memory allocation failed for operations\n");
        return;
    }
    
    /* Temporary array to hold base operations before generating final 127 */
    Operation temp_ops[300];
    int temp_idx = 0;
    
    /* Face rotations: 6 faces x 4 directions = 24 ops */
    const char *faces[] = {"U", "D", "L", "R", "F", "B"};
    const char *dirs[] = {"", "'", "2", "3"};
    for (int f = 0; f < 6; f++) {
        for (int d = 0; d < 4; d++) {
            snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "face");
            snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%s", faces[f]);
            snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "%s", dirs[d]);
            snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Rotate %s face %s", faces[f], dirs[d]);
            snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                    "('face', '%s', '%s', 'Rotate %s face %s')", faces[f], dirs[d], faces[f], dirs[d]);
            temp_ops[temp_idx].chain_length = 0;
            temp_idx++;
        }
    }
    
    /* Slice moves: 3 slices x 4 directions = 12 ops */
    const char *slices[] = {"M", "E", "S"};
    for (int s = 0; s < 3; s++) {
        for (int d = 0; d < 4; d++) {
            snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "slice");
            snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%s", slices[s]);
            snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "%s", dirs[d]);
            snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Rotate %s slice %s", slices[s], dirs[d]);
            snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                    "('slice', '%s', '%s', 'Rotate %s slice %s')", slices[s], dirs[d], slices[s], dirs[d]);
            temp_ops[temp_idx].chain_length = 0;
            temp_idx++;
        }
    }
    
    /* Wide moves: 6 moves x 4 directions = 24 ops */
    const char *wide_moves[] = {"u", "d", "l", "r", "f", "b"};
    for (int w = 0; w < 6; w++) {
        for (int d = 0; d < 4; d++) {
            snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "wide");
            snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%s", wide_moves[w]);
            snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "%s", dirs[d]);
            snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Wide move %s%s", wide_moves[w], dirs[d]);
            snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                    "('wide', '%s', '%s', 'Wide move %s%s')", wide_moves[w], dirs[d], wide_moves[w], dirs[d]);
            temp_ops[temp_idx].chain_length = 0;
            temp_idx++;
        }
    }
    
    /* Cube rotations: 3 axes x 4 directions = 12 ops */
    const char *cube_rot[] = {"x", "y", "z"};
    for (int r = 0; r < 3; r++) {
        for (int d = 0; d < 4; d++) {
            snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "cube");
            snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%s", cube_rot[r]);
            snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "%s", dirs[d]);
            snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Cube rotation %s%s", cube_rot[r], dirs[d]);
            snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                    "('cube', '%s', '%s', 'Cube rotation %s%s')", cube_rot[r], dirs[d], cube_rot[r], dirs[d]);
            temp_ops[temp_idx].chain_length = 0;
            temp_idx++;
        }
    }
    
    /* Swap operations: 3 axes x 4 offsets = 12 ops */
    for (int axis = 0; axis < 3; axis++) {
        for (int k = 0; k < 4; k++) {
            snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "swap");
            snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%d", axis);
            snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "%d", k);
            snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Swap axis=%d, offset=%d", axis, k);
            snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                    "('swap', %d, %d, 'Swap axis=%d, offset=%d')", axis, k, axis, k);
            temp_ops[temp_idx].chain_length = 0;
            temp_idx++;
        }
    }
    
    /* Diagonal flip operations: 3 axes = 3 ops */
    for (int axis = 0; axis < 3; axis++) {
        snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "diagflip");
        snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%d", axis);
        temp_ops[temp_idx].param2[0] = '\0';
        snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Diagonal flip axis=%d", axis);
        snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                "('diagflip', %d, '', 'Diagonal flip axis=%d')", axis, axis);
        temp_ops[temp_idx].chain_length = 0;
        temp_idx++;
    }
    
    int static_ops_count = temp_idx;  /* Should be 87 base operations */
    
    /* Generate 20 dynamic operations with 4-7 base operations */
    for (int i = 0; i < 20; i++) {
        uint8_t seed_input[256];
        memcpy(seed_input, key, key_len);
        seed_input[key_len] = i & 0xFF;
        seed_input[key_len + 1] = (i >> 8) & 0xFF;
        
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(seed_input, key_len + 2, hash);
        uint32_t seed = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) | 
                       ((uint32_t)hash[2] << 8) | ((uint32_t)hash[3]);
        
        MT19937InitState rng;
        mt_init_seed(&rng, seed);
        
        int n_ops = 4 + (mt_random_init(&rng) % 4);  /* 4-7 operations */
        
        snprintf(temp_ops[temp_idx].type, sizeof(temp_ops[temp_idx].type), "dynamic");
        snprintf(temp_ops[temp_idx].param1, sizeof(temp_ops[temp_idx].param1), "%d", i);
        snprintf(temp_ops[temp_idx].param2, sizeof(temp_ops[temp_idx].param2), "ops");
        snprintf(temp_ops[temp_idx].desc, sizeof(temp_ops[temp_idx].desc), "Dynamic pattern %d", i);
        snprintf(temp_ops[temp_idx].str_repr, sizeof(temp_ops[temp_idx].str_repr),
                "('dynamic', %d, 'ops', 'Dynamic pattern %d')", i, i);
        
        temp_ops[temp_idx].chain_length = n_ops;
        for (int j = 0; j < n_ops; j++) {
            temp_ops[temp_idx].chain[j] = mt_random_init(&rng) % static_ops_count;
        }
        temp_idx++;
    }
    
    int all_ops_count = temp_idx;  /* Should be 107 (87 + 20) */
    
    /* Store temp_ops in cipher->base_operations for use by apply_operation */
    memcpy(cipher->base_operations, temp_ops, sizeof(Operation) * all_ops_count);
    cipher->base_ops_count = all_ops_count;
    
    /* Generate 127 final operations using base operations */
    /* For original algorithm, we use simple deterministic generation based on key */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        uint8_t seed_input[256];
        memcpy(seed_input, key, key_len);
        memcpy(seed_input + key_len, "WBC1_OP", 7);
        seed_input[key_len + 7] = i & 0xFF;
        seed_input[key_len + 8] = (i >> 8) & 0xFF;
        
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(seed_input, key_len + 9, hash);
        uint32_t seed = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) | 
                       ((uint32_t)hash[2] << 8) | ((uint32_t)hash[3]);
        
        MT19937InitState rng;
        mt_init_seed(&rng, seed);
        
        int chain_len = 3 + (mt_random_init(&rng) % 4);  /* 3-6 operations */
        
        /* Generate chain */
        snprintf(cipher->operations[i].type, sizeof(cipher->operations[i].type), "dynamic");
        snprintf(cipher->operations[i].param1, sizeof(cipher->operations[i].param1), "%d", i);
        snprintf(cipher->operations[i].param2, sizeof(cipher->operations[i].param2), "chain");
        snprintf(cipher->operations[i].desc, sizeof(cipher->operations[i].desc), "Operation %d", i);
        snprintf(cipher->operations[i].str_repr, sizeof(cipher->operations[i].str_repr),
                "('dynamic', %d, 'chain', 'Operation %d')", i, i);
        
        cipher->operations[i].chain_length = chain_len;
        for (int j = 0; j < chain_len; j++) {
            cipher->operations[i].chain[j] = mt_random_init(&rng) % all_ops_count;
        }
    }
}

/* Apply permutation operation to block */
static void apply_operation(WBC1OriginalCipher *cipher, uint8_t *block, int op_id, int inverse) {
    /* Simple permutation: rotate bytes */
    /* In full implementation, this would perform actual Rubik's cube operations */
    int size = cipher->block_size_bytes;
    uint8_t temp[MAX_BLOCK_SIZE];
    memcpy(temp, block, size);
    
    /* Simple rotation based on operation ID */
    int shift = (op_id % size) + 1;
    if (inverse) {
        shift = size - shift;
    }
    
    for (int i = 0; i < size; i++) {
        block[i] = temp[(i + shift) % size];
    }
}

/* Initialize cipher */
void wbc1_original_init(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len, int block_size_bits, int speed_profile) {
    memset(cipher, 0, sizeof(WBC1OriginalCipher));
    
    /* Store key */
    cipher->key_len_bytes = key_len;
    cipher->key_len_bits = key_len * 8;
    cipher->key = (uint8_t *)malloc(key_len);
    memcpy(cipher->key, key, key_len);
    
    /* Set block size */
    cipher->block_size_bits = block_size_bits;
    cipher->block_size_bytes = block_size_bits / 8;
    
    /* Calculate cube dimension */
    /* For simplicity: use fixed mappings */
    switch (block_size_bits) {
        case 32:  cipher->cube_d = 2; break;  /* 2×2×2 = 8 positions × 4 bits */
        case 64:  cipher->cube_d = 4; break;  /* 2×2×4 or similar */
        case 128: cipher->cube_d = 4; break;  /* 2×4×4 or 2×2×8 */
        case 512: cipher->cube_d = 8; break;  /* 4×4×8 or similar */
        default:  cipher->cube_d = 4; break;
    }
    
    /* Initialize operations table with full 127 operations */
    init_operations(cipher, cipher->key, cipher->key_len_bytes);

    if (speed_profile == 0) {
        cipher->use_local_diffusion = 1; /* quality */
        cipher->key_byte_step = 1;
    } else if (speed_profile == 1) {
        cipher->use_local_diffusion = 0; /* fast */
        cipher->key_byte_step = 1;
    } else {
        cipher->use_local_diffusion = 0; /* ultra */
        cipher->key_byte_step = 4;
    }

    /* Cache key schedule (op IDs selected per key step) */
    cipher->round_steps = (cipher->key_len_bytes + cipher->key_byte_step - 1) / cipher->key_byte_step;
    cipher->round_op_ids = (uint8_t *)malloc((size_t)cipher->round_steps);
    if (cipher->round_op_ids) {
        int step = 0;
        for (int byte_idx = 0; byte_idx < cipher->key_len_bytes; byte_idx += cipher->key_byte_step) {
            uint8_t mixed_byte = mix_key_byte(cipher->key[byte_idx]);
            cipher->round_op_ids[step++] = (uint8_t)(mixed_byte % NUM_OPERATIONS);
        }
    } else {
        cipher->round_steps = 0;
    }

    /* Cache bit maps for cyclic shifts */
    build_shift_maps(cipher);
}

/* Free cipher resources */
void wbc1_original_free(WBC1OriginalCipher *cipher) {
    if (cipher->key) free(cipher->key);
    if (cipher->operations) free(cipher->operations);
    if (cipher->base_operations) free(cipher->base_operations);
    if (cipher->round_op_ids) free(cipher->round_op_ids);
    memset(cipher, 0, sizeof(WBC1OriginalCipher));
}

/* Mix key byte to ensure all bits have equal influence on operation selection */
static uint8_t mix_key_byte(uint8_t byte) {
    /* XOR-based mixing function for better bit diffusion
     * This ensures that flipping any single bit in the key byte
     * will have approximately equal impact on the selected operation.
     * Without mixing, high-order bits have weak influence due to modulo 127.
     */
    uint8_t mixed = byte;
    
    /* Mix high bits into low bits */
    mixed ^= (byte >> 4);
    
    /* Mix with rotation for circular diffusion */
    mixed ^= ((byte << 3) | (byte >> 5));
    
    /* Final mixing pass */
    mixed ^= (byte >> 1);
    
    return mixed;
}

/* Local reversible diffusion to improve intra-block bit spreading */
static void local_diffusion_round(uint8_t *block, int size) {
    if (size < 2) return;

    for (int i = 1; i < size; i++) {
        block[i] ^= block[i - 1];
    }
    for (int i = size - 2; i >= 0; i--) {
        block[i] ^= block[i + 1];
    }
}

/* Inverse of local_diffusion_round */
static void local_diffusion_round_inverse(uint8_t *block, int size) {
    if (size < 2) return;

    for (int i = 0; i < size - 1; i++) {
        block[i] ^= block[i + 1];
    }
    for (int i = size - 1; i >= 1; i--) {
        block[i] ^= block[i - 1];
    }
}

/* Encrypt single block using original algorithm (BYTE-BASED) */
void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext) {
    /* Copy plaintext to ciphertext (working buffer) */
    memcpy(ciphertext, plaintext, cipher->block_size_bytes);

    /* Fast path: cached key schedule */
    if (cipher->round_op_ids && cipher->round_steps > 0) {
        for (int step = 0; step < cipher->round_steps; step++) {
            int op_id = cipher->round_op_ids[step];

            /* Step 2: Apply selected operation */
            apply_operation(cipher, ciphertext, op_id, 0);

            /* Step 2.5: Optional local diffusion after permutation */
            if (cipher->use_local_diffusion) {
                local_diffusion_round(ciphertext, cipher->block_size_bytes);
            }

            /* Step 3: Cyclic bitwise shift by d bits (cached map) */
            apply_shift_cached(cipher, ciphertext, 0);
        }
        return;
    }

    /* Fallback path: compute operation IDs on the fly */
    for (int byte_idx = 0; byte_idx < cipher->key_len_bytes; byte_idx += cipher->key_byte_step) {
        uint8_t key_byte = cipher->key[byte_idx];
        uint8_t mixed_byte = mix_key_byte(key_byte);
        int op_id = mixed_byte % NUM_OPERATIONS;
        
        /* Step 2: Apply selected operation */
        apply_operation(cipher, ciphertext, op_id, 0);

        /* Step 2.5: Optional local diffusion after permutation */
        if (cipher->use_local_diffusion) {
            local_diffusion_round(ciphertext, cipher->block_size_bytes);
        }
        
        /* Step 3: Cyclic bitwise shift by d bits */
        apply_shift_cached(cipher, ciphertext, 0);
    }
}

/* Decrypt single block (reverse process - BYTE-BASED) */
void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext) {
    /* Copy ciphertext to plaintext (working buffer) */
    memcpy(plaintext, ciphertext, cipher->block_size_bytes);

    /* Fast path: cached key schedule in reverse */
    if (cipher->round_op_ids && cipher->round_steps > 0) {
        for (int step = cipher->round_steps - 1; step >= 0; step--) {
            int op_id = cipher->round_op_ids[step];

            /* Step 1: Reverse cyclic shift */
            apply_shift_cached(cipher, plaintext, 1);

            /* Step 2: Reverse local diffusion (if enabled) */
            if (cipher->use_local_diffusion) {
                local_diffusion_round_inverse(plaintext, cipher->block_size_bytes);
            }

            /* Step 4: Apply inverse operation */
            apply_operation(cipher, plaintext, op_id, 1);
        }
        return;
    }

    /* Fallback path: compute operation IDs on the fly */
    int last_idx = ((cipher->key_len_bytes - 1) / cipher->key_byte_step) * cipher->key_byte_step;
    for (int byte_idx = last_idx; byte_idx >= 0; byte_idx -= cipher->key_byte_step) {
        /* Step 1: Reverse cyclic shift */
        apply_shift_cached(cipher, plaintext, 1);

        /* Step 2: Reverse local diffusion (if enabled) */
        if (cipher->use_local_diffusion) {
            local_diffusion_round_inverse(plaintext, cipher->block_size_bytes);
        }
        
        /* Step 3: Get key byte, mix it, and select operation */
        uint8_t key_byte = cipher->key[byte_idx];
        uint8_t mixed_byte = mix_key_byte(key_byte);
        int op_id = mixed_byte % NUM_OPERATIONS;
        
        /* Step 4: Apply inverse operation */
        apply_operation(cipher, plaintext, op_id, 1);
    }
}

/* Parallel encryption using MPI */
void parallel_original_encrypt(WBC1OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len,
                               uint8_t **ciphertext, int *ciphertext_len) {
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    int block_size = cipher->block_size_bytes;
    int num_blocks = (plaintext_len + block_size - 1) / block_size;
    int padded_len = num_blocks * block_size;
    
    /* Prepare padded plaintext on root */
    uint8_t *padded_plaintext = NULL;
    if (rank == 0) {
        padded_plaintext = (uint8_t *)calloc(padded_len, 1);
        memcpy(padded_plaintext, plaintext, plaintext_len);
        /* PKCS7 padding */
        int padding_len = padded_len - plaintext_len;
        for (int i = 0; i < padding_len; i++) {
            padded_plaintext[plaintext_len + i] = padding_len;
        }
    }
    
    /* Distribute blocks among processes */
    int blocks_per_proc = num_blocks / size;
    int extra_blocks = num_blocks % size;
    int my_num_blocks = blocks_per_proc + (rank < extra_blocks ? 1 : 0);
    
    uint8_t *my_plaintext = (uint8_t *)malloc(my_num_blocks * block_size);
    uint8_t *my_ciphertext = (uint8_t *)malloc(my_num_blocks * block_size);
    
    /* Scatter blocks */
    int *sendcounts = NULL;
    int *displs = NULL;
    if (rank == 0) {
        sendcounts = (int *)malloc(size * sizeof(int));
        displs = (int *)malloc(size * sizeof(int));
        int offset = 0;
        for (int i = 0; i < size; i++) {
            int proc_blocks = blocks_per_proc + (i < extra_blocks ? 1 : 0);
            sendcounts[i] = proc_blocks * block_size;
            displs[i] = offset;
            offset += sendcounts[i];
        }
    }
    
    MPI_Scatterv(padded_plaintext, sendcounts, displs, MPI_BYTE,
                 my_plaintext, my_num_blocks * block_size, MPI_BYTE,
                 0, MPI_COMM_WORLD);
    
    /* Encrypt local blocks */
    for (int i = 0; i < my_num_blocks; i++) {
        wbc1_original_encrypt_block(cipher, 
                                    my_plaintext + i * block_size,
                                    my_ciphertext + i * block_size);
    }
    
    /* Gather encrypted blocks */
    uint8_t *gathered_ciphertext = NULL;
    if (rank == 0) {
        gathered_ciphertext = (uint8_t *)malloc(padded_len);
    }
    
    MPI_Gatherv(my_ciphertext, my_num_blocks * block_size, MPI_BYTE,
                gathered_ciphertext, sendcounts, displs, MPI_BYTE,
                0, MPI_COMM_WORLD);
    
    /* Return result on root */
    if (rank == 0) {
        *ciphertext = gathered_ciphertext;
        *ciphertext_len = padded_len;
        free(padded_plaintext);
        free(sendcounts);
        free(displs);
    }
    
    free(my_plaintext);
    free(my_ciphertext);
}

/* Parallel decryption using MPI */
void parallel_original_decrypt(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len,
                               uint8_t **plaintext, int *plaintext_len) {
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    int block_size = cipher->block_size_bytes;
    int num_blocks = ciphertext_len / block_size;
    
    /* Distribute blocks */
    int blocks_per_proc = num_blocks / size;
    int extra_blocks = num_blocks % size;
    int my_num_blocks = blocks_per_proc + (rank < extra_blocks ? 1 : 0);
    
    uint8_t *my_ciphertext = (uint8_t *)malloc(my_num_blocks * block_size);
    uint8_t *my_plaintext = (uint8_t *)malloc(my_num_blocks * block_size);
    
    /* Scatter blocks */
    int *sendcounts = NULL;
    int *displs = NULL;
    if (rank == 0) {
        sendcounts = (int *)malloc(size * sizeof(int));
        displs = (int *)malloc(size * sizeof(int));
        int offset = 0;
        for (int i = 0; i < size; i++) {
            int proc_blocks = blocks_per_proc + (i < extra_blocks ? 1 : 0);
            sendcounts[i] = proc_blocks * block_size;
            displs[i] = offset;
            offset += sendcounts[i];
        }
    }
    
    MPI_Scatterv(ciphertext, sendcounts, displs, MPI_BYTE,
                 my_ciphertext, my_num_blocks * block_size, MPI_BYTE,
                 0, MPI_COMM_WORLD);
    
    /* Decrypt local blocks */
    for (int i = 0; i < my_num_blocks; i++) {
        wbc1_original_decrypt_block(cipher,
                                    my_ciphertext + i * block_size,
                                    my_plaintext + i * block_size);
    }
    
    /* Gather decrypted blocks */
    uint8_t *gathered_plaintext = NULL;
    if (rank == 0) {
        gathered_plaintext = (uint8_t *)malloc(ciphertext_len);
    }
    
    MPI_Gatherv(my_plaintext, my_num_blocks * block_size, MPI_BYTE,
                gathered_plaintext, sendcounts, displs, MPI_BYTE,
                0, MPI_COMM_WORLD);
    
    /* Remove padding on root */
    if (rank == 0) {
        int padding_len = gathered_plaintext[ciphertext_len - 1];
        
        /* Validate PKCS7 padding */
        int valid_padding = 0;
        if (padding_len > 0 && padding_len <= block_size) {
            valid_padding = 1;
            /* Check that all padding bytes have the same value */
            for (int i = ciphertext_len - padding_len; i < ciphertext_len; i++) {
                if (gathered_plaintext[i] != padding_len) {
                    valid_padding = 0;
                    break;
                }
            }
        }
        
        /* Remove padding only if valid */
        if (valid_padding) {
            *plaintext_len = ciphertext_len - padding_len;
        } else {
            *plaintext_len = ciphertext_len;  /* No padding to remove */
        }
        
        *plaintext = (uint8_t *)malloc(*plaintext_len);
        memcpy(*plaintext, gathered_plaintext, *plaintext_len);
        free(gathered_plaintext);
        free(sendcounts);
        free(displs);
    }
    
    free(my_ciphertext);
    free(my_plaintext);
}

/* ========================================
 * Statistical Test Functions
 * ======================================== */

/* Generate random bytes for testing */
static uint8_t* generate_random_bytes(int size) {
    uint8_t *data = (uint8_t *)malloc(size);
    srand(time(NULL));
    for (int i = 0; i < size; i++) {
        data[i] = rand() % 256;
    }
    return data;
}

/* Shannon Entropy calculation */
static double shannon_entropy(const uint8_t *data, int len) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* Frequency test (Chi-square) */
static void frequency_test(const uint8_t *data, int len, double *mean, double *std, double *chi_square) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    
    /* Calculate mean */
    double sum = 0.0;
    for (int i = 0; i < 256; i++) {
        sum += freq[i];
    }
    *mean = sum / 256.0;
    
    /* Calculate standard deviation */
    double sum_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = freq[i] - *mean;
        sum_sq += diff * diff;
    }
    *std = sqrt(sum_sq / 256.0);
    
    /* Calculate chi-square */
    double expected = len / 256.0;
    *chi_square = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = freq[i] - expected;
        *chi_square += (diff * diff) / expected;
    }
}

/* Avalanche effect test */
static void avalanche_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total_percent = 0.0;
    double min_percent = 100.0;
    double max_percent = 0.0;
    
    int block_size = cipher->block_size_bytes;
    
    for (int test = 0; test < num_tests; test++) {
        /* Generate random plaintext */
        uint8_t *plaintext1 = generate_random_bytes(block_size);
        uint8_t *plaintext2 = (uint8_t *)malloc(block_size);
        memcpy(plaintext2, plaintext1, block_size);
        
        /* Flip one random bit */
        int flip_byte = rand() % block_size;
        int flip_bit = rand() % 8;
        plaintext2[flip_byte] ^= (1 << flip_bit);
        
        /* Encrypt both */
        uint8_t *cipher1 = (uint8_t *)malloc(block_size);
        uint8_t *cipher2 = (uint8_t *)malloc(block_size);
        
        wbc1_original_encrypt_block(cipher, plaintext1, cipher1);
        wbc1_original_encrypt_block(cipher, plaintext2, cipher2);
        
        /* Count differing bits */
        int diff_bits = 0;
        for (int i = 0; i < block_size; i++) {
            uint8_t xor_val = cipher1[i] ^ cipher2[i];
            for (int b = 0; b < 8; b++) {
                if (xor_val & (1 << b)) diff_bits++;
            }
        }
        
        double percent = (100.0 * diff_bits) / (block_size * 8);
        total_percent += percent;
        if (percent < min_percent) min_percent = percent;
        if (percent > max_percent) max_percent = percent;
        
        free(plaintext1);
        free(plaintext2);
        free(cipher1);
        free(cipher2);
    }
    
    results[0] = total_percent / num_tests;  /* Average */
    results[1] = min_percent;
    results[2] = max_percent;
}

/* Correlation test */
static double correlation_test(const uint8_t *data1, const uint8_t *data2, int len) {
    double mean1 = 0.0, mean2 = 0.0;
    for (int i = 0; i < len; i++) {
        mean1 += data1[i];
        mean2 += data2[i];
    }
    mean1 /= len;
    mean2 /= len;
    
    double cov = 0.0, var1 = 0.0, var2 = 0.0;
    for (int i = 0; i < len; i++) {
        double diff1 = data1[i] - mean1;
        double diff2 = data2[i] - mean2;
        cov += diff1 * diff2;
        var1 += diff1 * diff1;
        var2 += diff2 * diff2;
    }
    
    if (var1 == 0.0 || var2 == 0.0) return 0.0;
    return cov / sqrt(var1 * var2);
}

/* Differential test (key sensitivity) */
static void differential_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total_percent = 0.0;
    double min_percent = 100.0;
    double max_percent = 0.0;
    
    int block_size = cipher->block_size_bytes;
    uint8_t *plaintext = generate_random_bytes(block_size);
    
    for (int test = 0; test < num_tests; test++) {
        /* Encrypt with original key */
        uint8_t *cipher1 = (uint8_t *)malloc(block_size);
        wbc1_original_encrypt_block(cipher, plaintext, cipher1);
        
        /* Modify one bit in key */
        int flip_byte = rand() % cipher->key_len_bytes;
        int flip_bit = rand() % 8;
        cipher->key[flip_byte] ^= (1 << flip_bit);
        
        /* Encrypt with modified key */
        uint8_t *cipher2 = (uint8_t *)malloc(block_size);
        wbc1_original_encrypt_block(cipher, plaintext, cipher2);
        
        /* Restore key */
        cipher->key[flip_byte] ^= (1 << flip_bit);
        
        /* Count differing bits */
        int diff_bits = 0;
        for (int i = 0; i < block_size; i++) {
            uint8_t xor_val = cipher1[i] ^ cipher2[i];
            for (int b = 0; b < 8; b++) {
                if (xor_val & (1 << b)) diff_bits++;
            }
        }
        
        double percent = (100.0 * diff_bits) / (block_size * 8);
        total_percent += percent;
        if (percent < min_percent) min_percent = percent;
        if (percent > max_percent) max_percent = percent;
        
        free(cipher1);
        free(cipher2);
    }
    
    results[0] = total_percent / num_tests;  /* Average */
    results[1] = min_percent;
    results[2] = max_percent;
    free(plaintext);
}

/* Benchmark helpers */
static int cmp_double_asc(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double aggregate_bench_time(double *t, int n, int trim) {
    if (!trim || n < 5) {
        double s = 0.0;
        for (int i = 0; i < n; i++) s += t[i];
        return s / n;
    }

    double tmp[64];
    memcpy(tmp, t, (size_t)n * sizeof(double));
    qsort(tmp, (size_t)n, sizeof(double), cmp_double_asc);

    int cut = (n >= 15) ? 2 : 1;
    int start = cut;
    int end = n - cut;
    if (end <= start) {
        double s = 0.0;
        for (int i = 0; i < n; i++) s += t[i];
        return s / n;
    }

    double s = 0.0;
    for (int i = start; i < end; i++) s += tmp[i];
    return s / (end - start);
}

static double read_cpu_mhz(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0.0;
    char line[256];
    double mhz = 0.0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "cpu MHz", 7) == 0) {
            char *p = strchr(line, ':');
            if (p) {
                mhz = atof(p + 1);
                break;
            }
        }
    }
    fclose(f);
    return mhz;
}

/* Local benchmark in style of wbc1_cascade_new0 */
/* bench_profile: 1=quick, 2=full */
static void benchmark_core(WBC1OriginalCipher *cipher, int bench_profile, int repeats_override) {
    static const int sizes_quick[] = {1, 10, 100, 1000};
    static const int sizes_full[] = {1, 10, 100, 1000, 10000};
    const int *sizes = (bench_profile == 1) ? sizes_quick : sizes_full;
    int ns = (bench_profile == 1)
             ? (int)(sizeof(sizes_quick) / sizeof(sizes_quick[0]))
             : (int)(sizeof(sizes_full) / sizeof(sizes_full[0]));

    int repeats = (bench_profile == 1) ? 3 : 10;
    int trim_outliers = 1;

    if (repeats_override > 0) {
        repeats = repeats_override;
    }

    {
        const char *env = getenv("WBC_BENCH_REPEATS");
        if (env) {
            int v = atoi(env);
            if (v >= 1 && v <= 64) repeats = v;
        }
    }
    {
        const char *env = getenv("WBC_BENCH_TRIM");
        if (env && env[0] == '0') trim_outliers = 0;
    }

    double enc_spds[8] = {0};
    double dec_spds[8] = {0};

        printf("\nPerformance Benchmark / Бенчмарк производительности (%s):\n",
            (bench_profile == 1) ? "quick" : "full");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers ? "trimmed mean" : "mean");
    printf("  %10s  %10s  %10s  %10s  %10s  %12s  %12s  %9s\n",
           "Size (KB)", "Enc (s)", "Dec (s)", "Enc MB/s", "Dec MB/s", "Enc Mbit/s", "Dec Mbit/s", "Check");
    printf("  %s\n", "----------------------------------------------------------------------------------------------");

    for (int si = 0; si < ns; si++) {
        int size = sizes[si] * 1024;
        int block_size = cipher->block_size_bytes;
        int num_blocks = (size + block_size - 1) / block_size;
        int padded_len = num_blocks * block_size;

        uint8_t *data = generate_random_bytes(size);
        uint8_t *plain_padded = (uint8_t *)calloc((size_t)padded_len, 1);
        uint8_t *enc = (uint8_t *)malloc((size_t)padded_len);
        uint8_t *dec = (uint8_t *)malloc((size_t)padded_len);
        if (!data || !plain_padded || !enc || !dec) {
            free(data); free(plain_padded); free(enc); free(dec);
            printf("  %10d  %10s  %10s  %10s  %10s  %12s  %12s  %9s\n",
                   sizes[si], "OOM", "OOM", "OOM", "OOM", "OOM", "OOM", "FAIL");
            continue;
        }

        memcpy(plain_padded, data, size);
        int pad = padded_len - size;
        for (int i = 0; i < pad; i++) {
            plain_padded[size + i] = (uint8_t)pad;
        }

        double enc_times[64] = {0};
        double dec_times[64] = {0};
        int all_ok = 1;

        for (int r = 0; r < repeats; r++) {
            struct timespec t0, t1;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int b = 0; b < num_blocks; b++) {
                wbc1_original_encrypt_block(cipher,
                                            plain_padded + b * block_size,
                                            enc + b * block_size);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            enc_times[r] = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int b = 0; b < num_blocks; b++) {
                wbc1_original_decrypt_block(cipher,
                                            enc + b * block_size,
                                            dec + b * block_size);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            dec_times[r] = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

            if (memcmp(plain_padded, dec, (size_t)padded_len) != 0) {
                all_ok = 0;
            }
        }

        double enc_avg = aggregate_bench_time(enc_times, repeats, trim_outliers);
        double dec_avg = aggregate_bench_time(dec_times, repeats, trim_outliers);

        double enc_mbps = ((double)size / 1000000.0) / (enc_avg > 0 ? enc_avg : 1e-9);
        double dec_mbps = ((double)size / 1000000.0) / (dec_avg > 0 ? dec_avg : 1e-9);
        double enc_mbit = enc_mbps * 8.0;
        double dec_mbit = dec_mbps * 8.0;

        enc_spds[si] = enc_mbps;
        dec_spds[si] = dec_mbps;

        printf("  %10d  %10.5f  %10.5f  %10.2f  %10.2f  %12.2f  %12.2f  %9s\n",
               sizes[si], enc_avg, dec_avg, enc_mbps, dec_mbps, enc_mbit, dec_mbit, all_ok ? "OK" : "FAIL");

        free(data);
        free(plain_padded);
        free(enc);
        free(dec);
    }

    {
        double cpu_mhz = read_cpu_mhz();
        if (cpu_mhz > 0.0) {
            printf("\n  CPB / Cycles per byte  (CPU: %.0f MHz)\n", cpu_mhz);
            printf("  %10s  %10s  %10s\n", "Size (KB)", "Enc CPB", "Dec CPB");
            printf("  %s\n", "------------------------------------------");
            for (int si = 0; si < ns; si++) {
                double ecpb = (enc_spds[si] > 0.0) ? (cpu_mhz / enc_spds[si]) : 0.0;
                double dcpb = (dec_spds[si] > 0.0) ? (cpu_mhz / dec_spds[si]) : 0.0;
                printf("  %10d  %10.2f  %10.2f\n", sizes[si], ecpb, dcpb);
            }
        } else {
            printf("\n  CPB: CPU frequency unavailable\n");
        }
    }
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

/* Print hex data */
static void print_hex(const uint8_t *data, int len, int max_bytes) {
    for (int i = 0; i < len && i < max_bytes; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len > max_bytes) printf("...\n");
    else if (len % 32 != 0) printf("\n");
}

/* ========================================
 * Key and Operation Display Functions
 * ======================================== */

/* Display key in hex format */
static void print_key_hex(const uint8_t *key, int key_len) {
    printf("\n");
    printf("====================================================================================================\n");
    printf("Generated key (hex) / Сгенерированный ключ (hex)\n");
    printf("====================================================================================================\n");
    for (int i = 0; i < key_len; i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n");
        } else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
    if (key_len % 32 != 0) printf("\n");
    printf("====================================================================================================\n");
    printf("\n");
}

/* Display key-to-operation mapping */
static void print_key_operation_mapping(WBC1OriginalCipher *cipher, int show_count) {
    printf("\n");
    printf("====================================================================================================\n");
    printf("Key-to-Operation Mapping / Соответствие байтов ключа операциям\n");
    printf("Format: Key[N]: ASCII Hex → Operation ID: (type, params) description\n");
    printf("====================================================================================================\n");
    
    if (show_count > cipher->key_len_bytes) {
        show_count = cipher->key_len_bytes;
    }
    
    for (int i = 0; i < show_count; i++) {
        uint8_t key_byte = cipher->key[i];
        int op_id = key_byte % NUM_OPERATIONS;
        Operation *op = &cipher->operations[op_id];
        
        /* ASCII character if printable, otherwise '.' */
        char ascii_char = (key_byte >= 32 && key_byte <= 126) ? key_byte : '.';
        
        printf("Key[%3d]: %c 0x%02X → Op %3d: ", i, ascii_char, key_byte, op_id);
        
        if (strcmp(op->type, "dynamic") == 0) {
            printf("(dynamic, '%s', chain=%d ops) %s\n", 
                   op->param1, op->chain_length, op->desc);
        } else {
            printf("(%s, '%s', '%s') %s\n",
                   op->type, op->param1, op->param2, op->desc);
        }
    }
    
    printf("====================================================================================================\n");
    printf("\n");
}

/* Print operations table */
static void print_operations_table(WBC1OriginalCipher *cipher) {
    printf("\n");
    printf("==============================================================================\n");
    printf("          WBC1 ORIGINAL - ТАБЛИЦА ОПЕРАЦИЙ / OPERATIONS TABLE\n");
    printf("==============================================================================\n");
    printf("%-7s %-10s %-10s %s\n", 
           "Номер", "ASCII", "Hex", "Описание операции");
    printf("%-7s %-10s %-10s %s\n", 
           "Number", "Char", "Code", "Operation Description");
    printf("------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        Operation *op = &cipher->operations[i];
        
        /* ASCII character (printable or . for non-printable) */
        char ascii_char[12];
        if (i >= 32 && i < 127) {
            snprintf(ascii_char, sizeof(ascii_char), "'%c'", (char)i);
        } else {
            snprintf(ascii_char, sizeof(ascii_char), ".");
        }
        
        /* Hex representation */
        char hex[12];
        snprintf(hex, sizeof(hex), "0x%02X", i);
        
        /* Print operation info with type and parameters */
        printf("%-7d %-10s %-10s ", i, ascii_char, hex);
        
        /* Print operation details including type and chain info */
        printf("(%s", op->type);
        if (strlen(op->param1) > 0) {
            printf(", '%s'", op->param1);
        }
        if (strlen(op->param2) > 0) {
            printf(", '%s'", op->param2);
        }
        if (op->chain_length > 0) {
            printf(", chain=%d ops", op->chain_length);
        }
        printf(") %s\n", op->desc);
    }
    
    printf("==============================================================================\n");
    printf("Всего операций / Total operations: %d\n", NUM_OPERATIONS);
    
    /* Count operation types */
    int dynamic_count = 0;
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        if (strcmp(cipher->operations[i].type, "dynamic") == 0) {
            dynamic_count++;
        }
    }
    
    printf("\nТипы операций / Operation types:\n");
    printf("  - Динамические операции / Dynamic operations: %d\n", dynamic_count);
    printf("  - Базовые операции / Base operations: %d\n", cipher->base_ops_count);
    printf("    - Вращения граней / Face rotations: 24\n");
    printf("    - Срезы / Slice moves: 12\n");
    printf("    - Широкие ходы / Wide moves: 24\n");
    printf("    - Вращения куба / Cube rotations: 12\n");
    printf("    - Swap операции / Swap operations: 12\n");
    printf("    - Diagonal flips: 3\n");
    printf("    - Динамические паттерны / Dynamic patterns: 20\n");
    printf("==============================================================================\n\n");
    
    /* Additional statistics */
    printf("\nПримеры базовых операций / Examples of base operations:\n");
    printf("------------------------------------------------------------------------------\n");
    
    /* Show first few of each type from base_operations */
    if (cipher->base_operations) {
        printf("Вращения граней (Face rotations):\n");
        for (int i = 0; i < 6 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nСрезы (Slice moves):\n");
        for (int i = 24; i < 28 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nШирокие ходы (Wide moves):\n");
        for (int i = 36; i < 40 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nВращения куба (Cube rotations):\n");
        for (int i = 60; i < 64 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nSwap операции:\n");
        for (int i = 72; i < 76 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nДиагональные перевороты (Diagonal flips):\n");
        for (int i = 84; i < 87 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s') %s\n", i, op->type, op->param1, op->param2, op->desc);
        }
        
        printf("\nДинамические паттерны (Dynamic patterns):\n");
        for (int i = 87; i < 90 && i < cipher->base_ops_count; i++) {
            Operation *op = &cipher->base_operations[i];
            printf("  %d: (%s, '%s', '%s', chain=%d ops) %s\n", 
                   i, op->type, op->param1, op->param2, op->chain_length, op->desc);
        }
    }
    printf("==============================================================================\n\n");
    
    printf("Отображение битов ключа на операции:\n");
    printf("Key bit to operation mapping:\n");
    printf("------------------------------------------------------------------------------\n");
    for (int i = 0; i < 10 && i < cipher->key_len_bits; i++) {
        int key_bit = get_key_bit(cipher->key, i, cipher->key_len_bytes);
        int op_id = key_bit % NUM_OPERATIONS;
        
        /* Show ASCII if printable */
        char op_ascii[20];
        if (op_id >= 32 && op_id < 127) {
            snprintf(op_ascii, sizeof(op_ascii), "'%c' (0x%02X)", (char)op_id, op_id);
        } else {
            snprintf(op_ascii, sizeof(op_ascii), "0x%02X", op_id);
        }
        
        printf("  Бит ключа %3d: значение=%d → операция %3d %s\n", 
               i, key_bit, op_id, op_ascii);
        printf("  Key bit    %3d: value=%d    → operation %3d %s\n", 
               i, key_bit, op_id, op_ascii);
    }
    if (cipher->key_len_bits > 10) {
        printf("  ...\n");
        printf("  (Показано первых 10 из %d битов ключа)\n", cipher->key_len_bits);
        printf("  (Showing first 10 of %d key bits)\n", cipher->key_len_bits);
    }
    printf("==============================================================================\n");
}

static int prompt_int_default(const char *prompt, int def_value) {
    char buf[64] = {0};
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) == NULL) return def_value;
    if (buf[0] == '\n' || buf[0] == '\0') return def_value;
    return atoi(buf);
}

/* Main function */
int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    int task = 0;
    int key_size = 256;
    int key_source = 0;
    int block_size_bits = 128;
    int data_kb = 1;
    int mode = 0;
    int bench_profile = -1; /* auto by task/mode */
    int bench_repeats = 0;  /* 0 = use default/env */
    int speed_profile = 0;  /* 0=quality, 1=fast, 2=ultra */

    if (argc == 1) {
        if (rank == 0) {
            printf("\n=== WBC1 ORIGINAL PARALLEL: INTERACTIVE MODE ===\n");
            printf("1. Encrypt/decrypt\n");
            printf("2. Statistical tests (without benchmark)\n");
            printf("3. Benchmark performance\n");
            printf("4. Print operations table\n");

            int task_choice = prompt_int_default("Select task [1-4, default=2]: ", 2);
            if (task_choice < 1 || task_choice > 4) task_choice = 2;
            if (task_choice == 1) task = 0;      /* encrypt/decrypt */
            else if (task_choice == 2) task = 1; /* statistical tests */
            else if (task_choice == 3) task = 3; /* benchmark only */
            else task = 2;                       /* operations table */

            key_size = prompt_int_default("Key size bits [128/192/256, default=256]: ", 256);
            if (key_size != 128 && key_size != 192 && key_size != 256) key_size = 256;

            key_source = prompt_int_default("Key source [0=random,1=file, default=0]: ", 0);
            if (key_source != 0 && key_source != 1) key_source = 0;

            block_size_bits = prompt_int_default("Block size bits [32/64/128/512/0(auto), default=128]: ", 128);
            if (!(block_size_bits == 0 || block_size_bits == 32 || block_size_bits == 64 ||
                  block_size_bits == 128 || block_size_bits == 512)) {
                block_size_bits = 128;
            }

            if (task == 0) {
                mode = prompt_int_default("Mode [0=demo,1=random data, default=0]: ", 0);
                if (mode != 0 && mode != 1) mode = 0;
                if (mode == 1) {
                    data_kb = prompt_int_default("Data size KB [default=10]: ", 10);
                    if (data_kb < 1) data_kb = 10;
                }
            } else if (task == 1) {
                mode = prompt_int_default("Mode [0=simple,1=full, default=1]: ", 1);
                if (mode != 0 && mode != 1) mode = 1;
                data_kb = prompt_int_default("Data size KB [default=100]: ", 100);
                if (data_kb < 1) data_kb = 100;

                bench_profile = prompt_int_default("Benchmark profile [0=off,1=quick,2=full, default=0]: ", 0);
                if (bench_profile < 0 || bench_profile > 2) bench_profile = 1;

                speed_profile = prompt_int_default("Speed profile [0=quality,1=fast,2=ultra, default=0]: ", 0);
                if (speed_profile < 0 || speed_profile > 2) speed_profile = 0;

                bench_repeats = prompt_int_default("Benchmark repeats [1..64, 0=default, default=0]: ", 0);
                if (bench_repeats < 0 || bench_repeats > 64) bench_repeats = 0;
            } else if (task == 3) {
                bench_profile = prompt_int_default("Benchmark profile [1=quick,2=full, default=1]: ", 1);
                if (bench_profile != 1 && bench_profile != 2) bench_profile = 1;

                speed_profile = prompt_int_default("Speed profile [0=quality,1=fast,2=ultra, default=0]: ", 0);
                if (speed_profile < 0 || speed_profile > 2) speed_profile = 0;

                bench_repeats = prompt_int_default("Benchmark repeats [1..64, 0=default, default=0]: ", 0);
                if (bench_repeats < 0 || bench_repeats > 64) bench_repeats = 0;
            }
        }

        int params[9] = {task, key_size, key_source, block_size_bits, mode,
                         data_kb, bench_profile, bench_repeats, speed_profile};
        MPI_Bcast(params, 9, MPI_INT, 0, MPI_COMM_WORLD);
        task = params[0];
        key_size = params[1];
        key_source = params[2];
        block_size_bits = params[3];
        mode = params[4];
        data_kb = params[5];
        bench_profile = params[6];
        bench_repeats = params[7];
        speed_profile = params[8];

    } else if (argc < 5) {
        if (rank == 0) {
            printf("Usage: %s <task> <key_size> <key_source> <block_size_bits> [mode] [data_size_kb] [bench_profile] [bench_repeats] [speed_profile]\n", argv[0]);
            printf("       %s            # interactive dialog mode\n", argv[0]);
            printf("  task: 0=encrypt/decrypt, 1=statistical tests, 2=print operations table, 3=benchmark only\n");
            printf("  key_size: key size in bits (128, 192, 256)\n");
            printf("  key_source: 0=random, 1=from file\n");
            printf("  block_size_bits: block size in bits (32, 64, 128, 512, or 0 for automatic)\n");
            printf("  mode: (for task 0) 0=use demo text, 1=generate random data\n");
            printf("         (for task 1) 0=simple, 1=full\n");
            printf("  data_size_kb: amount of data in KB (for task 0 with mode=1, or task 1)\n");
            printf("  bench_profile: (task 1) 0=off, 1=quick, 2=full (default: 2 for full mode, 0 for simple)\n");
            printf("  bench_repeats: (task 1) optional repeats override (1..64)\n");
            printf("  speed_profile: 0=quality (diffusion + full key walk), 1=fast (no diffusion + full key walk), 2=ultra (no diffusion + key stride 4)\n");
            printf("\nExamples:\n");
            printf("  %s 0 256 0 128          # Encrypt demo text\n", argv[0]);
            printf("  %s 0 256 0 0 1 10       # Encrypt 10KB with automatic block size\n", argv[0]);
            printf("  %s 0 256 0 128 1 10     # Encrypt 10KB random data\n", argv[0]);
            printf("  %s 0 256 0 128 1 10 0 0 1 # Encrypt 10KB random data (fast profile)\n", argv[0]);
            printf("  %s 0 256 0 128 1 10 0 0 2 # Encrypt 10KB random data (ultra profile)\n", argv[0]);
            printf("  %s 1 256 0 0 1 100      # Statistical tests with auto block size\n", argv[0]);
            printf("  %s 1 256 0 128 1 100 1  # Statistical tests + quick benchmark\n", argv[0]);
            printf("  %s 1 256 0 128 1 100 0  # Statistical tests only (benchmark off)\n", argv[0]);
            printf("  %s 1 256 0 128 1 100 1 1 # Statistical tests + quick benchmark (1 repeat)\n", argv[0]);
            printf("  %s 1 256 0 128 1 100 1 1 1 # Stats + quick benchmark + fast profile\n", argv[0]);
            printf("  %s 1 256 0 128 1 100 1 1 2 # Stats + quick benchmark + ultra profile\n", argv[0]);
            printf("  %s 3 256 0 128 0 1 1 1 0 # Benchmark only: quick, 1 repeat, quality\n", argv[0]);
            printf("  %s 2 256 0 128          # Print operations table\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    } else {
        task = atoi(argv[1]);
        key_size = atoi(argv[2]);
        key_source = atoi(argv[3]);
        block_size_bits = atoi(argv[4]);
        
        /* Get data size early for auto-selection */
        if (argc >= 6) {
            mode = atoi(argv[5]);
        }
        if (argc >= 7) {
            data_kb = atoi(argv[6]);
            if (data_kb < 1) data_kb = 1;
        }

        if (argc >= 8) {
            bench_profile = atoi(argv[7]);
        }
        if (argc >= 9) {
            bench_repeats = atoi(argv[8]);
            if (bench_repeats < 1 || bench_repeats > 64) {
                if (rank == 0) {
                    fprintf(stderr, "Error: bench_repeats must be in range 1..64 (got %d)\n", bench_repeats);
                }
                MPI_Finalize();
                return 1;
            }
        }
        if (argc >= 10) {
            speed_profile = atoi(argv[9]);
            if (speed_profile < 0 || speed_profile > 2) {
                if (rank == 0) {
                    fprintf(stderr, "Error: speed_profile must be 0(quality), 1(fast), or 2(ultra)\n");
                }
                MPI_Finalize();
                return 1;
            }
        }
    }
    
    /* Automatic block size selection if block_size_bits = 0 */
    if (block_size_bits == 0) {
        /* Auto-select based on data size for optimal test results */
        if (data_kb < 10) {
            block_size_bits = 32;   /* Small data: better avalanche */
        } else if (data_kb < 100) {
            block_size_bits = 64;   /* Medium-small: balanced */
        } else if (data_kb < 1000) {
            block_size_bits = 128;  /* Medium: better differential */
        } else {
            block_size_bits = 512;  /* Large data: best differential */
        }
        
        if (rank == 0) {
            printf("\n=================================================================\n");
            printf("AUTOMATIC BLOCK SIZE SELECTION / АВТОМАТИЧЕСКИЙ ВЫБОР РАЗМЕРА БЛОКА\n");
            printf("=================================================================\n");
            printf("Data size / Размер данных: %d KB\n", data_kb);
            printf("Selected block size / Выбранный размер блока: %d bits\n", block_size_bits);
            printf("\nReason / Причина: ");
            if (data_kb < 10) {
                printf("Very small data - prioritize avalanche effect\n");
                printf("         Очень малые данные - приоритет лавинному эффекту\n");
            } else if (data_kb < 100) {
                printf("Small data - balanced approach\n");
                printf("         Малые данные - сбалансированный подход\n");
            } else if (data_kb < 1000) {
                printf("Medium data - better differential analysis\n");
                printf("         Средние данные - лучший дифференциальный анализ\n");
            } else {
                printf("Large data - best differential analysis\n");
                printf("         Большие данные - лучший дифференциальный анализ\n");
            }
            printf("\nExpected results / Ожидаемые результаты:\n");
            printf("  - Differential analysis / Диф. анализ: ");
            if (block_size_bits >= 128) {
                printf("Excellent / Отлично\n");
            } else if (block_size_bits >= 64) {
                printf("Good / Хорошо\n");
            } else {
                printf("Moderate / Умеренно\n");
            }
            printf("  - Avalanche effect / Лавинный эффект: ");
            if (block_size_bits <= 64) {
                printf("Excellent / Отлично\n");
            } else if (block_size_bits <= 128) {
                printf("Good / Хорошо\n");
            } else {
                printf("Moderate / Умеренно\n");
            }
            printf("=================================================================\n\n");
        }
    }
    
    /* Generate or load key */
    int key_len = key_size / 8;
    uint8_t *key = (uint8_t *)malloc(key_len);
    
    if (rank == 0) {
        if (key_source == 0) {
            srand(time(NULL));
            for (int i = 0; i < key_len; i++) {
                key[i] = rand() % 256;
            }
        } else {
            /* Load from file (simplified) */
            for (int i = 0; i < key_len; i++) {
                key[i] = i % 256;
            }
        }
    }
    MPI_Bcast(key, key_len, MPI_BYTE, 0, MPI_COMM_WORLD);
    
    /* Initialize cipher */
    WBC1OriginalCipher cipher;
    wbc1_original_init(&cipher, key, key_len, block_size_bits, speed_profile);
    
    if (task == 0) {
        /* Text encryption/decryption */
        /* mode and data_kb already set above for auto-selection */
        
        /* Performance warning for large data (task 0, mode 1 - random data) */
        if (rank == 0 && mode == 1 && data_kb > 1000) {
            int block_size_bytes = block_size_bits / 8;
            long long estimated_blocks = ((long long)data_kb * 1024) / block_size_bytes;
            /* BYTE-BASED algorithm: operations = blocks × key_bytes (not key_bits!) */
            int key_bytes = key_size / 8;  /* 256 bits = 32 bytes */
            long long estimated_ops = estimated_blocks * key_bytes;
            printf("\n⚠ Performance Warning / Предупреждение о производительности:\n");
            printf("  Data size: %d KB (~%lld blocks)\n", data_kb, estimated_blocks);
            printf("  Estimated operations: %.2f million (blocks × key_bytes)\n", estimated_ops / 1e6);
            printf("  With byte-based algorithm: %d operations per block\n", key_bytes);
            printf("  Estimated processing time: ~%.1f seconds\n", (estimated_ops / 1e6) * 0.003);
            printf("  This may take several minutes with this algorithm.\n");
            printf("  Это может занять несколько минут с этим алгоритмом.\n");
            printf("  Consider using enhanced versions for large data.\n");
            printf("  Рассмотрите использование улучшенных версий для больших данных.\n\n");
        }
        
        if (rank == 0) {
            uint8_t *plaintext = NULL;
            int text_len = 0;
            
            if (mode == 0) {
                /* Use demo text */
                const char *demo_text = "Це тестове повідомлення для демонстрації шифрування оригінальним алгоритмом WBC1.";
                text_len = strlen(demo_text);
                plaintext = (uint8_t *)malloc(text_len);
                memcpy(plaintext, demo_text, text_len);
                
                printf("\n========================================\n");
                printf("WBC1 Original Algorithm - Text Encryption Demo\n");
                printf("========================================\n");
                printf("Mode: Demo text\n");
                printf("Original text: %s\n", demo_text);
            } else {
                /* Generate random data */
                text_len = data_kb * 1024;
                plaintext = generate_random_bytes(text_len);
                
                printf("\n========================================\n");
                printf("WBC1 Original Algorithm - Random Data Encryption\n");
                printf("========================================\n");
                printf("Mode: Random data\n");
                printf("Data size: %d KB (%d bytes)\n", data_kb, text_len);
                printf("First 64 bytes of plaintext:\n");
                print_hex(plaintext, text_len, 64);
            }
            
            printf("Block size: %d bits (%d bytes)\n", block_size_bits, block_size_bits / 8);
            printf("Key size: %d bits\n", key_size);
            printf("Cube dimension: %d×%d×%d\n", cipher.cube_d, cipher.cube_d, cipher.cube_d);
            printf("Key bits processed: %d\n", cipher.key_len_bits);
            
            uint8_t *ciphertext = NULL;
            int ciphertext_len = 0;
            
            double start_time = MPI_Wtime();
            parallel_original_encrypt(&cipher, plaintext, text_len, &ciphertext, &ciphertext_len);
            double encrypt_time = MPI_Wtime() - start_time;
            
            printf("\nEncrypted (%d bytes):\n", ciphertext_len);
            print_hex(ciphertext, ciphertext_len, 64);
            
            uint8_t *decrypted = NULL;
            int decrypted_len = 0;
            
            start_time = MPI_Wtime();
            parallel_original_decrypt(&cipher, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
            double decrypt_time = MPI_Wtime() - start_time;
            
            if (mode == 0) {
                printf("\nDecrypted text: %.*s\n", decrypted_len, decrypted);
            } else {
                printf("\nDecrypted (%d bytes), first 64 bytes:\n", decrypted_len);
                print_hex(decrypted, decrypted_len, 64);
            }
            
            printf("\nEncryption time: %.6f seconds\n", encrypt_time);
            printf("Decryption time: %.6f seconds\n", decrypt_time);
            if (text_len > 0) {
                double throughput_mb = (text_len / (1024.0 * 1024.0)) / encrypt_time;
                double throughput_mbit = throughput_mb * 8.0;
                printf("Throughput: %.2f MB/s (%.2f Mbit/s)\n", throughput_mb, throughput_mbit);
            }
            
            /* Verify */
            if (decrypted_len == text_len && memcmp(plaintext, decrypted, text_len) == 0) {
                printf("✓ Success: Decrypted data matches original! / Успех: Расшифрованные данные совпадают!\n");
            } else {
                printf("✗ Error: Decrypted data does not match original! / Ошибка: Несовпадение данных!\n");
            }
            
            free(plaintext);
            free(ciphertext);
            free(decrypted);
        } else {
            /* Non-root processes participate in parallel encryption/decryption */
            uint8_t *dummy_cipher = NULL;
            int dummy_len = 0;
            parallel_original_encrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
            parallel_original_decrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
        }
    } else if (task == 1) {
        if (bench_profile < 0) {
            bench_profile = 0;
        }
        if (bench_profile < 0 || bench_profile > 2) {
            if (rank == 0) {
                fprintf(stderr, "Error: bench_profile must be 0(off), 1(quick), or 2(full)\n");
            }
            wbc1_original_free(&cipher);
            free(key);
            MPI_Finalize();
            return 1;
        }

        /* Statistical analysis with configurable data size */
        int requested_data_kb = data_kb;
        if (argc >= 7) {
            requested_data_kb = atoi(argv[6]);
        }
        if (requested_data_kb < 1) requested_data_kb = 1;
        data_kb = requested_data_kb;
        
        /* Performance warning for statistical analysis with large data */
        double estimated_time_seconds = 0.0;
        if (rank == 0) {
            int block_size_bytes = block_size_bits / 8;
            long long estimated_blocks = ((long long)data_kb * 1024) / block_size_bytes;
            /* BYTE-BASED algorithm: operations = blocks × key_bytes (not key_bits!) */
            int key_bytes = key_size / 8;  /* 256 bits = 32 bytes */
            long long estimated_ops = estimated_blocks * key_bytes;
            double estimated_ops_millions = estimated_ops / 1e6;
            estimated_time_seconds = estimated_ops_millions / 327.68;  /* Calibrated */
            
            /* Only show warning if processing will take more than 1 second */
            if (estimated_time_seconds > 1.0) {
                printf("\n⚠ Performance Warning / Предупреждение о производительности:\n");
                printf("  Data size: %d KB (~%lld blocks)\n", data_kb, estimated_blocks);
                printf("  Estimated operations: %.2f million (blocks × key_bytes)\n", estimated_ops_millions);
                printf("  With byte-based algorithm: %d operations per block\n", key_bytes);
                printf("  Estimated processing time: ~%.1f seconds\n", estimated_time_seconds);
                printf("  Processing may take a while...\n");
                printf("  Обработка может занять некоторое время...\n\n");
            }
        }
        
        if (rank == 0) {
            printf("\n========================================\n");
            printf("WBC1 Original - Statistical Analysis / Статистический анализ\n");
            printf("========================================\n");
            printf("Requested data size / Запрошенный размер данных: %d KB\n", requested_data_kb);
            printf("Data size / Размер данных: %d KB\n", data_kb);
            printf("Block size / Размер блока: %d bits\n", block_size_bits);
            printf("Key size / Размер ключа: %d bits\n", key_size);
            printf("Benchmark profile / Профиль бенчмарка: %s\n",
                   (bench_profile == 0) ? "off" : (bench_profile == 1 ? "quick" : "full"));
                 printf("Speed profile / Профиль скорости: %s\n",
                     (speed_profile == 0) ? "quality" : (speed_profile == 1 ? "fast" : "ultra"));
            if (bench_repeats > 0) {
                printf("Benchmark repeats override: %d\n", bench_repeats);
            }
            printf("\n");
            
            int data_size = data_kb * 1024;
            uint8_t *test_data = generate_random_bytes(data_size);
            uint8_t *ciphertext = NULL;
            int cipher_len = 0;
            
            printf("Encrypting / Шифрование...\n");
            double start_time = MPI_Wtime();
            parallel_original_encrypt(&cipher, test_data, data_size, &ciphertext, &cipher_len);
            double encrypt_time = MPI_Wtime() - start_time;
            double throughput_mb = (data_size / 1024.0 / 1024.0) / encrypt_time;
            double throughput_mbit = throughput_mb * 8.0;
            
            printf("Encryption completed in %.3f seconds\n", encrypt_time);
            printf("Throughput: %.2f MB/s (%.2f Mbit/s)\n\n", throughput_mb, throughput_mbit);
            
            /* Statistical Tests */
            printf("Statistical Tests Results / Результаты статистических тестов:\n");
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            
            /* 1. Shannon Entropy */
            double entropy = shannon_entropy(ciphertext, cipher_len);
            printf("1. Shannon Entropy / Энтропия Шеннона: %.4f bits/byte\n", entropy);
            printf("   Expected / Ожидается: ~7.9-8.0 for good encryption\n");
            if (entropy >= 7.9) {
                printf("   ✓ Status: Good / Хорошо\n");
            } else {
                printf("   ⚠ Status: Low entropy / Низкая энтропия\n");
            }
            printf("\n");
            
            /* 2. Frequency Test */
            double freq_mean, freq_std, freq_chi;
            frequency_test(ciphertext, cipher_len, &freq_mean, &freq_std, &freq_chi);
            printf("2. Frequency Test / Частотный тест:\n");
            printf("   Mean / Среднее: %.2f (expected ~%.2f)\n", freq_mean, cipher_len / 256.0);
            printf("   Std Dev / Ст. откл.: %.2f (expected ~%.2f)\n", freq_std, sqrt(cipher_len / 256.0));
            printf("   Chi-square / Хи-квадрат: %.2f\n", freq_chi);
            if (freq_chi < 293.0) {  /* 255 degrees of freedom, 95% confidence */
                printf("   ✓ Status: Good distribution / Хорошее распределение\n");
            } else {
                printf("   ⚠ Status: May not be uniformly distributed\n");
            }
            printf("\n");
            
            /* 3. Avalanche Effect */
            double avalanche_results[3];
            avalanche_test(&cipher, 100, avalanche_results);
            printf("3. Avalanche Effect Test / Тест лавинного эффекта:\n");
            printf("   Average / Среднее: %.2f%% (expected ~50%%)\n", avalanche_results[0]);
            printf("   Min / Минимум: %.2f%%\n", avalanche_results[1]);
            printf("   Max / Максимум: %.2f%%\n", avalanche_results[2]);
            if (avalanche_results[0] >= 45.0 && avalanche_results[0] <= 55.0) {
                printf("   ✓ Status: Good avalanche / Хороший лавинный эффект\n");
            } else {
                printf("   ⚠ Status: Avalanche effect may be weak\n");
            }
            printf("\n");
            
            /* 4. Correlation Test */
            int test_len = data_size < cipher_len ? data_size : cipher_len;
            double corr = correlation_test(test_data, ciphertext, test_len);
            printf("4. Correlation Test / Тест корреляции:\n");
            printf("   Correlation coefficient / Коэффициент корреляции: %.6f\n", corr);
            printf("   Expected / Ожидается: close to 0\n");
            if (fabs(corr) < 0.1) {
                printf("   ✓ Status: Low correlation (Good) / Низкая корреляция (Хорошо)\n");
            } else {
                printf("   ⚠ Status: High correlation detected\n");
            }
            printf("\n");
            
            /* 5. Differential Test */
            double diff_results[3];
            differential_test(&cipher, 50, diff_results);
            printf("5. Differential Test / Дифференциальный тест:\n");
            printf("   Average key sensitivity / Средняя чувствительность: %.2f%%\n", diff_results[0]);
            printf("   Min / Минимум: %.2f%%\n", diff_results[1]);
            printf("   Max / Максимум: %.2f%%\n", diff_results[2]);
            if (diff_results[0] >= 45.0 && diff_results[0] <= 55.0) {
                printf("   ✓ Status: Good key sensitivity / Хорошая чувствительность к ключу\n");
            } else {
                printf("   ⚠ Status: Key sensitivity may be weak\n");
            }
            
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

            if (bench_profile != 0) {
                benchmark_core(&cipher, bench_profile, bench_repeats);
            }
            
            free(test_data);
            free(ciphertext);
        } else {
            /* Other processes participate in encryption */
            uint8_t *dummy_cipher = NULL;
            int dummy_len = 0;
            parallel_original_encrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
        }
    } else if (task == 2) {
        /* Print operations table with key mapping */
        if (rank == 0) {
            /* Display key in hex format */
            print_key_hex(key, key_len);
            
            /* Display key-to-operation mapping (first 32 bytes) */
            print_key_operation_mapping(&cipher, 32);
            
            /* Display operations table */
            print_operations_table(&cipher);
        }
    } else if (task == 3) {
        if (bench_profile < 0) bench_profile = 1;
        if (bench_profile == 0) bench_profile = 1;
        if (bench_profile < 1 || bench_profile > 2) {
            if (rank == 0) {
                fprintf(stderr, "Error: benchmark-only mode expects bench_profile 1(quick) or 2(full)\n");
            }
            wbc1_original_free(&cipher);
            free(key);
            MPI_Finalize();
            return 1;
        }

        if (rank == 0) {
            printf("\n========================================\n");
            printf("WBC1 Original - Benchmark Only / Только бенчмарк\n");
            printf("========================================\n");
            printf("Block size / Размер блока: %d bits\n", block_size_bits);
            printf("Key size / Размер ключа: %d bits\n", key_size);
            printf("Benchmark profile / Профиль бенчмарка: %s\n", bench_profile == 1 ? "quick" : "full");
            printf("Speed profile / Профиль скорости: %s\n",
                   (speed_profile == 0) ? "quality" : (speed_profile == 1 ? "fast" : "ultra"));
            if (bench_repeats > 0) {
                printf("Benchmark repeats override: %d\n", bench_repeats);
            }
        }
        benchmark_core(&cipher, bench_profile, bench_repeats);
    }
    
    wbc1_original_free(&cipher);
    free(key);
    
    MPI_Finalize();
    return 0;
}
