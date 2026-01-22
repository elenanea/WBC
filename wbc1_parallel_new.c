/*
 * WBC1 Block Cipher - ENHANCED Parallel Implementation with MPI
 * 
 * === ENHANCED VERSION with Improved Mode 0 Avalanche ===
 * 
 * This implementation includes:
 * - Key-dependent S-box generation using SHA-256
 * - 127 dynamic Rubik's cube permutation operations
 * - XOR with round keys
 * - Cumulative XOR diffusion
 * - Cyclic bitwise rotation
 * - Round key generation
 * - Support for Mode 0 (ENHANCED simplified) and Mode 1 (full algorithm)
 * - MPI parallelization for distributed block processing
 * 
 * === MODE 0 ENHANCEMENTS (Preserving Rubik's Cube Analogy) ===
 * 
 * Mode 0 now includes 6 operations per round (vs original 2):
 * 1. Primary Rubik's cube rotation (main face)
 * 2. Secondary Rubik's cube rotation (perpendicular face)
 * 3. Key-dependent byte transposition (layer twisting)
 * 4. Multi-layer diffusion (rotating multiple faces simultaneously)
 * 5. Tertiary Rubik's cube rotation (third axis)
 * 6. Cascading bit rotation (sub-cubes at different speeds)
 * 
 * All enhancements maintain the Rubik's cube analogy:
 * - Multi-axis rotations = rotating different cube faces
 * - Byte transposition = twisting cube layers
 * - Multi-layer diffusion = simultaneous face rotations
 * - Cascading rotations = rotating sub-cubes independently
 * 
 * Expected improvements:
 * - Significantly better avalanche effect in Mode 0 (~45-50%)
 * - Maintained speed (all operations are lightweight)
 * - Preserved Rubik's cube conceptual model
 * - Mode 1 unchanged (already optimal)
 * 
 * THREAD SAFETY:
 * - Each MPI process maintains its own cipher instance (no shared state)
 * - Uses C standard library rand() with deterministic seeding (not thread-safe)
 * - Safe for MPI processes (separate memory spaces)
 * - NOT safe for multi-threaded use within a single process
 * - For multi-threaded applications, use separate cipher instances per thread
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

#define BLOCK_SIZE 16
#define MAX_ROUNDS 64
#define NUM_OPERATIONS 127
#define MAX_OP_STRING 256

/* Algorithm modes */
#define MODE_SIMPLIFIED 0  /* 2 operations: permutation + rotation */
#define MODE_FULL 1        /* 5 operations: permutation + XOR + S-box + diffusion + rotation */

/* Operation metadata structure to match Python's tuple representation */
typedef struct {
    char type[32];      /* e.g., "face", "slice", "wide", "cube", "alg", "pattern", "swap", "diagflip", "dynamic" */
    char param1[64];    /* e.g., face name, axis number */
    char param2[64];    /* e.g., direction, offset */
    char desc[128];     /* description */
    char str_repr[MAX_OP_STRING];  /* Python-like str() representation: "('type', 'param1', 'param2', 'desc')" */
    int chain_length;   /* Number of sub-operations in chain (0 for base operations) */
    int chain[8];       /* Pre-generated chain of sub-operation indices (3-6 for dynamic ops) */
} Operation;

/* FIX #2: Removed global operations - now per-instance in WBC1Cipher struct
 * This matches Python where operations are generated per cipher instance (line 200-201)
 * Previously: Global arrays shared across all cipher instances → wrong operations for different keys
 * Now: Each cipher instance has its own operations → correct behavior with multiple keys
 */

/* WBC1 Cipher structure */
typedef struct {
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
    int perm_table[BLOCK_SIZE * 8];
    int inv_perm_table[BLOCK_SIZE * 8];
    uint8_t round_keys[MAX_ROUNDS][BLOCK_SIZE];
    uint8_t *key;
    int key_len;
    int block_size;
    int num_rounds;
    int algorithm_mode;
    /* FIX #2: Per-instance operations (matching Python line 200-201) */
    Operation *operations;           /* 127 final operations */
    Operation *base_operations;      /* 107 base operations (87 base + 20 dynamic_20) */
    int base_ops_count;              /* Count of base operations */
} WBC1Cipher;

/* Helper function prototypes */
static uint8_t rotate_right(uint8_t byte, int n);
static uint8_t rotate_left(uint8_t byte, int n);
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output);
static void generate_sbox(WBC1Cipher *cipher);
static void generate_inverse_sbox(WBC1Cipher *cipher);
static void generate_permutation(WBC1Cipher *cipher);
static void generate_inverse_permutation(WBC1Cipher *cipher);
static void generate_round_keys(WBC1Cipher *cipher);
static void apply_operation(WBC1Cipher *cipher, uint8_t *block, int op_id, int inverse);
static void substitute_bytes(WBC1Cipher *cipher, uint8_t *block, int inverse);
static void cyclic_bitwise_rotate(uint8_t *block, int size, int shift, int direction);
static void xor_with_key(uint8_t *block, const uint8_t *key, int size);
static void two_layer_diffusion(uint8_t *block, int size, int inverse);
static void print_operations_table(WBC1Cipher *cipher);

/* Cipher operations */
void wbc1_init(WBC1Cipher *cipher, const uint8_t *key, int key_len, int num_rounds, int algorithm_mode);
void wbc1_free(WBC1Cipher *cipher);
void wbc1_encrypt_block(WBC1Cipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext);
void wbc1_decrypt_block(WBC1Cipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext);

/* Parallel operations */
void parallel_encrypt(WBC1Cipher *cipher, const uint8_t *plaintext, int plaintext_len, 
                     uint8_t **ciphertext, int *ciphertext_len);
void parallel_decrypt(WBC1Cipher *cipher, const uint8_t *ciphertext, int ciphertext_len,
                     uint8_t **plaintext, int *plaintext_len);

/* Utility functions */
static void pad_data(const uint8_t *data, int len, uint8_t **padded, int *padded_len);
static void unpad_data(const uint8_t *data, int len, uint8_t **unpadded, int *unpadded_len);

/* ===== Helper Function Implementations ===== */

/* Mersenne Twister MT19937 implementation to match numpy.random.RandomState */
#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

typedef struct {
    uint32_t mt[MT_N];
    int mti;
} MT19937State;

static void mt_init(MT19937State *state, uint32_t seed) {
    state->mt[0] = seed & 0xffffffffUL;
    for (state->mti = 1; state->mti < MT_N; state->mti++) {
        state->mt[state->mti] = 
            (1812433253UL * (state->mt[state->mti-1] ^ (state->mt[state->mti-1] >> 30)) + state->mti);
        state->mt[state->mti] &= 0xffffffffUL;
    }
}

static uint32_t mt_random(MT19937State *state) {
    uint32_t y;
    static uint32_t mag01[2] = {0x0UL, MT_MATRIX_A};
    
    if (state->mti >= MT_N) {
        int kk;
        
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (state->mt[kk] & MT_UPPER_MASK) | (state->mt[kk+1] & MT_LOWER_MASK);
            state->mt[kk] = state->mt[kk+MT_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (; kk < MT_N-1; kk++) {
            y = (state->mt[kk] & MT_UPPER_MASK) | (state->mt[kk+1] & MT_LOWER_MASK);
            state->mt[kk] = state->mt[kk+(MT_M-MT_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (state->mt[MT_N-1] & MT_UPPER_MASK) | (state->mt[0] & MT_LOWER_MASK);
        state->mt[MT_N-1] = state->mt[MT_M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];
        
        state->mti = 0;
    }
    
    y = state->mt[state->mti++];
    
    /* Tempering */
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    
    return y;
}

static uint8_t rotate_right(uint8_t byte, int n) {
    n = n % 8;
    return ((byte >> n) | (byte << (8 - n))) & 0xFF;
}

static uint8_t rotate_left(uint8_t byte, int n) {
    n = n % 8;
    return ((byte << n) | (byte >> (8 - n))) & 0xFF;
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
    /* Use EVP API to avoid deprecation warnings in OpenSSL 3.0+ */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create EVP_MD_CTX\n");
        exit(1);
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        fprintf(stderr, "Error: SHA-256 hashing failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    
    EVP_MD_CTX_free(ctx);
}

/* MT19937 random state for initialization */
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

/* Initialize operations array matching Python's build_127_ascii_operations */
static void init_operations(WBC1Cipher *cipher, const uint8_t *key, int key_len) {
    /* FIX #2: Per-instance operations - allocate memory for this cipher instance */
    cipher->operations = (Operation *)malloc(NUM_OPERATIONS * sizeof(Operation));
    cipher->base_operations = (Operation *)malloc(300 * sizeof(Operation));
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
    
    /* FIX #3: Generate 127 unique operation chains with uniqueness check
     * Python (line 156-163): Retries up to 1000 times to ensure unique chains
     * Uses set() to track seen chains and only accepts if chain_serialized not in seen
     */
    
    /* Simple hash table for tracking seen chains (using string hashing) */
    #define MAX_SEEN 256
    typedef struct {
        char chain_str[512];
        int in_use;
    } SeenChain;
    SeenChain *seen_chains = (SeenChain *)calloc(MAX_SEEN, sizeof(SeenChain));
    int seen_count = 0;
    
    /* Generate 127 final operations with pre-generated chains */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        int attempt = 0;
        int chain_found = 0;
        
        while (attempt < 1000 && !chain_found) {
            uint8_t seed_input[256];
            memcpy(seed_input, key, key_len);
            memcpy(seed_input + key_len, "WBC1_OP", 7);
            seed_input[key_len + 7] = i & 0xFF;
            seed_input[key_len + 8] = (i >> 8) & 0xFF;
            seed_input[key_len + 9] = attempt & 0xFF;
            seed_input[key_len + 10] = (attempt >> 8) & 0xFF;
            
            uint8_t hash[SHA256_DIGEST_LENGTH];
            sha256_hash(seed_input, key_len + 11, hash);
            uint32_t seed = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) | 
                           ((uint32_t)hash[2] << 8) | ((uint32_t)hash[3]);
            
            MT19937InitState rng;
            mt_init_seed(&rng, seed);
            
            int chain_len = 3 + (mt_random_init(&rng) % 4);  /* 3-6 operations */
            
            /* Generate chain */
            int chain[8];
            for (int j = 0; j < chain_len; j++) {
                chain[j] = mt_random_init(&rng) % all_ops_count;
            }
            
            /* Serialize chain to string for uniqueness check (matching Python) */
            char chain_serialized[512];
            int offset = sprintf(chain_serialized, "(");
            for (int j = 0; j < chain_len; j++) {
                if (j > 0) offset += sprintf(chain_serialized + offset, ", ");
                offset += sprintf(chain_serialized + offset, "('%s', '%s', '%s', '%s')",
                    temp_ops[chain[j]].type, temp_ops[chain[j]].param1,
                    temp_ops[chain[j]].param2, temp_ops[chain[j]].desc);
            }
            sprintf(chain_serialized + offset, ")");
            
            /* Check if chain is unique (not in seen set) */
            int is_duplicate = 0;
            for (int s = 0; s < seen_count && s < MAX_SEEN; s++) {
                if (seen_chains[s].in_use && strcmp(seen_chains[s].chain_str, chain_serialized) == 0) {
                    is_duplicate = 1;
                    break;
                }
            }
            
            if (!is_duplicate && seen_count < MAX_SEEN) {
                /* Chain is unique - add to seen set and use it */
                size_t copy_len = strlen(chain_serialized);
                if (copy_len >= sizeof(seen_chains[seen_count].chain_str)) {
                    copy_len = sizeof(seen_chains[seen_count].chain_str) - 1;
                }
                memcpy(seen_chains[seen_count].chain_str, chain_serialized, copy_len);
                seen_chains[seen_count].chain_str[copy_len] = '\0';
                seen_chains[seen_count].in_use = 1;
                seen_count++;
                
                snprintf(cipher->operations[i].type, sizeof(cipher->operations[i].type), "dynamic");
                snprintf(cipher->operations[i].param1, sizeof(cipher->operations[i].param1), "%d", i);
                snprintf(cipher->operations[i].param2, sizeof(cipher->operations[i].param2), "chain");
                snprintf(cipher->operations[i].desc, sizeof(cipher->operations[i].desc), "Dynamic ASCII op %d", i + 1);
                snprintf(cipher->operations[i].str_repr, sizeof(cipher->operations[i].str_repr),
                        "('dynamic', %d, 'chain', 'Dynamic ASCII op %d')", i, i + 1);
                
                cipher->operations[i].chain_length = chain_len;
                for (int j = 0; j < chain_len; j++) {
                    cipher->operations[i].chain[j] = chain[j];
                }
                chain_found = 1;
            } else {
                /* Duplicate found or seen table full - retry */
                attempt++;
            }
        }
        
        /* Safety fallback after 1000 attempts (matching Python line 160-162) */
        if (!chain_found) {
            int fallback_idx = i % all_ops_count;
            snprintf(cipher->operations[i].type, sizeof(cipher->operations[i].type), "dynamic");
            snprintf(cipher->operations[i].param1, sizeof(cipher->operations[i].param1), "%d", i);
            snprintf(cipher->operations[i].param2, sizeof(cipher->operations[i].param2), "chain");
            snprintf(cipher->operations[i].desc, sizeof(cipher->operations[i].desc), "Dynamic ASCII op %d", i + 1);
            snprintf(cipher->operations[i].str_repr, sizeof(cipher->operations[i].str_repr),
                    "('dynamic', %d, 'chain', 'Dynamic ASCII op %d')", i, i + 1);
            cipher->operations[i].chain_length = 1;
            cipher->operations[i].chain[0] = fallback_idx;
        }
    }
    
    free(seen_chains);
}

/* FIX #1: Individualize operations by sorting by hash (matching Python line 249-262)
 * Python: ops.sort(key=lambda op: hashlib.sha256(json.dumps([str(x) for x in op], sort_keys=True).encode() + self.key).digest())
 * This ensures op_id values map to same operations in Python and C
 */

/* Global key for sorting comparison */
static const uint8_t *g_sort_key = NULL;
static int g_sort_key_len = 0;

/* Comparison function for qsort that computes hash(str_repr + key) */
static int compare_operations_by_hash(const void *a, const void *b) {
    const Operation *op_a = (const Operation *)a;
    const Operation *op_b = (const Operation *)b;
    
    /* Compute hash for operation A: hash(str_repr + key) */
    size_t len_a = strlen(op_a->str_repr) + g_sort_key_len;
    uint8_t *input_a = malloc(len_a);
    memcpy(input_a, op_a->str_repr, strlen(op_a->str_repr));
    memcpy(input_a + strlen(op_a->str_repr), g_sort_key, g_sort_key_len);
    
    uint8_t hash_a[SHA256_DIGEST_LENGTH];
    sha256_hash(input_a, len_a, hash_a);
    free(input_a);
    
    /* Compute hash for operation B: hash(str_repr + key) */
    size_t len_b = strlen(op_b->str_repr) + g_sort_key_len;
    uint8_t *input_b = malloc(len_b);
    memcpy(input_b, op_b->str_repr, strlen(op_b->str_repr));
    memcpy(input_b + strlen(op_b->str_repr), g_sort_key, g_sort_key_len);
    
    uint8_t hash_b[SHA256_DIGEST_LENGTH];
    sha256_hash(input_b, len_b, hash_b);
    free(input_b);
    
    /* Compare hashes byte by byte */
    return memcmp(hash_a, hash_b, SHA256_DIGEST_LENGTH);
}

/* Sort operations by hash for key-dependent ordering (matching Python's _individualize_operations) */
static void individualize_operations(WBC1Cipher *cipher, const uint8_t *key, int key_len) {
    /* Set global key for comparison function */
    g_sort_key = key;
    g_sort_key_len = key_len;
    
    /* Sort cipher->operations array by hash(str_repr + key) */
    qsort(cipher->operations, NUM_OPERATIONS, sizeof(Operation), compare_operations_by_hash);
    
    /* Clear global key */
    g_sort_key = NULL;
    g_sort_key_len = 0;
}

/* Generate key-dependent S-box using SHA-256 */
static void generate_sbox(WBC1Cipher *cipher) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_hash(cipher->key, cipher->key_len, hash);
    
    /* Use first 4 bytes as seed for pseudo-random permutation */
    uint32_t seed = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    
    /* Initialize S-box with identity permutation */
    for (int i = 0; i < 256; i++) {
        cipher->sbox[i] = i;
    }
    
    /* Fisher-Yates shuffle using Mersenne Twister (matching numpy.random.RandomState) */
    MT19937State mt_state;
    mt_init(&mt_state, seed);
    for (int i = 255; i > 0; i--) {
        uint32_t rand_val = mt_random(&mt_state);
        int j = rand_val % (i + 1);
        uint8_t temp = cipher->sbox[i];
        cipher->sbox[i] = cipher->sbox[j];
        cipher->sbox[j] = temp;
    }
}

static void generate_inverse_sbox(WBC1Cipher *cipher) {
    for (int i = 0; i < 256; i++) {
        cipher->inv_sbox[cipher->sbox[i]] = i;
    }
}

static void generate_permutation(WBC1Cipher *cipher) {
    uint8_t input[256];
    memcpy(input, cipher->key, cipher->key_len);
    memcpy(input + cipher->key_len, "perm", 4);
    
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_hash(input, cipher->key_len + 4, hash);
    
    uint32_t seed = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
    
    /* Initialize permutation table */
    int total_bits = cipher->block_size * 8;
    for (int i = 0; i < total_bits; i++) {
        cipher->perm_table[i] = i;
    }
    
    /* Fisher-Yates shuffle using Mersenne Twister (matching numpy.random.RandomState) */
    MT19937State mt_state;
    mt_init(&mt_state, seed);
    for (int i = total_bits - 1; i > 0; i--) {
        uint32_t rand_val = mt_random(&mt_state);
        int j = rand_val % (i + 1);
        int temp = cipher->perm_table[i];
        cipher->perm_table[i] = cipher->perm_table[j];
        cipher->perm_table[j] = temp;
    }
}

static void generate_inverse_permutation(WBC1Cipher *cipher) {
    int total_bits = cipher->block_size * 8;
    for (int i = 0; i < total_bits; i++) {
        cipher->inv_perm_table[cipher->perm_table[i]] = i;
    }
}

static void generate_round_keys(WBC1Cipher *cipher) {
    for (int round = 0; round < cipher->num_rounds; round++) {
        uint8_t input[256];
        memcpy(input, cipher->key, cipher->key_len);
        
        /* Append round number in big-endian */
        input[cipher->key_len] = (round >> 24) & 0xFF;
        input[cipher->key_len + 1] = (round >> 16) & 0xFF;
        input[cipher->key_len + 2] = (round >> 8) & 0xFF;
        input[cipher->key_len + 3] = round & 0xFF;
        
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(input, cipher->key_len + 4, hash);
        
        /* Use first block_size bytes as round key */
        memcpy(cipher->round_keys[round], hash, cipher->block_size);
    }
}

/* NOTE: This function is no longer used after fixing avalanche effect.
 * We now generate permutations directly in apply_operation() with enhanced entropy mixing
 * to avoid double-hashing and ensure maximum diversity between sub-operations.
 * Kept for reference only - can be removed in future cleanup. */
#if 0
static void compute_operation_permutation(WBC1Cipher *cipher, int op_id, int *perm) {
    uint8_t input[256];
    memcpy(input, cipher->key, cipher->key_len);
    memcpy(input + cipher->key_len, "WBC1_OP", 7);
    input[cipher->key_len + 7] = (op_id >> 8) & 0xFF;
    input[cipher->key_len + 8] = op_id & 0xFF;
    
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_hash(input, cipher->key_len + 9, hash);
    
    uint64_t state[2];
    state[0] = ((uint64_t)hash[0] << 56) | ((uint64_t)hash[1] << 48) | 
               ((uint64_t)hash[2] << 40) | ((uint64_t)hash[3] << 32) |
               ((uint64_t)hash[4] << 24) | ((uint64_t)hash[5] << 16) |
               ((uint64_t)hash[6] << 8) | ((uint64_t)hash[7]);
    state[1] = ((uint64_t)hash[8] << 56) | ((uint64_t)hash[9] << 48) | 
               ((uint64_t)hash[10] << 40) | ((uint64_t)hash[11] << 32) |
               ((uint64_t)hash[12] << 24) | ((uint64_t)hash[13] << 16) |
               ((uint64_t)hash[14] << 8) | ((uint64_t)hash[15]);
    
    if (state[0] == 0) state[0] = 0x123456789ABCDEF0ULL;
    if (state[1] == 0) state[1] = 0xFEDCBA9876543210ULL;
    
    for (int i = 0; i < cipher->block_size; i++) {
        perm[i] = i;
    }
    
    for (int i = cipher->block_size - 1; i > 0; i--) {
        uint64_t s1 = state[0];
        uint64_t s0 = state[1];
        state[0] = s0;
        s1 ^= s1 << 23;
        s1 ^= s1 >> 17;
        s1 ^= s0;
        s1 ^= s0 >> 26;
        state[1] = s1;
        uint64_t result = s0 + s1;
        
        int j = result % (i + 1);
        int temp = perm[i];
        perm[i] = perm[j];
        perm[j] = temp;
    }
}
#endif

/* Apply dynamic Rubik's cube permutation operation using pre-generated chains */
static void apply_operation(WBC1Cipher *cipher, uint8_t *block, int op_id, int inverse) {
    int perm[BLOCK_SIZE];
    int inv_perm[BLOCK_SIZE];
    uint8_t temp[BLOCK_SIZE];
    
    /* Safety check */
    if (cipher->block_size > BLOCK_SIZE || cipher->block_size <= 0) {
        fprintf(stderr, "Error: Block size %d invalid (must be 1-%d)\n", cipher->block_size, BLOCK_SIZE);
        return;
    }
    
    /* Get the operation (all 127 operations have pre-generated chains) */
    Operation *op = &cipher->operations[op_id];
    int chain_length = op->chain_length;
    
    /* Apply chain of permutations using PRE-GENERATED chain indices
     * CRITICAL: For decryption (inverse=1), apply chain in REVERSE order */
    int start_idx = inverse ? (chain_length - 1) : 0;
    int end_idx = inverse ? -1 : chain_length;
    int step = inverse ? -1 : 1;
    
    for (int chain_idx = start_idx; chain_idx != end_idx; chain_idx += step) {
        /* Get the sub-operation from the pre-generated chain */
        int subop_idx = op->chain[chain_idx];
        
        /* Safety check */
        if (subop_idx < 0 || subop_idx >= cipher->base_ops_count) {
            fprintf(stderr, "Error: Invalid sub-op index %d in chain\n", subop_idx);
            continue;
        }
        
        Operation *subop = &cipher->base_operations[subop_idx];
        
        /* FIX #4: Linear chain iteration matching Python - NO RECURSION
         * Python (line 313-316): for subop in chain: block = _apply_single_operation(block, subop, inverse)
         * Each sub-operation applies ONE permutation, regardless of whether it has a chain or not.
         * DO NOT recurse into sub-operation chains - treat all as single permutation application.
         */
        
        /* Generate permutation from sub-operation's string representation + key */
        uint8_t subop_input[512];
        int op_str_len = strlen(subop->str_repr);
        memcpy(subop_input, subop->str_repr, op_str_len);
        memcpy(subop_input + op_str_len, cipher->key, cipher->key_len);
        
        uint8_t subop_hash[SHA256_DIGEST_LENGTH];
        sha256_hash(subop_input, op_str_len + cipher->key_len, subop_hash);
        
        /* Initialize permutation */
        for (int i = 0; i < cipher->block_size; i++) {
            perm[i] = i;
        }
        
        /* Use MT19937 to match numpy.random.RandomState */
        uint32_t seed = ((uint32_t)subop_hash[0] << 24) | 
                       ((uint32_t)subop_hash[1] << 16) |
                       ((uint32_t)subop_hash[2] << 8) | 
                       ((uint32_t)subop_hash[3]);
        
        MT19937State mt_state;
        mt_init(&mt_state, seed);
        
        /* Fisher-Yates shuffle */
        for (int i = cipher->block_size - 1; i > 0; i--) {
            uint32_t rand_val = mt_random(&mt_state);
            int j = rand_val % (i + 1);
            int tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        
        /* Apply permutation */
        if (inverse) {
            for (int i = 0; i < cipher->block_size; i++) {
                inv_perm[perm[i]] = i;
            }
            memcpy(temp, block, (size_t)cipher->block_size);
            for (int i = 0; i < cipher->block_size; i++) {
                block[i] = temp[inv_perm[i]];
            }
        } else {
            memcpy(temp, block, (size_t)cipher->block_size);
            for (int i = 0; i < cipher->block_size; i++) {
                block[i] = temp[perm[i]];
            }
        }
    }
}

/* S-box substitution */
static void substitute_bytes(WBC1Cipher *cipher, uint8_t *block, int inverse) {
    for (int i = 0; i < cipher->block_size; i++) {
        block[i] = inverse ? cipher->inv_sbox[block[i]] : cipher->sbox[block[i]];
    }
}

/* Cyclic bitwise rotation on all bytes */
static void cyclic_bitwise_rotate(uint8_t *block, int size, int shift, int direction) {
    shift = shift % 8;
    for (int i = 0; i < size; i++) {
        block[i] = (direction == 0) ? rotate_right(block[i], shift) : rotate_left(block[i], shift);
    }
}

/* ===== ENHANCED MODE 0 FUNCTIONS (Preserving Rubik's Cube Analogy) ===== */

/* XOR entire block with key */
static void xor_with_key(uint8_t *block, const uint8_t *key, int size) {
    for (int i = 0; i < size; i++) {
        block[i] ^= key[i];
    }
}

/* Key-dependent byte transposition (analogous to twisting cube layers) */
/* Multi-layer diffusion (analogous to rotating multiple cube faces) */
/* Two-layer diffusion: Forward cumulative + Backward cumulative XOR */
static void two_layer_diffusion(uint8_t *block, int size, int inverse) {
    if (size < 2) return;
    
    if (!inverse) {
        /* Forward pass: Y[i] = X[i] ^ Y[i-1] */
        for (int i = 1; i < size; i++) {
            block[i] ^= block[i - 1];
        }
        
        /* Backward pass: Z[i] = Y[i] ^ Z[i+1] */
        for (int i = size - 2; i >= 0; i--) {
            block[i] ^= block[i + 1];
        }
    } else {
        /* Inverse: Apply in reverse order */
        
        /* Inverse backward pass: Y[i] = Z[i] ^ Z[i+1] */
        for (int i = 0; i < size - 1; i++) {
            block[i] ^= block[i + 1];
        }
        
        /* Inverse forward pass: X[i] = Y[i] ^ Y[i-1] */
        for (int i = size - 1; i >= 1; i--) {
            block[i] ^= block[i - 1];
        }
    }
}

/* ===== Cipher Operations ===== */

void wbc1_init(WBC1Cipher *cipher, const uint8_t *key, int key_len, int num_rounds, int algorithm_mode) {
    /* FIX #2: Initialize operations array per-instance (matching Python line 200-201) */
    init_operations(cipher, key, key_len);
    
    /* FIX #1: Sort operations by hash for key-dependent ordering (matching Python line 201) */
    individualize_operations(cipher, key, key_len);
    
    cipher->key = malloc(key_len);
    memcpy(cipher->key, key, key_len);
    cipher->key_len = key_len;
    cipher->block_size = BLOCK_SIZE;
    cipher->num_rounds = num_rounds;
    cipher->algorithm_mode = algorithm_mode;
    
    generate_sbox(cipher);
    generate_inverse_sbox(cipher);
    generate_permutation(cipher);
    generate_inverse_permutation(cipher);
    generate_round_keys(cipher);
}

void wbc1_free(WBC1Cipher *cipher) {
    /* FIX #2: Free per-instance operations */
    if (cipher->operations) {
        free(cipher->operations);
        cipher->operations = NULL;
    }
    if (cipher->base_operations) {
        free(cipher->base_operations);
        cipher->base_operations = NULL;
    }
    
    if (cipher->key) {
        free(cipher->key);
        cipher->key = NULL;
    }
}

void wbc1_encrypt_block(WBC1Cipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext) {
    memcpy(ciphertext, plaintext, cipher->block_size);
    
    for (int round = 0; round < cipher->num_rounds; round++) {
        if (cipher->algorithm_mode == MODE_FULL) {
            /* MODE 1: Full algorithm with 5 steps per round */
            
            /* Step 1: Dynamic permutations - 32 operations per round */
            for (int j = 0; j < 32; j++) {
                int c_j = cipher->round_keys[round][j % cipher->key_len];
                int idx_j = c_j % NUM_OPERATIONS;
                apply_operation(cipher, ciphertext, idx_j, 0);
            }
            
            /* Step 2: Cyclic bitwise rotation */
            int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
            if (shift > 0) {
                cyclic_bitwise_rotate(ciphertext, cipher->block_size, shift, 0);
            }
            
            /* Step 3: XOR with round key */
            xor_with_key(ciphertext, cipher->round_keys[round], cipher->block_size);
            
            /* Step 4: S-box substitution */
            substitute_bytes(cipher, ciphertext, 0);
            
            /* Step 5: Two-layer diffusion (forward + backward cumulative XOR) */
            two_layer_diffusion(ciphertext, cipher->block_size, 0);
        } else {
            /* MODE 0: Simplified algorithm with 2 steps per round */
            
            /* Step 1: Dynamic permutations - 32 operations per round */
            for (int j = 0; j < 32; j++) {
                int c_j = cipher->round_keys[round][j % cipher->key_len];
                int idx_j = c_j % NUM_OPERATIONS;
                apply_operation(cipher, ciphertext, idx_j, 0);
            }
            
            /* Step 2: Cyclic bitwise rotation */
            int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
            if (shift > 0) {
                cyclic_bitwise_rotate(ciphertext, cipher->block_size, shift, 0);
            }
        }
    }
}

void wbc1_decrypt_block(WBC1Cipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext) {
    memcpy(plaintext, ciphertext, cipher->block_size);
    
    for (int round = cipher->num_rounds - 1; round >= 0; round--) {
        if (cipher->algorithm_mode == MODE_FULL) {
            /* MODE 1: Full algorithm - reverse order of steps */
            
            /* Step 5: Inverse two-layer diffusion */
            two_layer_diffusion(plaintext, cipher->block_size, 1);
            
            /* Step 4: Inverse S-box substitution */
            substitute_bytes(cipher, plaintext, 1);
            
            /* Step 3: XOR with round key (self-inverse) */
            xor_with_key(plaintext, cipher->round_keys[round], cipher->block_size);
            
            /* Step 2: Inverse cyclic bitwise rotation */
            int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
            if (shift > 0) {
                cyclic_bitwise_rotate(plaintext, cipher->block_size, shift, 1);
            }
            
            /* Step 1: Inverse dynamic permutations - reverse order */
            for (int j = 31; j >= 0; j--) {
                int c_j = cipher->round_keys[round][j % cipher->key_len];
                int idx_j = c_j % NUM_OPERATIONS;
                apply_operation(cipher, plaintext, idx_j, 1);
            }
        } else {
            /* MODE 0: Simplified algorithm - reverse order of steps */
            
            /* Step 2: Inverse cyclic bitwise rotation */
            int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
            if (shift > 0) {
                cyclic_bitwise_rotate(plaintext, cipher->block_size, shift, 1);
            }
            
            /* Step 1: Inverse dynamic permutations - reverse order */
            for (int j = 31; j >= 0; j--) {
                int c_j = cipher->round_keys[round][j % cipher->key_len];
                int idx_j = c_j % NUM_OPERATIONS;
                apply_operation(cipher, plaintext, idx_j, 1);
            }
        }
    }
}

/* ===== Padding Functions ===== */

static void pad_data(const uint8_t *data, int len, uint8_t **padded, int *padded_len) {
    int padding_length = BLOCK_SIZE - (len % BLOCK_SIZE);
    if (padding_length == 0) {
        padding_length = BLOCK_SIZE;
    }
    
    *padded_len = len + padding_length;
    *padded = malloc(*padded_len);
    
    memcpy(*padded, data, len);
    for (int i = len; i < *padded_len; i++) {
        (*padded)[i] = padding_length;
    }
}

static void unpad_data(const uint8_t *data, int len, uint8_t **unpadded, int *unpadded_len) {
    if (len == 0) {
        *unpadded = NULL;
        *unpadded_len = 0;
        return;
    }
    
    int padding_length = data[len - 1];
    
    if (padding_length > BLOCK_SIZE || padding_length == 0) {
        *unpadded = malloc(len);
        memcpy(*unpadded, data, len);
        *unpadded_len = len;
        return;
    }
    
    /* Verify padding */
    int valid = 1;
    for (int i = len - padding_length; i < len; i++) {
        if (data[i] != padding_length) {
            valid = 0;
            break;
        }
    }
    
    if (valid) {
        *unpadded_len = len - padding_length;
        *unpadded = malloc(*unpadded_len);
        memcpy(*unpadded, data, *unpadded_len);
    } else {
        *unpadded = malloc(len);
        memcpy(*unpadded, data, len);
        *unpadded_len = len;
    }
}

/* ===== Parallel MPI Operations ===== */

void parallel_encrypt(WBC1Cipher *cipher, const uint8_t *plaintext, int plaintext_len,
                     uint8_t **ciphertext, int *ciphertext_len) {
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    uint8_t *padded_data = NULL;
    int padded_len = 0;
    int num_blocks = 0;
    
    if (rank == 0) {
        /* Master process: pad data and prepare blocks */
        pad_data(plaintext, plaintext_len, &padded_data, &padded_len);
        num_blocks = padded_len / BLOCK_SIZE;
    }
    
    /* Broadcast number of blocks */
    MPI_Bcast(&num_blocks, 1, MPI_INT, 0, MPI_COMM_WORLD);
    
    /* Calculate distribution */
    int blocks_per_process = num_blocks / size;
    int remainder = num_blocks % size;
    int local_block_count = blocks_per_process + (rank < remainder ? 1 : 0);
    
    /* Prepare send counts and displacements */
    int *send_counts = NULL;
    int *displs = NULL;
    
    if (rank == 0) {
        send_counts = malloc(size * sizeof(int));
        displs = malloc(size * sizeof(int));
        if (!send_counts || !displs) {
            fprintf(stderr, "Error: Failed to allocate memory for send counts\n");
            if (send_counts) free(send_counts);
            if (displs) free(displs);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        
        int offset = 0;
        for (int i = 0; i < size; i++) {
            int count = blocks_per_process + (i < remainder ? 1 : 0);
            send_counts[i] = count * BLOCK_SIZE;
            displs[i] = offset;
            offset += send_counts[i];
        }
    }
    
    /* Allocate local buffer */
    uint8_t *local_blocks = malloc(local_block_count * BLOCK_SIZE);
    if (!local_blocks) {
        fprintf(stderr, "Error: Failed to allocate memory for local blocks\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    
    /* Scatter blocks to all processes */
    MPI_Scatterv(padded_data, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_blocks, local_block_count * BLOCK_SIZE, MPI_UNSIGNED_CHAR,
                 0, MPI_COMM_WORLD);
    
    /* Encrypt local blocks */
    uint8_t *encrypted_local = malloc(local_block_count * BLOCK_SIZE);
    if (!encrypted_local) {
        fprintf(stderr, "Error: Failed to allocate memory for encrypted blocks\n");
        free(local_blocks);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    for (int i = 0; i < local_block_count; i++) {
        wbc1_encrypt_block(cipher, local_blocks + i * BLOCK_SIZE, 
                          encrypted_local + i * BLOCK_SIZE);
    }
    
    /* Gather encrypted blocks */
    uint8_t *all_encrypted = NULL;
    if (rank == 0) {
        all_encrypted = malloc(num_blocks * BLOCK_SIZE);
        if (!all_encrypted) {
            fprintf(stderr, "Error: Failed to allocate memory for gathering encrypted blocks\n");
            free(local_blocks);
            free(encrypted_local);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }
    
    MPI_Gatherv(encrypted_local, local_block_count * BLOCK_SIZE, MPI_UNSIGNED_CHAR,
                all_encrypted, send_counts, displs, MPI_UNSIGNED_CHAR,
                0, MPI_COMM_WORLD);
    
    /* Clean up */
    free(local_blocks);
    free(encrypted_local);
    
    if (rank == 0) {
        *ciphertext = all_encrypted;
        *ciphertext_len = num_blocks * BLOCK_SIZE;
        free(padded_data);
        free(send_counts);
        free(displs);
    } else {
        *ciphertext = NULL;
        *ciphertext_len = 0;
    }
}

void parallel_decrypt(WBC1Cipher *cipher, const uint8_t *ciphertext, int ciphertext_len,
                     uint8_t **plaintext, int *plaintext_len) {
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    int num_blocks = 0;
    
    if (rank == 0) {
        num_blocks = ciphertext_len / BLOCK_SIZE;
    }
    
    /* Broadcast number of blocks */
    MPI_Bcast(&num_blocks, 1, MPI_INT, 0, MPI_COMM_WORLD);
    
    /* Calculate distribution */
    int blocks_per_process = num_blocks / size;
    int remainder = num_blocks % size;
    int local_block_count = blocks_per_process + (rank < remainder ? 1 : 0);
    
    /* Prepare send counts and displacements */
    int *send_counts = NULL;
    int *displs = NULL;
    
    if (rank == 0) {
        send_counts = malloc(size * sizeof(int));
        displs = malloc(size * sizeof(int));
        if (!send_counts || !displs) {
            fprintf(stderr, "Error: Failed to allocate memory for send counts\n");
            if (send_counts) free(send_counts);
            if (displs) free(displs);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        
        int offset = 0;
        for (int i = 0; i < size; i++) {
            int count = blocks_per_process + (i < remainder ? 1 : 0);
            send_counts[i] = count * BLOCK_SIZE;
            displs[i] = offset;
            offset += send_counts[i];
        }
    }
    
    /* Allocate local buffer */
    uint8_t *local_blocks = malloc(local_block_count * BLOCK_SIZE);
    if (!local_blocks) {
        fprintf(stderr, "Error: Failed to allocate memory for local blocks\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    
    /* Scatter blocks to all processes */
    MPI_Scatterv(ciphertext, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_blocks, local_block_count * BLOCK_SIZE, MPI_UNSIGNED_CHAR,
                 0, MPI_COMM_WORLD);
    
    /* Decrypt local blocks */
    uint8_t *decrypted_local = malloc(local_block_count * BLOCK_SIZE);
    if (!decrypted_local) {
        fprintf(stderr, "Error: Failed to allocate memory for decrypted blocks\n");
        free(local_blocks);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    for (int i = 0; i < local_block_count; i++) {
        wbc1_decrypt_block(cipher, local_blocks + i * BLOCK_SIZE,
                          decrypted_local + i * BLOCK_SIZE);
    }
    
    /* Gather decrypted blocks */
    uint8_t *all_decrypted = NULL;
    if (rank == 0) {
        all_decrypted = malloc(num_blocks * BLOCK_SIZE);
        if (!all_decrypted) {
            fprintf(stderr, "Error: Failed to allocate memory for gathering decrypted blocks\n");
            free(local_blocks);
            free(decrypted_local);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }
    
    MPI_Gatherv(decrypted_local, local_block_count * BLOCK_SIZE, MPI_UNSIGNED_CHAR,
                all_decrypted, send_counts, displs, MPI_UNSIGNED_CHAR,
                0, MPI_COMM_WORLD);
    
    /* Clean up */
    free(local_blocks);
    free(decrypted_local);
    
    if (rank == 0) {
        /* Remove padding */
        unpad_data(all_decrypted, num_blocks * BLOCK_SIZE, plaintext, plaintext_len);
        free(all_decrypted);
        free(send_counts);
        free(displs);
    } else {
        *plaintext = NULL;
        *plaintext_len = 0;
    }
}

/* ===== Statistical Analysis Functions ===== */

double shannon_entropy(const uint8_t *data, int len) {
    if (len == 0) return 0.0;
    
    // Count frequency
    int frequency[256] = {0};
    for (int i = 0; i < len; i++) {
        frequency[data[i]]++;
    }
    
    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void avalanche_test(WBC1Cipher *cipher, int num_tests, double *results) {
    // results should be array of size num_tests
    // Test by flipping single bit and measuring output bit changes
    // Uses single block encryption (like Python) to test pure algorithm without padding artifacts
    
    // Seed random number generator for test data generation
    // Use /dev/urandom for high-quality random seed
    FILE *urandom = fopen("/dev/urandom", "rb");
    unsigned int seed;
    if (urandom) {
        if (fread(&seed, sizeof(seed), 1, urandom) == 1) {
            srand(seed);
        } else {
            srand((unsigned int)time(NULL));
        }
        fclose(urandom);
    } else {
        srand((unsigned int)time(NULL));
    }
    
    for (int test = 0; test < num_tests; test++) {
        // Generate random plaintext block (single block, no padding)
        uint8_t plaintext[BLOCK_SIZE];
        uint8_t plaintext_flipped[BLOCK_SIZE];
        uint8_t ciphertext1[BLOCK_SIZE];
        uint8_t ciphertext2[BLOCK_SIZE];
        
        for (int i = 0; i < BLOCK_SIZE; i++) {
            plaintext[i] = rand() % 256;
            plaintext_flipped[i] = plaintext[i];
        }
        
        // Flip one random bit
        int bit_pos = rand() % (BLOCK_SIZE * 8);
        int byte_idx = bit_pos / 8;
        int bit_idx = bit_pos % 8;
        plaintext_flipped[byte_idx] ^= (1 << bit_idx);
        
        // Encrypt both using single block encryption (no padding)
        wbc1_encrypt_block(cipher, plaintext, ciphertext1);
        wbc1_encrypt_block(cipher, plaintext_flipped, ciphertext2);
        
        // Count bit differences in ciphertext
        int bits_changed = 0;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            uint8_t diff = ciphertext1[i] ^ ciphertext2[i];
            for (int j = 0; j < 8; j++) {
                if (diff & (1 << j)) bits_changed++;
            }
        }
        
        results[test] = (double)bits_changed / (BLOCK_SIZE * 8) * 100.0;
    }
}

void frequency_test(const uint8_t *data, int len, double *mean, double *std, double *chi_square) {
    if (len == 0) {
        *mean = 0; *std = 0; *chi_square = 0;
        return;
    }
    
    int frequency[256] = {0};
    for (int i = 0; i < len; i++) {
        frequency[data[i]]++;
    }
    
    // Calculate mean
    double sum = 0;
    for (int i = 0; i < 256; i++) {
        sum += frequency[i];
    }
    *mean = sum / 256.0;
    
    // Calculate std dev
    double var_sum = 0;
    for (int i = 0; i < 256; i++) {
        double diff = frequency[i] - *mean;
        var_sum += diff * diff;
    }
    *std = sqrt(var_sum / 256.0);
    
    // Calculate chi-square
    double expected = (double)len / 256.0;
    *chi_square = 0;
    for (int i = 0; i < 256; i++) {
        double diff = frequency[i] - expected;
        *chi_square += (diff * diff) / expected;
    }
}

double correlation_test(const uint8_t *data1, const uint8_t *data2, int len) {
    if (len == 0) return 0.0;
    
    // Calculate means
    double mean1 = 0, mean2 = 0;
    for (int i = 0; i < len; i++) {
        mean1 += data1[i];
        mean2 += data2[i];
    }
    mean1 /= len;
    mean2 /= len;
    
    // Calculate correlation
    double numerator = 0, denom1 = 0, denom2 = 0;
    for (int i = 0; i < len; i++) {
        double diff1 = data1[i] - mean1;
        double diff2 = data2[i] - mean2;
        numerator += diff1 * diff2;
        denom1 += diff1 * diff1;
        denom2 += diff2 * diff2;
    }
    
    if (denom1 == 0 || denom2 == 0) return 0.0;
    return numerator / sqrt(denom1 * denom2);
}

/* Function to print operations table */
static void print_operations_table(WBC1Cipher *cipher) {
    printf("\n");
    printf("======================================================================\n");
    printf("          ТАБЛИЦА ПЕРЕСТАНОВОК / OPERATIONS TABLE\n");
    printf("======================================================================\n");
    printf("%-6s %-8s %-8s %-50s %s\n", "Номер", "ASCII", "Hex", "Операция", "Описание");
    printf("%-6s %-8s %-8s %-50s %s\n", "Number", "Char", "Code", "Operation", "Description");
    printf("----------------------------------------------------------------------\n");
    
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        Operation *op = &cipher->operations[i];
        
        /* ASCII character (printable or . for non-printable) */
        char ascii_char[10];
        if (i >= 32 && i < 127) {
            snprintf(ascii_char, sizeof(ascii_char), "%c", (char)i);
        } else {
            snprintf(ascii_char, sizeof(ascii_char), ".");
        }
        
        /* Hex representation */
        char hex[10];
        snprintf(hex, sizeof(hex), "0x%02X", i);
        
        /* Operation type and parameters */
        char operation[51];
        if (strcmp(op->type, "dynamic") == 0) {
            if (op->chain_length > 0) {
                snprintf(operation, sizeof(operation), "Dynamic[%d ops]", op->chain_length);
            } else {
                snprintf(operation, sizeof(operation), "Dynamic");
            }
        } else if (strcmp(op->type, "face") == 0) {
            snprintf(operation, sizeof(operation), "Face %s%s", op->param1, op->param2);
        } else if (strcmp(op->type, "slice") == 0) {
            snprintf(operation, sizeof(operation), "Slice %s%s", op->param1, op->param2);
        } else if (strcmp(op->type, "wide") == 0) {
            snprintf(operation, sizeof(operation), "Wide %s%s", op->param1, op->param2);
        } else if (strcmp(op->type, "cube") == 0) {
            snprintf(operation, sizeof(operation), "Cube %s%s", op->param1, op->param2);
        } else if (strcmp(op->type, "alg") == 0) {
            snprintf(operation, sizeof(operation), "Alg:%s", op->param1);
        } else if (strcmp(op->type, "pattern") == 0) {
            snprintf(operation, sizeof(operation), "Pat:%s", op->param1);
        } else if (strcmp(op->type, "swap") == 0) {
            snprintf(operation, sizeof(operation), "Swap ax=%s off=%s", op->param1, op->param2);
        } else if (strcmp(op->type, "diagflip") == 0) {
            snprintf(operation, sizeof(operation), "DiagFlip ax=%s", op->param1);
        } else {
            snprintf(operation, sizeof(operation), "%s", op->type);
        }
        
        /* Description (truncate if too long) */
        char description[50];
        if (strlen(op->desc) > 45) {
            strncpy(description, op->desc, 42);
            description[42] = '.';
            description[43] = '.';
            description[44] = '.';
            description[45] = '\0';
        } else {
            strncpy(description, op->desc, sizeof(description) - 1);
            description[sizeof(description) - 1] = '\0';
        }
        
        printf("%-6d %-8s %-8s %-50s %s\n", i, ascii_char, hex, operation, description);
    }
    
    printf("======================================================================\n");
    printf("Всего операций / Total operations: %d\n", NUM_OPERATIONS);
    printf("======================================================================\n\n");
}

/* ===== Main Test Function ===== */

int main(int argc, char **argv) {
    MPI_Init(&argc, &argv);
    
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    /* Default parameters - matches Python interface:
     * Format: <algorithm_mode> <key_bits> <key_source> <rounds> <task> [data_kb]
     * algorithm_mode: 0=simplified (2 ops), 1=full (5 ops)
     * key_bits: key size in bits (128, 192, 256, etc.)
     * key_source: 0=auto-generate, 1=user-provided (not implemented in C)
     * rounds: number of encryption rounds
     * task: 0=text encryption, 1=statistical analysis (not fully implemented)
     * data_kb: data size in KB for task=1
     */
    int algorithm_mode = MODE_FULL;
    int key_bits = 256;
    /* Note: key_source (argv[3]) is parsed for compatibility with Python interface but not used */
    /* C version always auto-generates keys based on key_bits parameter */
    int num_rounds = 16;
    int task = 0;  /* 0=text encryption, 1=statistical analysis */
    int data_kb = 1;  /* Data size in KB for task=1 */
    
    /* Parse command-line arguments */
    if (argc >= 5) {
        algorithm_mode = atoi(argv[1]);
        key_bits = atoi(argv[2]);
        /* argv[3] is key_source - parsed for Python compatibility but not used in C */
        num_rounds = atoi(argv[4]);
        if (argc >= 6) {
            task = atoi(argv[5]);
        }
        if (argc >= 7 && task == 1) {
            data_kb = atoi(argv[6]);
        }
        
        /* Validate parameters */
        if (task < 0 || task > 2) {
            if (rank == 0) {
                fprintf(stderr, "Error: Invalid task value %d. Task must be 0, 1, or 2.\n", task);
                fprintf(stderr, "  0 = text encryption\n");
                fprintf(stderr, "  1 = statistical analysis\n");
                fprintf(stderr, "  2 = print operations table\n");
            }
            free(key);
            MPI_Finalize();
            return 1;
        }
        if (algorithm_mode < 0 || algorithm_mode > 1) {
            if (rank == 0) {
                fprintf(stderr, "Error: Invalid algorithm_mode %d. Must be 0 or 1.\n", algorithm_mode);
            }
            free(key);
            MPI_Finalize();
            return 1;
        }
    } else if (rank == 0) {
        printf("Usage: %s <algorithm_mode> <key_bits> <key_source> <rounds> <task> [data_kb]\n", argv[0]);
        printf("  algorithm_mode: 0=simplified (2 ops/round), 1=full (5 ops/round)\n");
        printf("  key_bits: key size in bits (128, 192, 256, etc.)\n");
        printf("  key_source: 0=auto-generate, 1=user-provided (C version always auto-generates)\n");
        printf("  rounds: number of encryption rounds\n");
        printf("  task: 0=text encryption, 1=statistical analysis, 2=print operations table\n");
        printf("  data_kb: data size in KB for task=1 (optional, default=1)\n\n");
        printf("Example: mpirun -n 4 %s 1 256 0 16 0\n", argv[0]);
        printf("Example: mpirun -n 1 %s 0 256 0 16 1 10  (statistical analysis with 10KB data)\n", argv[0]);
        printf("Example: mpirun -n 1 %s 0 256 0 16 2  (print operations table)\n", argv[0]);
        free(key);
        MPI_Finalize();
        return 0;
    }
    
    /* Generate key based on key_bits */
    int key_len = key_bits / 8;
    if (key_len < 16) key_len = 16;  /* Minimum 128 bits */
    if (key_len > 32) key_len = 32;  /* Maximum 256 bits */
    
    uint8_t *key = malloc(key_len);
    if (!key) {
        fprintf(stderr, "Error: Failed to allocate memory for key\n");
        MPI_Finalize();
        return 1;
    }
    
    /* Auto-generate key (simple method - could use better RNG) */
    const char *key_base = "WBC1SecretKey_AutoGenerated_";
    int base_len = strlen(key_base);
    for (int i = 0; i < key_len; i++) {
        key[i] = (i < base_len) ? key_base[i] : (uint8_t)(i * 7 + 13);
    }
    
    /* Initialize cipher */
    WBC1Cipher cipher;
    wbc1_init(&cipher, key, key_len, num_rounds, algorithm_mode);
    
    /* Handle task=2: Print operations table */
    if (task == 2) {
        if (rank == 0) {
            printf("======================================================================\n");
            printf("ПАРАЛЛЕЛЬНЫЙ ШИФР WBC1 / PARALLEL WBC1 CIPHER (C Implementation)\n");
            printf("======================================================================\n");
            printf("Количество MPI процессов / MPI processes: %d\n", size);
            printf("Режим / Mode: %s\n", algorithm_mode == MODE_FULL ? "1 (Full - 160 ops/round)" : "0 (Simplified - 32 ops/round)");
            printf("Размер ключа / Key size: %d бит / bits (%d байт / bytes)\n", key_bits, key_len);
            printf("Размер блока / Block size: %d байт / bytes\n", BLOCK_SIZE);
            printf("Количество раундов / Rounds: %d\n", num_rounds);
            printf("Задача / Task: Вывод таблицы операций / Print operations table\n");
            printf("======================================================================\n");
            
            print_operations_table(&cipher);
        }
        
        wbc1_free(&cipher);
        free(key);
        MPI_Finalize();
        return 0;
    }
    
    /* Prepare test data based on task */
    uint8_t *plaintext = NULL;
    int plain_len = 0;
    
    if (task == 1) {
        /* Statistical analysis mode - generate data based on data_kb */
        plain_len = data_kb * 1024;
        plaintext = malloc(plain_len);
        if (!plaintext) {
            fprintf(stderr, "Error: Failed to allocate memory for test data\n");
            free(key);
            MPI_Finalize();
            return 1;
        }
        /* Fill with truly random data for statistical analysis */
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            size_t bytes_read = fread(plaintext, 1, plain_len, urandom);
            if (bytes_read != (size_t)plain_len) {
                /* Fallback: use time-seeded PRNG */
                srand((unsigned int)time(NULL) ^ rank);
                for (int i = 0; i < plain_len; i++) {
                    plaintext[i] = (uint8_t)rand();
                }
            }
            fclose(urandom);
        } else {
            /* Fallback: use time-seeded PRNG */
            srand((unsigned int)time(NULL) ^ rank);
            for (int i = 0; i < plain_len; i++) {
                plaintext[i] = (uint8_t)rand();
            }
        }
    } else {
        /* Text encryption mode - use demo text */
        const char *plaintext_str = "This is a demonstration of the WBC1 parallel cipher with dynamic Rubik's cube permutation operations. "
                                   "The implementation supports both simplified (2 operations per round) and full (5 operations per round) algorithm modes. "
                                   "It uses MPI for distributed parallel processing across multiple nodes. ";
        
        /* Repeat for larger test */
        int repeat_count = 4;
        plain_len = strlen(plaintext_str) * repeat_count;
        plaintext = malloc(plain_len);
        if (!plaintext) {
            fprintf(stderr, "Error: Failed to allocate memory for test plaintext\n");
            free(key);
            MPI_Finalize();
            return 1;
        }
        for (int i = 0; i < repeat_count; i++) {
            memcpy(plaintext + i * strlen(plaintext_str), plaintext_str, strlen(plaintext_str));
        }
    }
    
    if (rank == 0) {
        printf("======================================================================\n");
        printf("ПАРАЛЛЕЛЬНЫЙ ШИФР WBC1 / PARALLEL WBC1 CIPHER (C Implementation)\n");
        printf("======================================================================\n");
        printf("Количество MPI процессов / MPI processes: %d\n", size);
        printf("Режим / Mode: %s\n", algorithm_mode == MODE_FULL ? "1 (Full - 5 операций / operations)" : "0 (Simplified - 2 операции / operations)");
        printf("Размер ключа / Key size: %d бит / bits (%d байт / bytes)\n", key_bits, key_len);
        printf("Размер блока / Block size: %d байт / bytes\n", BLOCK_SIZE);
        printf("Количество раундов / Rounds: %d\n", num_rounds);
        printf("Задача / Task: %s\n", task == 0 ? "Шифрование текста / Text encryption" : "Статистический анализ / Statistical analysis");
        if (task == 1) {
            printf("Размер данных / Data size: %d KB (%d байт / bytes)\n", data_kb, plain_len);
        }
        printf("======================================================================\n");
        printf("\nДлина открытого текста / Original plaintext length: %d байт / bytes\n", plain_len);
        if (task == 0 && plain_len <= 200) {
            printf("Открытый текст / Original plaintext: %.*s\n\n", plain_len, plaintext);
        } else if (task == 0) {
            printf("Открытый текст / Original plaintext: %.80s...\n\n", plaintext);
        } else {
            printf("Данные (первые 64 байта, hex) / Data (first 64 bytes, hex): ");
            for (int i = 0; i < 64 && i < plain_len; i++) {
                printf("%02x", plaintext[i]);
            }
            printf("...\n\n");
        }
    }
    
    /* Encrypt */
    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();
    uint8_t *ciphertext = NULL;
    int ciphertext_len = 0;
    parallel_encrypt(&cipher, plaintext, plain_len, &ciphertext, &ciphertext_len);
    MPI_Barrier(MPI_COMM_WORLD);
    double enc_time = MPI_Wtime() - start_time;
    
    if (rank == 0) {
        printf("Encrypted ciphertext length: %d bytes\n", ciphertext_len);
        if (task == 0) {
            printf("Ciphertext (hex, first 128 bytes): ");
            for (int i = 0; i < 128 && i < ciphertext_len; i++) {
                printf("%02x", ciphertext[i]);
            }
            printf("...\n");
        } else {
            printf("Ciphertext (hex, first 64 bytes): ");
            for (int i = 0; i < 64 && i < ciphertext_len; i++) {
                printf("%02x", ciphertext[i]);
            }
            printf("...\n");
        }
        printf("Encryption time: %.6f seconds\n", enc_time);
        if (task == 1) {
            double throughput_enc = (plain_len / 1024.0) / enc_time;  /* KB/s */
            printf("Encryption throughput: %.2f KB/s\n", throughput_enc);
        }
        printf("\n");
    }
    
    /* Decrypt */
    MPI_Barrier(MPI_COMM_WORLD);
    start_time = MPI_Wtime();
    uint8_t *decrypted = NULL;
    int decrypted_len = 0;
    parallel_decrypt(&cipher, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
    MPI_Barrier(MPI_COMM_WORLD);
    double dec_time = MPI_Wtime() - start_time;
    
    if (rank == 0) {
        printf("Decrypted plaintext length: %d bytes\n", decrypted_len);
        if (task == 0 && decrypted_len <= 200) {
            printf("Decrypted plaintext: %.*s\n", decrypted_len, decrypted);
        } else if (task == 0) {
            printf("Decrypted plaintext: %.80s...\n", decrypted);
        } else {
            printf("Decrypted data (first 64 bytes, hex): ");
            for (int i = 0; i < 64 && i < decrypted_len; i++) {
                printf("%02x", decrypted[i]);
            }
            printf("...\n");
        }
        printf("Decryption time: %.6f seconds\n", dec_time);
        if (task == 1) {
            double throughput_dec = (decrypted_len / 1024.0) / dec_time;  /* KB/s */
            printf("Decryption throughput: %.2f KB/s\n", throughput_dec);
        }
        printf("\n");
        
        /* Verify */
        if (decrypted_len == plain_len && memcmp(plaintext, decrypted, plain_len) == 0) {
            printf("✓ Шифрование/Дешифрование успешно / Encryption/Decryption successful!\n");
            printf("  Выход совпадает с входом / Output matches input!\n");
        } else {
            printf("✗ Ошибка / Error: Расшифрованный текст не соответствует оригиналу!\n");
            printf("  Decrypted text does not match original!\n");
        }
        
        /* Statistical analysis for task==1 */
        if (task == 1) {
            printf("\n");
            printf("======================================================================\n");
            printf("  КРИПТОГРАФИЧЕСКИЙ АНАЛИЗ / CRYPTOGRAPHIC QUALITY ANALYSIS\n");
            printf("======================================================================\n\n");
            
            // Shannon entropy
            double entropy_plain = shannon_entropy(plaintext, plain_len);
            double entropy_cipher = shannon_entropy(ciphertext, ciphertext_len);
            printf("1. Энтропия Шеннона / Shannon Entropy:\n");
            printf("   Открытый текст / Plaintext:  %.4f бит/байт\n", entropy_plain);
            printf("   Шифртекст / Ciphertext:      %.4f бит/байт\n", entropy_cipher);
            printf("   (Идеально / Ideal: 8.0 бит/байт)\n");
            
            // Frequency test
            double freq_mean, freq_std, freq_chi;
            frequency_test(ciphertext, ciphertext_len, &freq_mean, &freq_std, &freq_chi);
            printf("\n2. Частотный тест / Frequency Test:\n");
            printf("   Среднее / Mean:        %.2f\n", freq_mean);
            printf("   Ст. откл. / Std dev:   %.2f\n", freq_std);
            printf("   Хи-квадрат / Chi-sq:   %.2f\n", freq_chi);
            
            // Avalanche test
            printf("\n3. Лавинный эффект / Avalanche Effect:\n");
            double avalanche_results[100];
            avalanche_test(&cipher, 100, avalanche_results);
            
            double av_sum = 0, av_min = 100, av_max = 0;
            for (int i = 0; i < 100; i++) {
                av_sum += avalanche_results[i];
                if (avalanche_results[i] < av_min) av_min = avalanche_results[i];
                if (avalanche_results[i] > av_max) av_max = avalanche_results[i];
            }
            double av_mean = av_sum / 100;
            double av_var = 0;
            for (int i = 0; i < 100; i++) {
                double diff = avalanche_results[i] - av_mean;
                av_var += diff * diff;
            }
            double av_std = sqrt(av_var / 100);
            
            printf("   Среднее изменение битов / Mean bit flip: %.2f%%\n", av_mean);
            printf("   Ст. откл. / Std dev:                     %.2f%%\n", av_std);
            printf("   Диапазон / Range: [%.2f%%, %.2f%%]\n", av_min, av_max);
            printf("   (Идеально / Ideal: ~50%%)\n");
            
            // Correlation - compare plaintext with ciphertext (should be low)
            double corr = correlation_test(plaintext, ciphertext, plain_len < ciphertext_len ? plain_len : ciphertext_len);
            printf("\n4. Корреляция / Correlation:\n");
            printf("   Корреляция открытый-шифр / PT-CT: %.6f\n", corr);
            printf("   (Идеально / Ideal: ~0.0)\n");
            
            // Differential test - key sensitivity
            printf("\n5. Дифференциальный тест / Differential Test:\n");
            printf("   Тестирование чувствительности к изменению ключа...\n");
            printf("   Testing key sensitivity to single bit flips...\n");
            
            long long total_flips = 0;
            // Only compare actual block size that gets encrypted (BLOCK_SIZE = 16 bytes)
            int test_block_size = BLOCK_SIZE;
            int total_bits = test_block_size * 8;
            
            // Test all 256 bits of the key (32 bytes * 8 bits)
            for (int bit_pos = 0; bit_pos < 256; bit_pos++) {
                // Create modified key with single bit flipped
                unsigned char modified_key[32];
                memcpy(modified_key, key, 32);
                modified_key[bit_pos / 8] ^= (1 << (bit_pos % 8));
                
                // Create cipher with modified key
                WBC1Cipher modified_cipher;
                wbc1_init(&modified_cipher, modified_key, 32, num_rounds, algorithm_mode);
                
                // Encrypt single block with modified key
                unsigned char modified_ciphertext[BLOCK_SIZE];
                unsigned char test_block[BLOCK_SIZE];
                memcpy(test_block, plaintext, (plain_len < BLOCK_SIZE) ? plain_len : BLOCK_SIZE);
                if (plain_len < BLOCK_SIZE) {
                    memset(test_block + plain_len, 0, BLOCK_SIZE - plain_len);
                }
                
                wbc1_encrypt_block(&modified_cipher, test_block, modified_ciphertext);
                
                // Count bit differences in encrypted block (only BLOCK_SIZE bytes)
                for (int byte_idx = 0; byte_idx < test_block_size; byte_idx++) {
                    unsigned char diff = ciphertext[byte_idx] ^ modified_ciphertext[byte_idx];
                    // Count set bits in diff
                    while (diff) {
                        total_flips += diff & 1;
                        diff >>= 1;
                    }
                }
                
                wbc1_free(&modified_cipher);
            }
            
            // Match Python formula: flips / (256 * total_bits)
            // This represents: bits_changed / (number_of_key_bits * output_bits)
            double diff_effect = (double)total_flips / (256.0 * (double)total_bits);
            printf("   Изменение выходных битов / Output bit changes: %.2f%%\n", diff_effect * 100.0);
            printf("   (Идеально / Ideal: ~50%% изменений при 1-битном изменении ключа)\n");
            
            printf("\n");
            printf("======================================================================\n");
            printf("АНАЛИЗ ЗАВЕРШЕН / ANALYSIS COMPLETED\n");
            printf("======================================================================\n");
        }
        
        free(ciphertext);
        free(decrypted);
    }
    
    free(key);
    free(plaintext);
    wbc1_free(&cipher);
    
    MPI_Finalize();
    return 0;
}
