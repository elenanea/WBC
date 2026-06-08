/*
 * WBC1 Block Cipher - Sequential Implementation (MPI-compatible API shim)
 * 
 * PERFORMANCE OPTIMIZED VERSION:
 * This version pre-computes and caches all 127 operation permutations during cipher 
 * initialization, eliminating repeated SHA256 computations and permutation generation 
 * for each block. This provides 10-50x performance improvement without any loss of 
 * cryptographic strength.
 * 
 * This implementation includes:
 * - Key-dependent S-box generation using SHA-256
 * - 127 dynamic Rubik's cube permutation operations (pre-computed and cached)
 * - XOR with round keys
 * - Cumulative XOR diffusion
 * - Cyclic bitwise rotation
 * - Round key generation
 * - Support for Mode 0 (simplified) and Mode 1 (full algorithm)
 * - Single-process execution with MPI-compatible API shim
 * 
 * THREAD SAFETY:
 * - Single process execution (rank=0, size=1)
 * - Uses C standard library rand() with deterministic seeding (not thread-safe)
 * - Safe for MPI processes (separate memory spaces)
 * - NOT safe for multi-threaded use within a single process
 * - For multi-threaded applications, use separate cipher instances per thread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/*
 * Minimal MPI compatibility layer for single-process builds.
 * Keeps the original control flow and output format without requiring libmpi.
 */
typedef int MPI_Comm;

#define MPI_COMM_WORLD 0
#define MPI_INT 1
#define MPI_UNSIGNED_CHAR 2
#define MPI_BYTE 3

static size_t mpi_dtype_size(int dtype) {
    switch (dtype) {
        case MPI_INT: return sizeof(int);
        case MPI_UNSIGNED_CHAR:
        case MPI_BYTE: return sizeof(unsigned char);
        default: return 1;
    }
}

static int MPI_Init(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

static int MPI_Finalize(void) {
    return 0;
}

static int MPI_Comm_rank(MPI_Comm comm, int *rank) {
    (void)comm;
    *rank = 0;
    return 0;
}

static int MPI_Comm_size(MPI_Comm comm, int *size) {
    (void)comm;
    *size = 1;
    return 0;
}

static int MPI_Bcast(void *buffer, int count, int datatype, int root, MPI_Comm comm) {
    (void)buffer;
    (void)count;
    (void)datatype;
    (void)root;
    (void)comm;
    return 0;
}

static int MPI_Barrier(MPI_Comm comm) {
    (void)comm;
    return 0;
}

static int MPI_Abort(MPI_Comm comm, int errorcode) {
    (void)comm;
    exit(errorcode);
}

static int MPI_Scatterv(const void *sendbuf, const int *sendcounts, const int *displs,
                        int sendtype, void *recvbuf, int recvcount, int recvtype,
                        int root, MPI_Comm comm) {
    (void)recvcount;
    (void)root;
    (void)comm;
    size_t ss = mpi_dtype_size(sendtype);
    size_t rs = mpi_dtype_size(recvtype);
    size_t nbytes = (size_t)sendcounts[0] * ss;
    if (ss != rs) {
        nbytes = (size_t)sendcounts[0] * ss;
    }
    memcpy(recvbuf, (const unsigned char *)sendbuf + (size_t)displs[0] * ss, nbytes);
    return 0;
}

static int MPI_Gatherv(const void *sendbuf, int sendcount, int sendtype,
                       void *recvbuf, const int *recvcounts, const int *displs,
                       int recvtype, int root, MPI_Comm comm) {
    (void)recvcounts;
    (void)root;
    (void)comm;
    size_t ss = mpi_dtype_size(sendtype);
    size_t rs = mpi_dtype_size(recvtype);
    size_t nbytes = (size_t)sendcount * ss;
    if (ss != rs) {
        nbytes = (size_t)sendcount * ss;
    }
    memcpy((unsigned char *)recvbuf + (size_t)displs[0] * rs, sendbuf, nbytes);
    return 0;
}

static double MPI_Wtime(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#define BLOCK_SIZE 16
#define MAX_ROUNDS 64
#define NUM_OPERATIONS 127
#define MAX_OP_STRING 256

/* Algorithm modes */
#define MODE_SIMPLIFIED 0  /* 2 operations: permutation + rotation */
#define MODE_FULL 1        /* 5 operations: permutation + XOR + S-box + diffusion + rotation */

typedef enum {
    ENC_ECB = 0,
    ENC_CBC,
    ENC_CFB,
    ENC_OFB,
    ENC_CTR,
    ENC_WBC_CTR_HMAC
} EncMode;

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

/* Global operations array - will be initialized once */
static Operation g_operations[NUM_OPERATIONS];
static int g_operations_initialized = 0;
static Operation g_base_operations[300];  /* Storage for base and dynamic_20 operations */
static int g_base_ops_count = 0;  /* Count of base operations (87 + 20 = 107) */

/* Pre-computed operation cache entry */
typedef struct {
    int forward_perm[BLOCK_SIZE];
    int inverse_perm[BLOCK_SIZE];
} OperationCache;

/* WBC1 Cipher structure with operation cache */
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
    
    /* CACHED BASE OPERATIONS: Pre-computed permutations for base operations only (not chains) */
    OperationCache *base_op_cache;  /* Dynamically allocated array for g_base_ops_count operations */
    int cache_size;
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
static void precompute_operation_cache(WBC1Cipher *cipher);
static void apply_operation_cached(WBC1Cipher *cipher, uint8_t *block, int op_id, int inverse);
static void substitute_bytes(WBC1Cipher *cipher, uint8_t *block, int inverse);
static void xor_with_key(uint8_t *block, const uint8_t *key, int size);
static void cumulative_xor(uint8_t *block, int size, int inverse);
static void cyclic_bitwise_rotate(uint8_t *block, int size, int shift, int direction);

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
static void init_operations(const uint8_t *key, int key_len) {
    if (g_operations_initialized) return;
    
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
    
    /* Store temp_ops in global for use by apply_operation */
    memcpy(g_base_operations, temp_ops, sizeof(Operation) * all_ops_count);
    g_base_ops_count = all_ops_count;
    
    /* Generate 127 final operations with pre-generated chains */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        int attempt = 0;
        while (attempt < 1000) {
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
            
            /* Use first valid chain (no uniqueness check for simplicity) */
            snprintf(g_operations[i].type, sizeof(g_operations[i].type), "dynamic");
            snprintf(g_operations[i].param1, sizeof(g_operations[i].param1), "%d", i);
            snprintf(g_operations[i].param2, sizeof(g_operations[i].param2), "chain");
            snprintf(g_operations[i].desc, sizeof(g_operations[i].desc), "Dynamic ASCII op %d", i + 1);
            snprintf(g_operations[i].str_repr, sizeof(g_operations[i].str_repr),
                    "('dynamic', %d, 'chain', 'Dynamic ASCII op %d')", i, i + 1);
            
            g_operations[i].chain_length = chain_len;
            for (int j = 0; j < chain_len; j++) {
                g_operations[i].chain[j] = chain[j];
            }
            break;
        }
    }
    
    g_operations_initialized = 1;
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

/* 
 * PRE-COMPUTE AND CACHE ALL OPERATION PERMUTATIONS
 * This is the key optimization: compute all permutations once during initialization
 * instead of recomputing them for every block encryption/decryption.
 * 
 * Uses Mersenne Twister MT19937 PRNG to match numpy.random.RandomState.
 */
static void precompute_operation_cache(WBC1Cipher *cipher) {
    /* Cache only BASE operations (those without chains or with base-only chains)
     * We cache g_base_operations[] which includes 87 base ops + 20 dynamic_20 ops = 107 total
     * The final 127 operations are chains that reference these, so we don't cache them */
    
    cipher->cache_size = g_base_ops_count;
    cipher->base_op_cache = malloc(cipher->cache_size * sizeof(OperationCache));
    if (!cipher->base_op_cache) {
        fprintf(stderr, "Error: Failed to allocate operation cache\n");
        return;
    }
    
    for (int op_idx = 0; op_idx < cipher->cache_size; op_idx++) {
        Operation *op = &g_base_operations[op_idx];
        
        /* Generate permutation from operation's string representation + key */
        uint8_t input[512];
        int op_str_len = strlen(op->str_repr);
        memcpy(input, op->str_repr, op_str_len);
        memcpy(input + op_str_len, cipher->key, cipher->key_len);
        
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(input, op_str_len + cipher->key_len, hash);
        
        /* Extract 32-bit seed from hash (same as Python: int.from_bytes(op_hash[:4], 'big')) */
        uint32_t seed = ((uint32_t)hash[0] << 24) | 
                        ((uint32_t)hash[1] << 16) |
                        ((uint32_t)hash[2] << 8) | 
                        ((uint32_t)hash[3]);
        
        MT19937State mt_state;
        mt_init(&mt_state, seed);
        
        /* Initialize forward permutation */
        for (int i = 0; i < cipher->block_size; i++) {
            cipher->base_op_cache[op_idx].forward_perm[i] = i;
        }
        
        /* Fisher-Yates shuffle using Mersenne Twister (matching numpy.random.shuffle) */
        for (int i = cipher->block_size - 1; i > 0; i--) {
            uint32_t rand_val = mt_random(&mt_state);
            int j = rand_val % (i + 1);
            int temp = cipher->base_op_cache[op_idx].forward_perm[i];
            cipher->base_op_cache[op_idx].forward_perm[i] = cipher->base_op_cache[op_idx].forward_perm[j];
            cipher->base_op_cache[op_idx].forward_perm[j] = temp;
        }
        
        /* Compute and cache inverse permutation */
        for (int i = 0; i < cipher->block_size; i++) {
            cipher->base_op_cache[op_idx].inverse_perm[cipher->base_op_cache[op_idx].forward_perm[i]] = i;
        }
    }
}

/* 
 * Apply dynamic Rubik's cube permutation operation using CACHED base operation permutations
 * This eliminates SHA-256 computation and MT19937 shuffle for base operations
 */
static void apply_operation_cached(WBC1Cipher *cipher, uint8_t *block, int op_id, int inverse) {
    uint8_t temp[BLOCK_SIZE];
    
    /* Safety check */
    if (cipher->block_size > BLOCK_SIZE || cipher->block_size <= 0) {
        fprintf(stderr, "Error: Block size %d invalid (must be 1-%d)\n", cipher->block_size, BLOCK_SIZE);
        return;
    }
    
    /* Get the operation (all 127 final operations have pre-generated chains) */
    Operation *op = &g_operations[op_id];
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
        if (subop_idx < 0 || subop_idx >= g_base_ops_count) {
            fprintf(stderr, "Error: Invalid sub-op index %d in chain\n", subop_idx);
            continue;
        }
        
        Operation *subop = &g_base_operations[subop_idx];
        
        /* If sub-operation is dynamic (has its own chain), recursively apply it */
        if (subop->chain_length > 0) {
            /* Apply sub-operation's chain recursively */
            int sub_start = inverse ? (subop->chain_length - 1) : 0;
            int sub_end = inverse ? -1 : subop->chain_length;
            int sub_step = inverse ? -1 : 1;
            
            for (int sub_idx = sub_start; sub_idx != sub_end; sub_idx += sub_step) {
                int nested_subop_idx = subop->chain[sub_idx];
                if (nested_subop_idx < 0 || nested_subop_idx >= g_base_ops_count) continue;
                
                /* Use CACHED permutation for base operation */
                memcpy(temp, block, cipher->block_size);
                if (inverse) {
                    for (int i = 0; i < cipher->block_size; i++) {
                        block[i] = temp[cipher->base_op_cache[nested_subop_idx].inverse_perm[i]];
                    }
                } else {
                    for (int i = 0; i < cipher->block_size; i++) {
                        block[i] = temp[cipher->base_op_cache[nested_subop_idx].forward_perm[i]];
                    }
                }
            }
        } else {
            /* Base operation without chain - use CACHED permutation */
            memcpy(temp, block, cipher->block_size);
            if (inverse) {
                for (int i = 0; i < cipher->block_size; i++) {
                    block[i] = temp[cipher->base_op_cache[subop_idx].inverse_perm[i]];
                }
            } else {
                for (int i = 0; i < cipher->block_size; i++) {
                    block[i] = temp[cipher->base_op_cache[subop_idx].forward_perm[i]];
                }
            }
        }
    }
}

static void substitute_bytes(WBC1Cipher *cipher, uint8_t *block, int inverse) {
    for (int i = 0; i < cipher->block_size; i++) {
        block[i] = inverse ? cipher->inv_sbox[block[i]] : cipher->sbox[block[i]];
    }
}

/* XOR with round key */
static void xor_with_key(uint8_t *block, const uint8_t *key, int size) {
    for (int i = 0; i < size; i++) {
        block[i] ^= key[i];
    }
}

/* Cumulative XOR diffusion: Y[0]=X[0], Y[i]=X[i]^Y[i-1] */
static void cumulative_xor(uint8_t *block, int size, int inverse) {
    if (inverse) {
        /* Inverse: backward cumulative XOR */
        for (int i = size - 1; i > 0; i--) {
            block[i] ^= block[i - 1];
        }
    } else {
        /* Forward: cumulative XOR */
        for (int i = 1; i < size; i++) {
            block[i] ^= block[i - 1];
        }
    }
}

/* Cyclic bitwise rotation on all bytes */
static void cyclic_bitwise_rotate(uint8_t *block, int size, int shift, int direction) {
    shift = shift % 8;
    for (int i = 0; i < size; i++) {
        block[i] = (direction == 0) ? rotate_right(block[i], shift) : rotate_left(block[i], shift);
    }
}

/* ===== Cipher Operations ===== */

void wbc1_init(WBC1Cipher *cipher, const uint8_t *key, int key_len, int num_rounds, int algorithm_mode) {
    /* Initialize operations array (once) with metadata matching Python */
    init_operations(key, key_len);
    
    cipher->base_op_cache = NULL;  /* Initialize to NULL before allocation */
    cipher->cache_size = 0;
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
    
    /* PERFORMANCE OPTIMIZATION: Pre-compute all operation permutations */
    precompute_operation_cache(cipher);
}

void wbc1_free(WBC1Cipher *cipher) {
    if (cipher->key) {
        free(cipher->key);
        cipher->key = NULL;
    }
    if (cipher->base_op_cache) {
        free(cipher->base_op_cache);
        cipher->base_op_cache = NULL;
    }
}

void wbc1_encrypt_block(WBC1Cipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext) {
    memcpy(ciphertext, plaintext, cipher->block_size);
    
    for (int round = 0; round < cipher->num_rounds; round++) {
        /* 1. Dynamic Rubik's cube operation (using cached permutation) */
        /* Use first byte of round_key (SHA-256 ensures diversity across rounds) */
        int op_id = cipher->round_keys[round][0] % NUM_OPERATIONS;
        apply_operation_cached(cipher, ciphertext, op_id, 0);
        
        if (cipher->algorithm_mode == MODE_FULL) {
            /* 2. XOR with round key */
            xor_with_key(ciphertext, cipher->round_keys[round], cipher->block_size);
            
            /* 3. S-box substitution */
            substitute_bytes(cipher, ciphertext, 0);
            
            /* 4. Cumulative XOR diffusion */
            cumulative_xor(ciphertext, cipher->block_size, 0);
        }
        
        /* 5. Cyclic bitwise rotation */
        int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
        cyclic_bitwise_rotate(ciphertext, cipher->block_size, shift, 0);
    }
}

void wbc1_decrypt_block(WBC1Cipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext) {
    memcpy(plaintext, ciphertext, cipher->block_size);
    
    for (int round = cipher->num_rounds - 1; round >= 0; round--) {
        /* 5. Inverse cyclic bitwise rotation */
        int shift = (cipher->block_size > 1) ? cipher->round_keys[round][1] % 8 : round % 8;
        cyclic_bitwise_rotate(plaintext, cipher->block_size, shift, 1);
        
        if (cipher->algorithm_mode == MODE_FULL) {
            /* 4. Inverse cumulative XOR diffusion */
            cumulative_xor(plaintext, cipher->block_size, 1);
            
            /* 3. Inverse S-box substitution */
            substitute_bytes(cipher, plaintext, 1);
            
            /* 2. XOR with round key (self-inverse) */
            xor_with_key(plaintext, cipher->round_keys[round], cipher->block_size);
        }
        
        /* 1. Inverse dynamic Rubik's cube operation (using cached permutation) */
        /* Use first byte of round_key (SHA-256 ensures diversity across rounds) */
        int op_id = cipher->round_keys[round][0] % NUM_OPERATIONS;
        apply_operation_cached(cipher, plaintext, op_id, 1);
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
            if (padded_data) free(padded_data);
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
    
    /* Encrypt local blocks (using cached operations for performance) */
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
    
    /* Decrypt local blocks (using cached operations for performance) */
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

static int cmp_double_asc(const void *a, const void *b) {
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double aggregate_bench_time_local(const double *arr, int n, int trim_outliers) {
    if (!arr || n <= 0) return 0.0;
    if (!trim_outliers || n < 5) {
        double s = 0.0;
        for (int i = 0; i < n; i++) s += arr[i];
        return s / (double)n;
    }

    double tmp[64];
    int m = (n > 64) ? 64 : n;
    for (int i = 0; i < m; i++) tmp[i] = arr[i];
    qsort(tmp, m, sizeof(double), cmp_double_asc);

    int lo = 1, hi = m - 1;
    if (hi <= lo) {
        double s = 0.0;
        for (int i = 0; i < m; i++) s += tmp[i];
        return s / (double)m;
    }

    double s = 0.0;
    int cnt = 0;
    for (int i = lo; i < hi; i++) {
        s += tmp[i];
        cnt++;
    }
    return (cnt > 0) ? (s / (double)cnt) : tmp[m / 2];
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
                if (mhz > 0.0) break;
            }
        }
    }
    fclose(f);
    return mhz;
}

static uint8_t *generate_random_bytes_local(int len) {
    uint8_t *data = (uint8_t *)malloc((size_t)len);
    if (!data) return NULL;

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t got = fread(data, 1, (size_t)len, urandom);
        fclose(urandom);
        if (got == (size_t)len) return data;
    }

    srand((unsigned int)time(NULL));
    for (int i = 0; i < len; i++) data[i] = (uint8_t)(rand() & 0xFF);
    return data;
}

static const char *enc_mode_name(EncMode mode) {
    switch (mode) {
        case ENC_ECB: return "ecb";
        case ENC_CBC: return "cbc";
        case ENC_CFB: return "cfb";
        case ENC_OFB: return "ofb";
        case ENC_CTR: return "ctr";
        case ENC_WBC_CTR_HMAC: return "wbc-ctr-hmac";
        default: return "ecb";
    }
}

static int parse_enc_mode(const char *s, EncMode *out) {
    if (strcmp(s, "ecb") == 0) *out = ENC_ECB;
    else if (strcmp(s, "cbc") == 0) *out = ENC_CBC;
    else if (strcmp(s, "cfb") == 0) *out = ENC_CFB;
    else if (strcmp(s, "ofb") == 0) *out = ENC_OFB;
    else if (strcmp(s, "ctr") == 0) *out = ENC_CTR;
    else if (strcmp(s, "wbc-ctr-hmac") == 0 || strcmp(s, "ctr-hmac") == 0) *out = ENC_WBC_CTR_HMAC;
    else return 0;
    return 1;
}

static void xor_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int n) {
    for (int i = 0; i < n; i++) dst[i] = a[i] ^ b[i];
}

static void increment_counter(uint8_t ctr[BLOCK_SIZE]) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

static int mode_encrypt(WBC1Cipher *cipher, EncMode mode, const uint8_t *plaintext, int plaintext_len,
                        uint8_t **ciphertext, int *ciphertext_len) {
    if (!cipher || !plaintext || plaintext_len < 0 || !ciphertext || !ciphertext_len) return 0;

    if (mode == ENC_ECB) {
        parallel_encrypt(cipher, plaintext, plaintext_len, ciphertext, ciphertext_len);
        return (*ciphertext != NULL);
    }

    if (mode == ENC_CBC) {
        uint8_t *iv = generate_random_bytes_local(BLOCK_SIZE);
        uint8_t *padded = NULL;
        int padded_len = 0;
        if (!iv) return 0;
        pad_data(plaintext, plaintext_len, &padded, &padded_len);
        if (!padded) { free(iv); return 0; }

        int blocks = padded_len / BLOCK_SIZE;
        uint8_t *out = (uint8_t *)malloc((size_t)BLOCK_SIZE + (size_t)padded_len);
        uint8_t prev[BLOCK_SIZE], tmp[BLOCK_SIZE];
        if (!out) { free(iv); free(padded); return 0; }
        memcpy(out, iv, BLOCK_SIZE);
        memcpy(prev, iv, BLOCK_SIZE);

        for (int b = 0; b < blocks; b++) {
            xor_n(tmp, padded + b * BLOCK_SIZE, prev, BLOCK_SIZE);
            wbc1_encrypt_block(cipher, tmp, out + BLOCK_SIZE + b * BLOCK_SIZE);
            memcpy(prev, out + BLOCK_SIZE + b * BLOCK_SIZE, BLOCK_SIZE);
        }

        free(iv);
        free(padded);
        *ciphertext = out;
        *ciphertext_len = BLOCK_SIZE + padded_len;
        return 1;
    }

    if (mode == ENC_CFB || mode == ENC_OFB || mode == ENC_CTR || mode == ENC_WBC_CTR_HMAC) {
        uint8_t iv[BLOCK_SIZE], feedback[BLOCK_SIZE], stream[BLOCK_SIZE];
        uint8_t *hdr = generate_random_bytes_local(BLOCK_SIZE);
        if (!hdr) return 0;
        memcpy(iv, hdr, BLOCK_SIZE);
        memcpy(feedback, iv, BLOCK_SIZE);

        int out_len = BLOCK_SIZE + plaintext_len + ((mode == ENC_WBC_CTR_HMAC) ? 32 : 0);
        uint8_t *out = (uint8_t *)malloc((size_t)out_len);
        if (!out) { free(hdr); return 0; }
        memcpy(out, iv, BLOCK_SIZE);

        for (int off = 0; off < plaintext_len; off += BLOCK_SIZE) {
            int chunk = (plaintext_len - off > BLOCK_SIZE) ? BLOCK_SIZE : (plaintext_len - off);
            wbc1_encrypt_block(cipher, feedback, stream);

            for (int i = 0; i < chunk; i++) {
                out[BLOCK_SIZE + off + i] = plaintext[off + i] ^ stream[i];
            }

            if (mode == ENC_CFB) {
                memset(feedback, 0, BLOCK_SIZE);
                memcpy(feedback, out + BLOCK_SIZE + off, (size_t)chunk);
            } else if (mode == ENC_OFB) {
                memcpy(feedback, stream, BLOCK_SIZE);
            } else {
                increment_counter(feedback);
            }
        }

        if (mode == ENC_WBC_CTR_HMAC) {
            unsigned int mac_len = 0;
            unsigned char mac[EVP_MAX_MD_SIZE];
            HMAC(EVP_sha256(), cipher->key, cipher->key_len,
                 out, (size_t)(BLOCK_SIZE + plaintext_len), mac, &mac_len);
            memcpy(out + BLOCK_SIZE + plaintext_len, mac, 32);
        }

        free(hdr);
        *ciphertext = out;
        *ciphertext_len = out_len;
        return 1;
    }

    return 0;
}

static int mode_decrypt(WBC1Cipher *cipher, EncMode mode, const uint8_t *ciphertext, int ciphertext_len,
                        uint8_t **plaintext, int *plaintext_len) {
    if (!cipher || !ciphertext || ciphertext_len < 0 || !plaintext || !plaintext_len) return 0;

    if (mode == ENC_ECB) {
        parallel_decrypt(cipher, ciphertext, ciphertext_len, plaintext, plaintext_len);
        return (*plaintext != NULL);
    }

    if (ciphertext_len < BLOCK_SIZE) return 0;

    if (mode == ENC_CBC) {
        int body_len = ciphertext_len - BLOCK_SIZE;
        if (body_len <= 0 || (body_len % BLOCK_SIZE) != 0) return 0;

        int blocks = body_len / BLOCK_SIZE;
        uint8_t *tmp = (uint8_t *)malloc((size_t)body_len);
        uint8_t prev[BLOCK_SIZE], decb[BLOCK_SIZE];
        if (!tmp) return 0;

        memcpy(prev, ciphertext, BLOCK_SIZE);
        for (int b = 0; b < blocks; b++) {
            const uint8_t *cb = ciphertext + BLOCK_SIZE + b * BLOCK_SIZE;
            wbc1_decrypt_block(cipher, cb, decb);
            xor_n(tmp + b * BLOCK_SIZE, decb, prev, BLOCK_SIZE);
            memcpy(prev, cb, BLOCK_SIZE);
        }

        unpad_data(tmp, body_len, plaintext, plaintext_len);
        free(tmp);
        return (*plaintext != NULL);
    }

    if (mode == ENC_CFB || mode == ENC_OFB || mode == ENC_CTR || mode == ENC_WBC_CTR_HMAC) {
        int body_len = ciphertext_len - BLOCK_SIZE;
        if (mode == ENC_WBC_CTR_HMAC) {
            if (body_len < 32) return 0;
            int payload_len = body_len - 32;
            unsigned int mac_len = 0;
            unsigned char mac[EVP_MAX_MD_SIZE];
            HMAC(EVP_sha256(), cipher->key, cipher->key_len,
                 ciphertext, (size_t)(BLOCK_SIZE + payload_len), mac, &mac_len);
            if (memcmp(mac, ciphertext + BLOCK_SIZE + payload_len, 32) != 0) {
                return 0;
            }
            body_len = payload_len;
        }

        uint8_t iv[BLOCK_SIZE], feedback[BLOCK_SIZE], stream[BLOCK_SIZE];
        uint8_t *out = (uint8_t *)malloc((size_t)body_len);
        if (!out) return 0;

        memcpy(iv, ciphertext, BLOCK_SIZE);
        memcpy(feedback, iv, BLOCK_SIZE);

        for (int off = 0; off < body_len; off += BLOCK_SIZE) {
            int chunk = (body_len - off > BLOCK_SIZE) ? BLOCK_SIZE : (body_len - off);
            wbc1_encrypt_block(cipher, feedback, stream);

            for (int i = 0; i < chunk; i++) {
                out[off + i] = ciphertext[BLOCK_SIZE + off + i] ^ stream[i];
            }

            if (mode == ENC_CFB) {
                memset(feedback, 0, BLOCK_SIZE);
                memcpy(feedback, ciphertext + BLOCK_SIZE + off, (size_t)chunk);
            } else if (mode == ENC_OFB) {
                memcpy(feedback, stream, BLOCK_SIZE);
            } else {
                increment_counter(feedback);
            }
        }

        *plaintext = out;
        *plaintext_len = body_len;
        return 1;
    }

    return 0;
}

static int run_self_tests(WBC1Cipher *cipher, EncMode mode, int rank) {
    typedef struct {
        const char *name;
        const uint8_t *data;
        int len;
    } SelfTestCase;

    static const uint8_t t_short[] = "Hello, WBC!";
    static const uint8_t t_block[] =
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    static const uint8_t t_single[] = "X";

    uint8_t all_vals[256];
    uint8_t bin100[100];
    uint8_t b10k[10000];
    uint8_t b100k[100000];

    for (int i = 0; i < 256; i++) all_vals[i] = (uint8_t)i;
    for (int i = 0; i < 100; i++) bin100[i] = (uint8_t)((i * 37 + 11) & 0xFF);
    for (int i = 0; i < 10000; i++) b10k[i] = (uint8_t)((i * 17 + 3) & 0xFF);
    for (int i = 0; i < 100000; i++) b100k[i] = (uint8_t)((i * 29 + 7) & 0xFF);

    const uint8_t t300_data[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor.";

    SelfTestCase tests[] = {
        {"Short text", t_short, (int)strlen((const char *)t_short)},
        {"One block (64B)", t_block, 64},
        {"300 bytes", t300_data, 300},
        {"Binary (100B)", bin100, 100},
        {"Empty input", (const uint8_t *)"", 0},
        {"All byte values", all_vals, 256},
        {"Single byte", t_single, 1},
        {"10 000 bytes", b10k, 10000},
        {"100 000 bytes", b100k, 100000},
    };

    int total = (int)(sizeof(tests) / sizeof(tests[0]));
    int passed = 0;

    if (rank == 0) {
        printf("\n  Self-tests  |  mode=%s  cascade=DOUBLE\n", enc_mode_name(mode));
        printf("────────────────────────────────────────────────────────────\n");
    }

    for (int i = 0; i < total; i++) {
        uint8_t *enc = NULL;
        int enc_len = 0;
        uint8_t *dec = NULL;
        int dec_len = 0;

        int ok = mode_encrypt(cipher, mode, tests[i].data, tests[i].len, &enc, &enc_len) &&
                 mode_decrypt(cipher, mode, enc, enc_len, &dec, &dec_len) &&
                 (dec_len == tests[i].len) &&
                 (tests[i].len == 0 || memcmp(dec, tests[i].data, (size_t)tests[i].len) == 0);

        if (ok) passed++;

        if (rank == 0) {
            printf("  %-35s %s\n", tests[i].name, ok ? "PASS ✓" : "FAIL ✗");
        }

        if (enc) free(enc);
        if (dec) free(dec);
    }

    if (rank == 0) {
        printf("────────────────────────────────────────────────────────────\n");
        printf("  Results: %d/%d passed\n\n", passed, total);
    }

    return (passed == total) ? 0 : 1;
}

static void benchmark_core(WBC1Cipher *cipher, EncMode enc_mode) {
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    static const int sizes_bytes[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000};
    int ns = (int)(sizeof(sizes_bytes) / sizeof(sizes_bytes[0]));
    int repeats = 10;
    int trim_outliers = 1;

    double enc_kbs[8] = {0.0};
    double dec_kbs[8] = {0.0};

    if (rank == 0) {
        printf("\nPerformance Benchmark / Бенчмарк производительности (MPI-aware):\n");
        printf("  Encryption mode: %s\n", enc_mode_name(enc_mode));
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  %s\n",
               "Size (KB)", "Enc (s)", "Enc (KB/s)", "Dec (KB/s)",
               "Enc (MB/s)", "Dec (MB/s)", "Enc (Mbit/s)", "Dec (Mbit/s)", "Integrity");
        printf("  %s\n", "--------------------------------------------------------------------------------------------------------------");
        printf("  Timing mode: legacy barrier/root\n");
        printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers ? "trimmed mean" : "mean");
    }

    for (int si = 0; si < ns; si++) {
        int size_bytes = sizes_bytes[si];
        uint8_t *plain = NULL;
        int all_ok = 1;

        if (rank == 0) {
            plain = generate_random_bytes_local(size_bytes);
            if (!plain) all_ok = 0;
        }

        MPI_Bcast(&all_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
        if (!all_ok) {
            if (rank == 0) fprintf(stderr, "Error: benchmark data allocation failed\n");
            if (plain) free(plain);
            break;
        }

        double enc_times[64] = {0.0};
        double dec_times[64] = {0.0};

        for (int r = 0; r < repeats; r++) {
            uint8_t *enc = NULL;
            uint8_t *dec = NULL;
            int enc_len = 0;
            int dec_len = 0;

            MPI_Barrier(MPI_COMM_WORLD);
            double t0 = MPI_Wtime();
            if (rank == 0) {
                mode_encrypt(cipher, enc_mode, plain, size_bytes, &enc, &enc_len);
            } else {
                mode_encrypt(cipher, enc_mode, NULL, 0, &enc, &enc_len);
            }
            MPI_Barrier(MPI_COMM_WORLD);
            if (rank == 0) enc_times[r] = MPI_Wtime() - t0;

            MPI_Barrier(MPI_COMM_WORLD);
            double t1 = MPI_Wtime();
            if (rank == 0) {
                mode_decrypt(cipher, enc_mode, enc, enc_len, &dec, &dec_len);
            } else {
                mode_decrypt(cipher, enc_mode, NULL, 0, &dec, &dec_len);
            }
            MPI_Barrier(MPI_COMM_WORLD);
            if (rank == 0) dec_times[r] = MPI_Wtime() - t1;

            if (rank == 0) {
                if (!dec || dec_len != size_bytes || memcmp(plain, dec, (size_t)size_bytes) != 0) {
                    all_ok = 0;
                }
            }

            if (enc) free(enc);
            if (dec) free(dec);
        }

        if (rank == 0) {
            double ea = aggregate_bench_time_local(enc_times, repeats, trim_outliers);
            double da = aggregate_bench_time_local(dec_times, repeats, trim_outliers);

            double size_kb = (double)size_bytes / 1024.0;
            double enc_kb_s = size_kb / (ea > 0.0 ? ea : 1e-9);
            double dec_kb_s = size_kb / (da > 0.0 ? da : 1e-9);
            double enc_mb_s = ((double)size_bytes / 1e6) / (ea > 0.0 ? ea : 1e-9);
            double dec_mb_s = ((double)size_bytes / 1e6) / (da > 0.0 ? da : 1e-9);

            enc_kbs[si] = enc_kb_s;
            dec_kbs[si] = dec_kb_s;

            printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
                   size_kb, ea, enc_kb_s, dec_kb_s,
                   enc_mb_s, dec_mb_s, enc_mb_s * 8.0, dec_mb_s * 8.0,
                   all_ok ? "OK" : "FAIL");
        }

        if (plain) free(plain);
    }

    if (rank == 0) {
        double cpu_mhz = read_cpu_mhz();
        if (cpu_mhz > 0.0) {
            printf("\n  --- Цикли / байт  (CPU: %.0f МГц) ---\n", cpu_mhz);
            printf("  %10s  %8s  %8s  %12s  %12s  %10s  %10s\n",
                   "Size (KB)", "Enc CPB", "Dec CPB", "E Cyc/blk", "D Cyc/blk", "E B/cycle", "D B/cycle");
            printf("  %s\n", "--------------------------------------------------------------------------");
            for (int si = 0; si < ns; si++) {
                double ecpb = (enc_kbs[si] > 0.0) ? cpu_mhz * 1e6 / (enc_kbs[si] * 1024.0) : 0.0;
                double dcpb = (dec_kbs[si] > 0.0) ? cpu_mhz * 1e6 / (dec_kbs[si] * 1024.0) : 0.0;
                double size_kb = (double)sizes_bytes[si] / 1024.0;
                printf("  %10.2f  %8.2f  %8.2f  %12.0f  %12.0f  %10.5f  %10.5f\n",
                       size_kb, ecpb, dcpb,
                       ecpb * (double)BLOCK_SIZE, dcpb * (double)BLOCK_SIZE,
                       (ecpb > 0.0) ? 1.0 / ecpb : 0.0,
                       (dcpb > 0.0) ? 1.0 / dcpb : 0.0);
            }
        } else {
            printf("\n  CPB: частота CPU недоступна\n");
        }
        printf("\n");
    }
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
     * task: 0=text encryption, 1=statistical analysis
     * data_kb: data size in KB for task=1
     */
    int algorithm_mode = MODE_FULL;
    int key_bits = 256;
    /* Note: key_source is parsed for compatibility with Python interface but not used */
    /* C version always auto-generates keys based on key_bits parameter */
    int num_rounds = 16;
    int task = 0;  /* 0=text encryption, 1=statistical analysis, 2=selftest, 3=benchmark */
    EncMode enc_mode = ENC_ECB;
    int data_kb = 1;  /* Data size in KB for task=1 */
    int use_named_cli = 0;
    const char *custom_text = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--", 2) == 0) {
            use_named_cli = 1;
            break;
        }
    }
    
    /* Parse command-line arguments */
    if (use_named_cli) {
        task = -1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--single") == 0 || strcmp(argv[i], "--once") == 0) {
                /* Compatibility no-op */
                continue;
            }

            if (strcmp(argv[i], "--task-encrypt") == 0 || strcmp(argv[i], "--encrypt") == 0) {
                task = 0;
            } else if (strcmp(argv[i], "--task-analysis") == 0 || strcmp(argv[i], "--analysis") == 0 ||
                       strcmp(argv[i], "--stats") == 0 || strcmp(argv[i], "--task-stats") == 0) {
                task = 1;
            } else if (strcmp(argv[i], "--task-selftest") == 0 || strcmp(argv[i], "--selftest") == 0 ||
                       strcmp(argv[i], "--task-test") == 0 || strcmp(argv[i], "--test") == 0) {
                task = 2;
            } else if (strcmp(argv[i], "--task-benchmark") == 0 || strcmp(argv[i], "--task-behchmark") == 0 || strcmp(argv[i], "--benchmark") == 0 ||
                       strcmp(argv[i], "--bench") == 0) {
                task = 3;
            } else if ((strcmp(argv[i], "--task") == 0 || strcmp(argv[i], "-t") == 0) && i + 1 < argc) {
                const char *v = argv[++i];
                if (strcmp(v, "0") == 0 || strcmp(v, "encrypt") == 0 || strcmp(v, "demo") == 0) task = 0;
                else if (strcmp(v, "1") == 0 || strcmp(v, "analysis") == 0 || strcmp(v, "stats") == 0 ||
                         strcmp(v, "stat") == 0) task = 1;
                else if (strcmp(v, "2") == 0 || strcmp(v, "selftest") == 0 || strcmp(v, "test") == 0) task = 2;
                else if (strcmp(v, "3") == 0 || strcmp(v, "benchmark") == 0 || strcmp(v, "bench") == 0 || strcmp(v, "behchmark") == 0) task = 3;
            } else if ((strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc) {
                const char *v = argv[++i];
                if (strcmp(v, "full") == 0 || strcmp(v, "1") == 0) algorithm_mode = MODE_FULL;
                else if (strcmp(v, "simple") == 0 || strcmp(v, "simplified") == 0 || strcmp(v, "0") == 0)
                    algorithm_mode = MODE_FULL;
                else {
                    EncMode parsed;
                    if (parse_enc_mode(v, &parsed)) enc_mode = parsed;
                }
            } else if (strcmp(argv[i], "--algo-mode") == 0 && i + 1 < argc) {
                const char *v = argv[++i];
                if (strcmp(v, "full") == 0 || strcmp(v, "1") == 0) algorithm_mode = MODE_FULL;
                else if (strcmp(v, "simple") == 0 || strcmp(v, "simplified") == 0 || strcmp(v, "0") == 0)
                    algorithm_mode = MODE_FULL;
            } else if (strcmp(argv[i], "--enc-mode") == 0 && i + 1 < argc) {
                EncMode parsed;
                if (parse_enc_mode(argv[++i], &parsed)) enc_mode = parsed;
            } else if ((strcmp(argv[i], "--key-size") == 0 || strcmp(argv[i], "-k") == 0) && i + 1 < argc) {
                key_bits = atoi(argv[++i]);
            } else if ((strcmp(argv[i], "--rounds") == 0 || strcmp(argv[i], "-r") == 0) && i + 1 < argc) {
                num_rounds = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
                data_kb = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) {
                custom_text = argv[++i];
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                if (rank == 0) {
                    printf("Usage (named): %s --task <encrypt|analysis|selftest|benchmark> [--mode full|ecb|cbc|cfb|ofb|ctr|wbc-ctr-hmac] [--enc-mode ecb|cbc|cfb|ofb|ctr|wbc-ctr-hmac] [--key-size 256] [--rounds N] [--size KB] [--text STRING]\n", argv[0]);
                    printf("Algorithm mode is fixed to full in this build\n");
                    printf("Aliases: --task-encrypt, --task-analysis, --task-selftest, --task-benchmark\n");
                    printf("Compatibility: --single and --once are accepted as no-op flags\n");
                    printf("Usage (legacy): %s <algorithm_mode> <key_bits> <key_source> <rounds> <task> [data_kb]\n", argv[0]);
                }
                MPI_Finalize();
                return 0;
            }
        }

        if (task < 0) task = 0;
        if (data_kb < 1) data_kb = 1;
    } else if (argc >= 5) {
        algorithm_mode = atoi(argv[1]);
        key_bits = atoi(argv[2]);
        /* argv[3] is key_source, parsed but unused - kept for Python compatibility */
        num_rounds = atoi(argv[4]);
        if (argc >= 6) {
            task = atoi(argv[5]);
        }
        if (argc >= 7 && (task == 1 || task == 3)) {
            data_kb = atoi(argv[6]);
        }
    } else if (rank == 0) {
        printf("Usage (named): %s --task <encrypt|analysis|selftest|benchmark> [--mode full|ecb|cbc|cfb|ofb|ctr|wbc-ctr-hmac] [--enc-mode ecb|cbc|cfb|ofb|ctr|wbc-ctr-hmac] [--key-size 256] [--rounds N] [--size KB] [--text STRING]\n", argv[0]);
        printf("Algorithm mode is fixed to full in this build\n");
        printf("Usage (legacy): %s <algorithm_mode> <key_bits> <key_source> <rounds> <task> [data_kb]\n", argv[0]);
        printf("  algorithm_mode: 0=simplified (2 ops), 1=full (5 ops)\n");
        printf("  task: 0=text encryption, 1=statistical analysis, 2=selftest, 3=benchmark\n");
        printf("Example: %s --task-benchmark --mode ctr --algo-mode full --key-size 256 --rounds 16\n", argv[0]);
    }

    algorithm_mode = MODE_FULL;
    if (num_rounds < 1) num_rounds = 1;
    if (num_rounds > MAX_ROUNDS) num_rounds = MAX_ROUNDS;
    
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
    } else if (task == 2 || task == 3) {
        plain_len = 0;
        plaintext = NULL;
    } else {
        /* Text encryption mode - use demo text */
        const char *plaintext_str = custom_text ? custom_text :
                                   "This is a demonstration of the WBC1 parallel cipher with dynamic Rubik's cube permutation operations. "
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
        printf("=== Parallel WBC1 Cipher (C Implementation - CACHED OPERATIONS) ===\n");
        printf("Number of MPI processes: %d\n", size);
        printf("Algorithm mode: %s\n", algorithm_mode == MODE_FULL ? "Full (5 operations)" : "Simplified (2 operations)");
        printf("Encryption mode: %s\n", enc_mode_name(enc_mode));
        printf("Key size: %d bits (%d bytes)\n", key_bits, key_len);
        printf("Block size: %d bytes\n", BLOCK_SIZE);
        printf("Number of rounds: %d\n", num_rounds);
        printf("Optimization: Pre-computed operation cache enabled\n");
        printf("Task: %s\n", task == 0 ? "Text encryption" : (task == 1 ? "Statistical analysis" : (task == 2 ? "Self-tests" : "Benchmark")));
        if (task == 1) {
            printf("Data size: %d KB (%d bytes)\n", data_kb, plain_len);
        }
        if (task != 3) {
            printf("\nOriginal plaintext length: %d bytes\n", plain_len);
            if (task == 0 && plain_len <= 200) {
                printf("Original plaintext: %.*s\n\n", plain_len, plaintext);
            } else if (task == 0) {
                printf("Original plaintext: %.80s...\n\n", plaintext);
            } else {
                printf("Original data (first 64 bytes, hex): ");
                for (int i = 0; i < 64 && i < plain_len; i++) {
                    printf("%02x", plaintext[i]);
                }
                printf("...\n\n");
            }
        }
    }
    
    /* Initialize cipher (this pre-computes all operation permutations) */
    double init_start = MPI_Wtime();
    WBC1Cipher cipher;
    wbc1_init(&cipher, key, key_len, num_rounds, algorithm_mode);
    double init_time = MPI_Wtime() - init_start;
    
    if (rank == 0) {
        printf("Cipher initialization time (with cache): %.6f seconds\n\n", init_time);
    }

    if (task == 3) {
        benchmark_core(&cipher, enc_mode);
        free(key);
        free(plaintext);
        wbc1_free(&cipher);
        MPI_Finalize();
        return 0;
    }

    if (task == 2) {
        int rc = run_self_tests(&cipher, enc_mode, rank);
        free(key);
        free(plaintext);
        wbc1_free(&cipher);
        MPI_Finalize();
        return rc;
    }
    
    /* Encrypt */
    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();
    uint8_t *ciphertext = NULL;
    int ciphertext_len = 0;
    if (!mode_encrypt(&cipher, enc_mode, plaintext, plain_len, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "Error: encryption failed for mode %s\n", enc_mode_name(enc_mode));
        free(key);
        free(plaintext);
        wbc1_free(&cipher);
        MPI_Finalize();
        return 1;
    }
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
    if (!mode_decrypt(&cipher, enc_mode, ciphertext, ciphertext_len, &decrypted, &decrypted_len)) {
        fprintf(stderr, "Error: decryption failed for mode %s\n", enc_mode_name(enc_mode));
        free(key);
        free(plaintext);
        free(ciphertext);
        wbc1_free(&cipher);
        MPI_Finalize();
        return 1;
    }
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
            printf("✓ Encryption/Decryption successful - output matches input!\n");
        } else {
            printf("✗ Error: Decrypted text does not match original!\n");
        }
        
        /* Statistical analysis for task==1 */
        if (task == 1) {
            printf("\n");
            printf("=" "==========================================\n");
            printf("  CRYPTOGRAPHIC QUALITY ANALYSIS\n");
            printf("=" "==========================================\n\n");
            
            // Shannon entropy
            double entropy_plain = shannon_entropy(plaintext, plain_len);
            double entropy_cipher = shannon_entropy(ciphertext, ciphertext_len);
            printf("1. Shannon Entropy (Randomness Test)\n");
            printf("   ────────────────────────────────\n");
            printf("   Plaintext:   %.6f bits/byte\n", entropy_plain);
            printf("   Ciphertext:  %.6f bits/byte", entropy_cipher);
            if (entropy_cipher >= 7.9) {
                printf("  ✓ EXCELLENT (≥7.9 expected)\n");
            } else if (entropy_cipher >= 7.5) {
                printf("  ⚠ ACCEPTABLE (7.5-7.9)\n");
            } else {
                printf("  ✗ POOR (<7.5)\n");
            }
            
            // Avalanche test
            printf("\n2. Avalanche Effect (Bit Diffusion Test)\n");
            printf("   ────────────────────────────────────\n");
            printf("   Testing: 1-bit input change → output bit changes\n");
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
            
            printf("   Mean:        %.2f%%", av_mean);
            if (av_mean >= 45.0 && av_mean <= 55.0) {
                printf("  ✓ EXCELLENT (45-55%% expected)\n");
            } else if (av_mean >= 40.0 && av_mean <= 60.0) {
                printf("  ⚠ ACCEPTABLE (40-60%%)\n");
            } else {
                printf("  ✗ POOR (far from 50%%)\n");
            }
            printf("   Std Dev:     %.2f%%\n", av_std);
            printf("   Range:       %.2f%% - %.2f%%\n", av_min, av_max);
            printf("   Iterations:  100 tests\n");
            
            // Frequency test
            double freq_mean, freq_std, freq_chi;
            frequency_test(ciphertext, ciphertext_len, &freq_mean, &freq_std, &freq_chi);
            printf("\n3. Frequency Distribution Analysis\n");
            printf("   ────────────────────────────────\n");
            printf("   Mean frequency:   %.2f bytes/value\n", freq_mean);
            printf("   Std deviation:    %.2f\n", freq_std);
            printf("   Chi-square:       %.2f", freq_chi);
            if (freq_chi < 300) {
                printf("  ✓ GOOD (uniform distribution)\n");
            } else {
                printf("  ⚠ Check distribution\n");
            }
            
            // Correlation - compare plaintext with ciphertext (should be low)
            double corr = correlation_test(plaintext, ciphertext, plain_len < ciphertext_len ? plain_len : ciphertext_len);
            printf("\n4. Correlation Test (Independence)\n");
            printf("   ────────────────────────────────\n");
            printf("   Plaintext-Ciphertext: %.6f", corr);
            if (fabs(corr) < 0.1) {
                printf("  ✓ EXCELLENT (<0.1 expected)\n");
            } else if (fabs(corr) < 0.3) {
                printf("  ⚠ ACCEPTABLE (0.1-0.3)\n");
            } else {
                printf("  ✗ POOR (>0.3, shows correlation)\n");
            }
            
            // Differential test - key sensitivity  
            printf("\n5. Differential Test (Key Sensitivity)\n");
            printf("   ────────────────────────────────────\n");
            printf("   Testing: 1-bit key change → output bit changes\n");
            
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
            printf("   Mean:        %.2f%%", diff_effect * 100.0);
            if (diff_effect * 100.0 >= 45.0 && diff_effect * 100.0 <= 55.0) {
                printf("  ✓ EXCELLENT (45-55%% expected)\n");
            } else if (diff_effect * 100.0 >= 40.0 && diff_effect * 100.0 <= 60.0) {
                printf("  ⚠ ACCEPTABLE (40-60%%)\n");
            } else {
                printf("  ✗ POOR (far from 50%%)\n");
            }
            printf("   Key bits tested: 256\n");
            
            // Performance summary
            double throughput_enc = (plain_len / 1024.0) / enc_time;
            double throughput_dec = (decrypted_len / 1024.0) / dec_time;
            printf("\n6. Performance Metrics\n");
            printf("   ───────────────────\n");
            printf("   Encryption:  %.2f KB/s (%.6f sec for %d KB)\n", 
                   throughput_enc, enc_time, plain_len/1024);
            printf("   Decryption:  %.2f KB/s (%.6f sec for %d KB)\n",
                   throughput_dec, dec_time, decrypted_len/1024);
            printf("   MPI Processes: %d\n", size);
            
            printf("\n" "==========================================\n");
            printf("  ANALYSIS COMPLETE\n");
            printf("=" "==========================================\n");
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
