/*
 * WBC1 Original Algorithm - Sequential Implementation (no MPI)
 *
 * Based on wbc1_original_parallel.c with MPI removed.
 *
 * Algorithm:
 * 1. Divide text T into blocks: T = {B1, B2, ..., Bk}, k = n/s
 * 2. For each block B_i:
 *    a. Write block into 3D cube d×d×d
 *    b. For each BYTE j of key K:
 *       - mixed = mix_key_byte(K[j])
 *       - Select operation: O = P[mixed mod 127]
 *       - Apply operation O to block
 *       - Perform cyclic bitwise shift by d bits
 *    c. Extract block
 * 3. Combine encrypted blocks
 *
 * Usage: ./wbc1_original_p <task> <key_size> <key_source> <block_size_bits> [mode] [data_size_kb]
 *   task: 0=encrypt/decrypt, 1=statistical tests, 2=print operations table
 *   key_size: 128, 192, 256
 *   key_source: 0=random, 1=sequential (0,1,2,...)
 *   block_size_bits: 32, 64, 128, 512, or 0=auto
 *   mode: (task 0) 0=demo text, 1=random data
 *         (task 1) unused
 *   data_size_kb: data size in KB
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_BLOCK_SIZE 64  /* Maximum block size in bytes (512 bits) */
#define NUM_OPERATIONS 127
#define MAX_OP_STRING  256

/* ── Operation structure ─────────────────────────────────────────────────── */
typedef struct {
    char type[32];
    char param1[64];
    char param2[64];
    char desc[128];
    char str_repr[MAX_OP_STRING];
    int  chain_length;
    int  chain[8];
} Operation;

/* ── Cipher structure ────────────────────────────────────────────────────── */
typedef struct {
    uint8_t   *key;
    int        key_len_bytes;
    int        key_len_bits;
    int        block_size_bits;
    int        block_size_bytes;
    int        cube_d;
    Operation *operations;
    Operation *base_operations;
    int        base_ops_count;
} WBC1OriginalCipher;

/* ── Timing helper ───────────────────────────────────────────────────────── */
static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ── SHA-256 wrapper ─────────────────────────────────────────────────────── */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

/* ── Mersenne Twister MT19937 ────────────────────────────────────────────── */
typedef struct { uint32_t mt[624]; int index; } MT19937InitState;

static void mt_init_seed(MT19937InitState *state, uint32_t seed) {
    state->mt[0] = seed;
    for (int i = 1; i < 624; i++)
        state->mt[i] = (1812433253UL * (state->mt[i-1] ^ (state->mt[i-1] >> 30)) + i);
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
    y ^= y >> 11; y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL; y ^= y >> 18;
    return y;
}

/* ── Key bit helper ──────────────────────────────────────────────────────── */
static int get_key_bit(const uint8_t *key, int bit_index, int key_len_bytes) {
    int byte_idx = (bit_index / 8) % key_len_bytes;
    int bit_pos  = 7 - (bit_index % 8);
    return (key[byte_idx] >> bit_pos) & 1;
}

/* ── Cyclic bitwise shift ────────────────────────────────────────────────── */
/* MixCube: chain-XOR diffusion — each byte XORed with the previous.
 * Invertible for any block size. */
static void mix_cube(uint8_t *data, int n) {
    for (int i = 1; i < n; i++) data[i] ^= data[i-1];
}
static void inv_mix_cube(uint8_t *data, int n) {
    for (int i = n-1; i >= 1; i--) data[i] ^= data[i-1];
}

static void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits) {
    if (shift_bits == 0 || size_bytes == 0) return;
    int total_bits = size_bytes * 8;
    shift_bits = shift_bits % total_bits;
    if (shift_bits < 0) shift_bits += total_bits;

    uint8_t *temp = (uint8_t *)malloc(size_bytes);
    memcpy(temp, block, size_bytes);

    for (int i = 0; i < total_bits; i++) {
        int src_bit  = (i + shift_bits) % total_bits;
        int src_byte = src_bit / 8, src_pos = 7 - (src_bit % 8);
        int dst_byte = i / 8,       dst_pos = 7 - (i % 8);
        int bit_val  = (temp[src_byte] >> src_pos) & 1;
        if (bit_val) block[dst_byte] |=  (1 << dst_pos);
        else         block[dst_byte] &= ~(1 << dst_pos);
    }
    free(temp);
}

/* ── init_operations ─────────────────────────────────────────────────────── */
static void init_operations(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len) {
    cipher->operations     = (Operation *)calloc(NUM_OPERATIONS, sizeof(Operation));
    cipher->base_operations= (Operation *)calloc(300,           sizeof(Operation));
    if (!cipher->operations || !cipher->base_operations) {
        fprintf(stderr, "Error: Memory allocation failed for operations\n");
        return;
    }

    Operation temp_ops[300];
    int temp_idx = 0;

    /* Face rotations: 6 × 4 = 24 */
    const char *faces[] = {"U","D","L","R","F","B"};
    const char *dirs[]  = {"","'","2","3"};
    for (int f = 0; f < 6; f++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "face");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", faces[f]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Rotate %s face %s", faces[f], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('face', '%s', '%s', 'Rotate %s face %s')", faces[f], dirs[d], faces[f], dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    /* Slice moves: 3 × 4 = 12 */
    const char *slices[] = {"M","E","S"};
    for (int s = 0; s < 3; s++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "slice");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", slices[s]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Rotate %s slice %s", slices[s], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('slice', '%s', '%s', 'Rotate %s slice %s')", slices[s], dirs[d], slices[s], dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    /* Wide moves: 6 × 4 = 24 */
    const char *wide_moves[] = {"u","d","l","r","f","b"};
    for (int w = 0; w < 6; w++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "wide");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", wide_moves[w]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Wide move %s%s", wide_moves[w], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('wide', '%s', '%s', 'Wide move %s%s')", wide_moves[w], dirs[d], wide_moves[w], dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    /* Cube rotations: 3 × 4 = 12 */
    const char *cube_rot[] = {"x","y","z"};
    for (int r = 0; r < 3; r++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "cube");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", cube_rot[r]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Cube rotation %s%s", cube_rot[r], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('cube', '%s', '%s', 'Cube rotation %s%s')", cube_rot[r], dirs[d], cube_rot[r], dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    /* Swap: 3 × 4 = 12 */
    for (int axis = 0; axis < 3; axis++) for (int k = 0; k < 4; k++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "swap");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", axis);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%d", k);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Swap axis=%d, offset=%d", axis, k);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('swap', %d, %d, 'Swap axis=%d, offset=%d')", axis, k, axis, k);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    /* Diagonal flip: 3 */
    for (int axis = 0; axis < 3; axis++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "diagflip");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", axis);
        temp_ops[temp_idx].param2[0] = '\0';
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Diagonal flip axis=%d", axis);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('diagflip', %d, '', 'Diagonal flip axis=%d')", axis, axis);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }

    int static_ops_count = temp_idx; /* 87 */

    /* 20 dynamic operations */
    for (int i = 0; i < 20; i++) {
        uint8_t seed_input[256];
        memcpy(seed_input, key, (size_t)key_len);
        seed_input[key_len]     = (uint8_t)(i & 0xFF);
        seed_input[key_len + 1] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(seed_input, (size_t)(key_len + 2), hash);
        uint32_t seed = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                        ((uint32_t)hash[2] << 8)  |  (uint32_t)hash[3];
        MT19937InitState rng; mt_init_seed(&rng, seed);
        int n_ops = 4 + (int)(mt_random_init(&rng) % 4);
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "dynamic");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", i);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"ops");
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Dynamic pattern %d", i);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('dynamic', %d, 'ops', 'Dynamic pattern %d')", i, i);
        temp_ops[temp_idx].chain_length = n_ops;
        for (int j = 0; j < n_ops; j++)
            temp_ops[temp_idx].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)static_ops_count);
        temp_idx++;
    }

    int all_ops_count = temp_idx; /* 107 */
    memcpy(cipher->base_operations, temp_ops, sizeof(Operation) * (size_t)all_ops_count);
    cipher->base_ops_count = all_ops_count;

    /* 127 final operations */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        uint8_t seed_input[256];
        memcpy(seed_input, key, (size_t)key_len);
        memcpy(seed_input + key_len, "WBC1_OP", 7);
        seed_input[key_len + 7] = (uint8_t)(i & 0xFF);
        seed_input[key_len + 8] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_hash(seed_input, (size_t)(key_len + 9), hash);
        uint32_t seed = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                        ((uint32_t)hash[2] << 8)  |  (uint32_t)hash[3];
        MT19937InitState rng; mt_init_seed(&rng, seed);
        int chain_len = 3 + (int)(mt_random_init(&rng) % 4);
        snprintf(cipher->operations[i].type,    sizeof(cipher->operations[0].type),  "dynamic");
        snprintf(cipher->operations[i].param1,  sizeof(cipher->operations[0].param1),"%d", i);
        snprintf(cipher->operations[i].param2,  sizeof(cipher->operations[0].param2),"chain");
        snprintf(cipher->operations[i].desc,    sizeof(cipher->operations[0].desc),  "Operation %d", i);
        snprintf(cipher->operations[i].str_repr,sizeof(cipher->operations[0].str_repr),
                 "('dynamic', %d, 'chain', 'Operation %d')", i, i);
        cipher->operations[i].chain_length = chain_len;
        for (int j = 0; j < chain_len; j++)
            cipher->operations[i].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)all_ops_count);
    }
}

/* ── apply_operation: simple byte-rotation permutation ──────────────────── */
static void apply_operation(WBC1OriginalCipher *cipher, uint8_t *block, int op_id, int inverse) {
    int size  = cipher->block_size_bytes;
    uint8_t temp[MAX_BLOCK_SIZE];
    memcpy(temp, block, (size_t)size);
    int shift = (op_id % size) + 1;
    if (inverse) shift = size - shift;
    for (int i = 0; i < size; i++)
        block[i] = temp[(i + shift) % size];
}

/* ── mix_key_byte ────────────────────────────────────────────────────────── */
static uint8_t mix_key_byte(uint8_t byte) {
    uint8_t mixed = byte;
    mixed ^= (byte >> 4);
    mixed ^= ((byte << 3) | (byte >> 5));
    mixed ^= (byte >> 1);
    return mixed;
}

/* ── Cipher init/free ────────────────────────────────────────────────────── */
static void wbc1_original_init(WBC1OriginalCipher *cipher,
                                const uint8_t *key, int key_len, int block_size_bits) {
    memset(cipher, 0, sizeof(WBC1OriginalCipher));
    cipher->key_len_bytes  = key_len;
    cipher->key_len_bits   = key_len * 8;
    cipher->key = (uint8_t *)malloc((size_t)key_len);
    memcpy(cipher->key, key, (size_t)key_len);
    cipher->block_size_bits  = block_size_bits;
    cipher->block_size_bytes = block_size_bits / 8;
    switch (block_size_bits) {
        case 32:  cipher->cube_d = 2; break;
        case 64:  cipher->cube_d = 4; break;
        case 128: cipher->cube_d = 4; break;
        case 512: cipher->cube_d = 8; break;
        default:  cipher->cube_d = 4; break;
    }
    init_operations(cipher, cipher->key, cipher->key_len_bytes);
}

static void wbc1_original_free(WBC1OriginalCipher *cipher) {
    if (cipher->key)             free(cipher->key);
    if (cipher->operations)      free(cipher->operations);
    if (cipher->base_operations) free(cipher->base_operations);
    memset(cipher, 0, sizeof(WBC1OriginalCipher));
}

/* ── Block encrypt/decrypt ───────────────────────────────────────────────── */
static void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher,
                                         const uint8_t *plaintext, uint8_t *ciphertext) {
    memcpy(ciphertext, plaintext, (size_t)cipher->block_size_bytes);
    for (int byte_idx = 0; byte_idx < cipher->key_len_bytes; byte_idx++) {
        uint8_t mixed_byte = mix_key_byte(cipher->key[byte_idx]);
        int op_id = mixed_byte % NUM_OPERATIONS;
        apply_operation(cipher, ciphertext, op_id, 0);
        mix_cube(ciphertext, cipher->block_size_bytes);
        cyclic_bitwise_shift(ciphertext, cipher->block_size_bytes, cipher->cube_d);
    }
}

static void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher,
                                         const uint8_t *ciphertext, uint8_t *plaintext) {
    memcpy(plaintext, ciphertext, (size_t)cipher->block_size_bytes);
    for (int byte_idx = cipher->key_len_bytes - 1; byte_idx >= 0; byte_idx--) {
        cyclic_bitwise_shift(plaintext, cipher->block_size_bytes, -cipher->cube_d);
        inv_mix_cube(plaintext, cipher->block_size_bytes);
        uint8_t mixed_byte = mix_key_byte(cipher->key[byte_idx]);
        int op_id = mixed_byte % NUM_OPERATIONS;
        apply_operation(cipher, plaintext, op_id, 1);
    }
}

/* ── Sequential encrypt/decrypt (replaces parallel MPI versions) ─────────── */
static uint8_t *seq_encrypt(WBC1OriginalCipher *cipher,
                             const uint8_t *plaintext, int plaintext_len,
                             int *out_len) {
    int block_size  = cipher->block_size_bytes;
    int num_blocks  = (plaintext_len + block_size - 1) / block_size;
    int padded_len  = num_blocks * block_size;
    int padding_len = padded_len - plaintext_len;

    uint8_t *padded = (uint8_t *)calloc((size_t)padded_len, 1);
    memcpy(padded, plaintext, (size_t)plaintext_len);
    /* PKCS7 padding */
    for (int i = 0; i < padding_len; i++)
        padded[plaintext_len + i] = (uint8_t)padding_len;

    uint8_t *result = (uint8_t *)malloc((size_t)padded_len);
    for (int i = 0; i < num_blocks; i++)
        wbc1_original_encrypt_block(cipher,
                                    padded  + i * block_size,
                                    result  + i * block_size);
    free(padded);
    *out_len = padded_len;
    return result;
}

static uint8_t *seq_decrypt(WBC1OriginalCipher *cipher,
                             const uint8_t *ciphertext, int ciphertext_len,
                             int *out_len) {
    int block_size = cipher->block_size_bytes;
    int num_blocks = ciphertext_len / block_size;

    uint8_t *decrypted = (uint8_t *)malloc((size_t)ciphertext_len);
    for (int i = 0; i < num_blocks; i++)
        wbc1_original_decrypt_block(cipher,
                                    ciphertext + i * block_size,
                                    decrypted  + i * block_size);

    /* Remove PKCS7 padding */
    int padding_len = decrypted[ciphertext_len - 1];
    int valid = (padding_len > 0 && padding_len <= block_size);
    if (valid) {
        for (int i = ciphertext_len - padding_len; i < ciphertext_len; i++)
            if (decrypted[i] != (uint8_t)padding_len) { valid = 0; break; }
    }
    *out_len = valid ? ciphertext_len - padding_len : ciphertext_len;
    uint8_t *result = (uint8_t *)malloc((size_t)(*out_len + 1));
    memcpy(result, decrypted, (size_t)*out_len);
    result[*out_len] = 0;
    free(decrypted);
    return result;
}

/* ── Statistical helpers ─────────────────────────────────────────────────── */
static uint8_t *generate_random_bytes(int size) {
    uint8_t *data = (uint8_t *)malloc((size_t)size);
    for (int i = 0; i < size; i++) data[i] = (uint8_t)(rand() % 256);
    return data;
}

static double shannon_entropy(const uint8_t *data, int len) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static void frequency_test(const uint8_t *data, int len,
                            double *mean, double *std, double *chi_square) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double sum = 0.0;
    for (int i = 0; i < 256; i++) sum += freq[i];
    *mean = sum / 256.0;
    double sum_sq = 0.0;
    for (int i = 0; i < 256; i++) { double d = freq[i] - *mean; sum_sq += d * d; }
    *std = sqrt(sum_sq / 256.0);
    double expected = len / 256.0;
    *chi_square = 0.0;
    for (int i = 0; i < 256; i++) {
        double d = freq[i] - expected;
        *chi_square += (d * d) / expected;
    }
}

/* ── per-block avalanche ──────────────────────────────────────────────────────── */
static void per_block_avalanche(WBC1OriginalCipher *cipher,
                                 const uint8_t *data, int data_len) {
    if (data_len <= 0) { printf("  Per-block avalanche: N/A (empty)\n"); return; }
    int bs = cipher->block_size_bytes;
    int num_blocks = (data_len + bs - 1) / bs;
    uint8_t *padded = (uint8_t *)calloc((size_t)(num_blocks * bs), 1);
    memcpy(padded, data, (size_t)data_len);

    printf("  Per-block avalanche (1-bit flip per block):\n");
    double total = 0.0;
    uint8_t ct0[MAX_BLOCK_SIZE], ct1[MAX_BLOCK_SIZE], blk1[MAX_BLOCK_SIZE];
    for (int b = 0; b < num_blocks; b++) {
        const uint8_t *blk = padded + b * bs;
        wbc1_original_encrypt_block(cipher, blk, ct0);
        memcpy(blk1, blk, bs);
        blk1[0] ^= 0x01;
        wbc1_original_encrypt_block(cipher, blk1, ct1);
        int diff = 0;
        for (int i = 0; i < bs; i++) diff += __builtin_popcount(ct0[i] ^ ct1[i]);
        double pct = (100.0 * diff) / (bs * 8);
        printf("  Block %3d/%d:  %5.1f%%\n", b + 1, num_blocks, pct);
        total += pct;
    }
    printf("  ──────────────────────────────\n");
    printf("  Average:        %5.1f%%  (ideal ~50%%)\n",
           num_blocks > 0 ? total / num_blocks : 0.0);
    free(padded);
}

static void avalanche_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total = 0.0, min_pct = 100.0, max_pct = 0.0;
    int block_size = cipher->block_size_bytes;
    for (int t = 0; t < num_tests; t++) {
        uint8_t *pt1 = generate_random_bytes(block_size);
        uint8_t *pt2 = (uint8_t *)malloc((size_t)block_size);
        memcpy(pt2, pt1, (size_t)block_size);
        pt2[rand() % block_size] ^= (uint8_t)(1 << (rand() % 8));
        uint8_t *ct1 = (uint8_t *)malloc((size_t)block_size);
        uint8_t *ct2 = (uint8_t *)malloc((size_t)block_size);
        wbc1_original_encrypt_block(cipher, pt1, ct1);
        wbc1_original_encrypt_block(cipher, pt2, ct2);
        int diff = 0;
        for (int i = 0; i < block_size; i++) {
            uint8_t x = ct1[i] ^ ct2[i];
            for (int b = 0; b < 8; b++) if (x & (1 << b)) diff++;
        }
        double pct = (100.0 * diff) / (block_size * 8);
        total += pct;
        if (pct < min_pct) min_pct = pct;
        if (pct > max_pct) max_pct = pct;
        free(pt1); free(pt2); free(ct1); free(ct2);
    }
    results[0] = total / num_tests;
    results[1] = min_pct;
    results[2] = max_pct;
}

static double correlation_test(const uint8_t *d1, const uint8_t *d2, int len) {
    double m1 = 0, m2 = 0;
    for (int i = 0; i < len; i++) { m1 += d1[i]; m2 += d2[i]; }
    m1 /= len; m2 /= len;
    double cov = 0, v1 = 0, v2 = 0;
    for (int i = 0; i < len; i++) {
        double a = d1[i] - m1, b = d2[i] - m2;
        cov += a * b; v1 += a * a; v2 += b * b;
    }
    if (v1 == 0.0 || v2 == 0.0) return 0.0;
    return cov / sqrt(v1 * v2);
}

static void differential_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total = 0.0, min_pct = 100.0, max_pct = 0.0;
    int block_size = cipher->block_size_bytes;
    uint8_t *pt = generate_random_bytes(block_size);
    for (int t = 0; t < num_tests; t++) {
        uint8_t *ct1 = (uint8_t *)malloc((size_t)block_size);
        wbc1_original_encrypt_block(cipher, pt, ct1);
        int fb = rand() % cipher->key_len_bytes;
        int fi = rand() % 8;
        cipher->key[fb] ^= (uint8_t)(1 << fi);
        uint8_t *ct2 = (uint8_t *)malloc((size_t)block_size);
        wbc1_original_encrypt_block(cipher, pt, ct2);
        cipher->key[fb] ^= (uint8_t)(1 << fi); /* restore */
        int diff = 0;
        for (int i = 0; i < block_size; i++) {
            uint8_t x = ct1[i] ^ ct2[i];
            for (int b = 0; b < 8; b++) if (x & (1 << b)) diff++;
        }
        double pct = (100.0 * diff) / (block_size * 8);
        total += pct; if (pct < min_pct) min_pct = pct; if (pct > max_pct) max_pct = pct;
        free(ct1); free(ct2);
    }
    results[0] = total / num_tests;
    results[1] = min_pct;
    results[2] = max_pct;
    free(pt);
}

/* ── Print helpers ───────────────────────────────────────────────────────── */
static void print_hex(const uint8_t *data, int len, int max_bytes) {
    for (int i = 0; i < len && i < max_bytes; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len > max_bytes) printf("...\n");
    else if (len % 32 != 0) printf("\n");
}

static void print_key_hex(const uint8_t *key, int key_len) {
    printf("\n");
    printf("====================================================================================================\n");
    printf("Generated key (hex) / Сгенерированный ключ (hex)\n");
    printf("====================================================================================================\n");
    for (int i = 0; i < key_len; i++) {
        printf("%02x", key[i]);
        if      ((i + 1) % 32 == 0) printf("\n");
        else if ((i + 1) % 8  == 0) printf(" ");
    }
    if (key_len % 32 != 0) printf("\n");
    printf("====================================================================================================\n\n");
}

static void print_key_operation_mapping(WBC1OriginalCipher *cipher, int show_count) {
    printf("\n");
    printf("====================================================================================================\n");
    printf("Key-to-Operation Mapping / Соответствие байтов ключа операциям\n");
    printf("Format: Key[N]: ASCII Hex → Operation ID: (type, params) description\n");
    printf("====================================================================================================\n");
    if (show_count > cipher->key_len_bytes) show_count = cipher->key_len_bytes;
    for (int i = 0; i < show_count; i++) {
        uint8_t key_byte = cipher->key[i];
        int op_id = key_byte % NUM_OPERATIONS;
        Operation *op = &cipher->operations[op_id];
        char ascii_char = (key_byte >= 32 && key_byte <= 126) ? (char)key_byte : '.';
        printf("Key[%3d]: %c 0x%02X → Op %3d: ", i, ascii_char, key_byte, op_id);
        if (strcmp(op->type, "dynamic") == 0)
            printf("(dynamic, '%s', chain=%d ops) %s\n", op->param1, op->chain_length, op->desc);
        else
            printf("(%s, '%s', '%s') %s\n", op->type, op->param1, op->param2, op->desc);
    }
    printf("====================================================================================================\n\n");
}

static void print_operations_table(WBC1OriginalCipher *cipher) {
    printf("\n");
    printf("==============================================================================\n");
    printf("          WBC1 ORIGINAL - ТАБЛИЦА ОПЕРАЦИЙ / OPERATIONS TABLE\n");
    printf("==============================================================================\n");
    printf("%-7s %-10s %-10s %s\n", "Номер","ASCII","Hex","Описание операции");
    printf("%-7s %-10s %-10s %s\n", "Number","Char","Code","Operation Description");
    printf("------------------------------------------------------------------------------\n");
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        Operation *op = &cipher->operations[i];
        char ascii_char[12];
        if (i >= 32 && i < 127) snprintf(ascii_char, sizeof(ascii_char), "'%c'", (char)i);
        else                    snprintf(ascii_char, sizeof(ascii_char), ".");
        char hex[12]; snprintf(hex, sizeof(hex), "0x%02X", i);
        printf("%-7d %-10s %-10s (%s", i, ascii_char, hex, op->type);
        if (strlen(op->param1) > 0) printf(", '%s'", op->param1);
        if (strlen(op->param2) > 0) printf(", '%s'", op->param2);
        if (op->chain_length > 0)   printf(", chain=%d ops", op->chain_length);
        printf(") %s\n", op->desc);
    }
    printf("==============================================================================\n");
    printf("Всего операций / Total operations: %d\n", NUM_OPERATIONS);
    printf("Базовых операций / Base operations: %d\n", cipher->base_ops_count);
    printf("  - Face rotations: 24  - Slice moves: 12  - Wide moves: 24\n");
    printf("  - Cube rotations: 12  - Swap: 12  - Diagflip: 3  - Dynamic: 20\n");
    printf("==============================================================================\n\n");

    printf("Key bit to operation mapping (first 10 bits):\n");
    printf("------------------------------------------------------------------------------\n");
    for (int i = 0; i < 10 && i < cipher->key_len_bits; i++) {
        int kbit  = get_key_bit(cipher->key, i, cipher->key_len_bytes);
        int op_id = kbit % NUM_OPERATIONS;
        char op_ascii[20];
        if (op_id >= 32 && op_id < 127)
            snprintf(op_ascii,sizeof(op_ascii),"'%c' (0x%02X)", (char)op_id, op_id);
        else
            snprintf(op_ascii,sizeof(op_ascii),"0x%02X", op_id);
        printf("  Key bit %3d: value=%d → operation %3d %s\n", i, kbit, op_id, op_ascii);
    }
    if (cipher->key_len_bits > 10)
        printf("  ... (showing first 10 of %d key bits)\n", cipher->key_len_bits);
    printf("==============================================================================\n");
}

/* ============================================================
 * main
 * ============================================================ */
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <task> <key_size> <key_source> <block_size_bits> [mode] [data_size_kb]\n", argv[0]);
        printf("  task:           0=encrypt/decrypt, 1=statistical tests, 2=print operations table\n");
        printf("  key_size:       128, 192, 256\n");
        printf("  key_source:     0=random, 1=sequential (0,1,2,...)\n");
        printf("  block_size_bits: 32, 64, 128, 512, or 0=auto\n");
        printf("  mode:           (task 0) 0=demo text, 1=random data\n");
        printf("  data_size_kb:   data size in KB\n");
        printf("\nExamples:\n");
        printf("  %s 0 256 0 128          # Encrypt demo text with 128-bit blocks\n", argv[0]);
        printf("  %s 0 256 0 128 1 10     # Encrypt 10 KB random data\n", argv[0]);
        printf("  %s 1 256 0 128 0 100    # Statistical tests, 100 KB\n", argv[0]);
        printf("  %s 2 256 0 128          # Print operations table\n", argv[0]);
        return 1;
    }

    int task            = atoi(argv[1]);
    int key_size        = atoi(argv[2]);
    int key_source      = atoi(argv[3]);
    int block_size_bits = atoi(argv[4]);
    int mode    = (argc >= 6) ? atoi(argv[5]) : 0;
    int data_kb = (argc >= 7) ? atoi(argv[6]) : 1;
    if (data_kb < 1) data_kb = 1;

    srand((unsigned int)time(NULL));

    /* Auto block size */
    if (block_size_bits == 0) {
        if      (data_kb < 10)   block_size_bits = 32;
        else if (data_kb < 100)  block_size_bits = 64;
        else if (data_kb < 1000) block_size_bits = 128;
        else                     block_size_bits = 512;
        printf("\nAuto block size: %d bits (data=%d KB)\n\n", block_size_bits, data_kb);
    }

    /* Generate / load key */
    int key_len = key_size / 8;
    uint8_t *key = (uint8_t *)malloc((size_t)key_len);
    if (key_source == 0) {
        for (int i = 0; i < key_len; i++) key[i] = (uint8_t)(rand() % 256);
    } else {
        for (int i = 0; i < key_len; i++) key[i] = (uint8_t)(i % 256);
    }

    /* Init cipher */
    WBC1OriginalCipher cipher;
    wbc1_original_init(&cipher, key, key_len, block_size_bits);

    /* ── task 0: encrypt / decrypt ───────────────────────────────────────── */
    if (task == 0) {
        uint8_t *plaintext = NULL;
        int text_len = 0;

        if (mode == 0) {
            const char *demo = "Це тестове повідомлення для демонстрації шифрування оригінальним алгоритмом WBC1.";
            text_len  = (int)strlen(demo);
            plaintext = (uint8_t *)malloc((size_t)text_len);
            memcpy(plaintext, demo, (size_t)text_len);
            printf("\n========================================\n");
            printf("WBC1 Original - Text Encryption Demo\n");
            printf("========================================\n");
            printf("Original text: %s\n", demo);
        } else {
            text_len  = data_kb * 1024;
            plaintext = generate_random_bytes(text_len);
            printf("\n========================================\n");
            printf("WBC1 Original - Random Data Encryption\n");
            printf("========================================\n");
            printf("Data size: %d KB (%d bytes)\n", data_kb, text_len);
            printf("First 64 bytes of plaintext:\n");
            print_hex(plaintext, text_len, 64);
        }

        printf("Block size: %d bits (%d bytes)\n", block_size_bits, block_size_bits / 8);
        printf("Key size: %d bits\n", key_size);
        printf("Cube dimension: %d×%d×%d\n", cipher.cube_d, cipher.cube_d, cipher.cube_d);
        printf("Key bytes processed per block: %d\n", cipher.key_len_bytes);

        int cipher_len = 0;
        double t0 = get_time();
        uint8_t *ciphertext = seq_encrypt(&cipher, plaintext, text_len, &cipher_len);
        double enc_time = get_time() - t0;

        printf("\nEncrypted (%d bytes):\n", cipher_len);
        print_hex(ciphertext, cipher_len, 64);

        int dec_len = 0;
        t0 = get_time();
        uint8_t *decrypted = seq_decrypt(&cipher, ciphertext, cipher_len, &dec_len);
        double dec_time = get_time() - t0;

        if (mode == 0) printf("\nDecrypted text: %.*s\n", dec_len, decrypted);
        else {
            printf("\nDecrypted (%d bytes), first 64 bytes:\n", dec_len);
            print_hex(decrypted, dec_len, 64);
        }

        printf("\nEncryption time: %.6f seconds\n", enc_time);
        printf("Decryption time: %.6f seconds\n", dec_time);
        if (text_len > 0)
            printf("Throughput: %.2f MB/s\n", (text_len / 1048576.0) / enc_time);

        if (dec_len == text_len && memcmp(plaintext, decrypted, (size_t)text_len) == 0)
            printf("✓ Success: Decrypted data matches original!\n");
        else
            printf("✗ Error: Decrypted data does NOT match original!\n");

        free(plaintext); free(ciphertext); free(decrypted);

    /* ── task 1: statistical tests ───────────────────────────────────────── */
    } else if (task == 1) {
        printf("\n========================================\n");
        printf("WBC1 Original - Statistical Analysis\n");
        printf("========================================\n");
        printf("Data size: %d KB | Block: %d bits | Key: %d bits\n",
               data_kb, block_size_bits, key_size);

        int data_size = data_kb * 1024;
        uint8_t *test_data = generate_random_bytes(data_size);

        int cipher_len = 0;
        printf("Encrypting...\n");
        double t0 = get_time();
        uint8_t *ciphertext = seq_encrypt(&cipher, test_data, data_size, &cipher_len);
        double enc_time = get_time() - t0;
        printf("Encryption: %.3f s | Throughput: %.2f MB/s\n\n",
               enc_time, (data_size / 1048576.0) / enc_time);

        printf("Statistical Tests Results:\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        double entropy = shannon_entropy(ciphertext, cipher_len);
        printf("1. Shannon Entropy: %.4f bits/byte (expected ~7.9-8.0)\n", entropy);
        printf("   %s\n\n", entropy >= 7.9 ? "✓ Good" : "⚠ Low entropy");

        double freq_mean, freq_std, freq_chi;
        frequency_test(ciphertext, cipher_len, &freq_mean, &freq_std, &freq_chi);
        printf("2. Frequency Test:\n");
        printf("   Mean: %.2f (exp ~127.5) | StdDev: %.2f | Chi²: %.2f\n",
               freq_mean, freq_std, freq_chi);
        printf("   %s\n\n", freq_chi < 293.0 ? "✓ Good distribution" : "⚠ May not be uniform");

        double av[3];
        avalanche_test(&cipher, 100, av);
        printf("3. Avalanche Effect: avg=%.2f%% min=%.2f%% max=%.2f%% (exp ~50%%)\n",
               av[0], av[1], av[2]);
        printf("   %s\n\n",
               (av[0] >= 45.0 && av[0] <= 55.0) ? "✓ Good avalanche" : "⚠ Weak avalanche");
        per_block_avalanche(&cipher, test_data, data_size);
        printf("\n");

        int tlen = data_size < cipher_len ? data_size : cipher_len;
        double corr = correlation_test(test_data, ciphertext, tlen);
        printf("4. Correlation: %.6f (exp close to 0)\n", corr);
        printf("   %s\n\n", fabs(corr) < 0.1 ? "✓ Low correlation" : "⚠ High correlation");

        double df[3];
        differential_test(&cipher, 50, df);
        printf("5. Differential Test (key sensitivity): avg=%.2f%% min=%.2f%% max=%.2f%%\n",
               df[0], df[1], df[2]);
        printf("   %s\n",
               (df[0] >= 45.0 && df[0] <= 55.0) ? "✓ Good key sensitivity" : "⚠ Weak key sensitivity");

        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        free(test_data); free(ciphertext);

    /* ── task 2: print operations table ─────────────────────────────────── */
    } else if (task == 2) {
        print_key_hex(key, key_len);
        print_key_operation_mapping(&cipher, 32);
        print_operations_table(&cipher);
    }

    wbc1_original_free(&cipher);
    free(key);
    return 0;
}
