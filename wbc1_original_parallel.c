/*
 * WBC1 Original Algorithm - Parallel Implementation with MPI
 * 
 * Based on the original algorithm description:
 * - Data divided into blocks of size s ∈ {32, 64, 128, 512} bits
 * - Blocks arranged in 3D cube d×d×d
 * - 127 permutation operations in table P
 * - Bit-by-bit key processing (each key bit selects an operation)
 * - Cyclic bitwise shift after each key bit
 * - MPI parallelization for block processing
 * 
 * Key differences from enhanced versions:
 * - Simple single-pass structure (no rounds)
 * - Bit-by-bit key processing vs byte-by-byte
 * - One operation per key bit vs 32 operations per round
 * - Variable block sizes vs fixed 128-bit blocks
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
#define MAX_KEY_BITS 2048  /* Maximum key size in bits */

/* Supported block sizes in bits */
typedef enum {
    BLOCK_32 = 32,    /* 2×2×2 cube */
    BLOCK_64 = 64,    /* 2×2×4 cube or 2×4×2 cube */
    BLOCK_128 = 128,  /* 2×2×8 cube or 2×4×4 cube */
    BLOCK_512 = 512   /* 4×4×8 cube or 2×8×8 cube */
} BlockSizeBits;

/* Operation metadata structure */
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
    int cube_d;  /* Cube dimension d×d×d */
    Operation *operations;
    Operation *base_operations;
    int base_ops_count;
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
} WBC1OriginalCipher;

/* Helper function prototypes */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output);
static void generate_sbox(WBC1OriginalCipher *cipher);
static void generate_inverse_sbox(WBC1OriginalCipher *cipher);
static void init_operations(WBC1OriginalCipher *cipher);
static void apply_operation(WBC1OriginalCipher *cipher, uint8_t *block, int op_id, int inverse);
static void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits);
static int get_key_bit(const uint8_t *key, int bit_index);

/* Cipher operations */
void wbc1_original_init(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len, int block_size_bits);
void wbc1_original_free(WBC1OriginalCipher *cipher);
void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext);
void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext);

/* Parallel operations */
void parallel_original_encrypt(WBC1OriginalCipher *cipher, const uint8_t *plaintext, int plaintext_len,
                               uint8_t **ciphertext, int *ciphertext_len);
void parallel_original_decrypt(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, int ciphertext_len,
                               uint8_t **plaintext, int *plaintext_len);

/* Statistical tests */
void run_statistical_tests_original(WBC1OriginalCipher *cipher, int num_blocks);

