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

/* Get bit value from key at given bit index */
static int get_key_bit(const uint8_t *key, int bit_index, int key_len_bytes) {
    int byte_idx = bit_index / 8;
    int bit_pos = 7 - (bit_index % 8);  /* MSB first */
    if (byte_idx >= key_len_bytes) {
        byte_idx = byte_idx % key_len_bytes;  /* Wrap around */
    }
    return (key[byte_idx] >> bit_pos) & 1;
}

/* Cyclic bitwise shift for entire block */
static void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits) {
    if (shift_bits == 0 || size_bytes == 0) return;
    
    int total_bits = size_bytes * 8;
    shift_bits = shift_bits % total_bits;  /* Normalize shift */
    if (shift_bits < 0) shift_bits += total_bits;
    
    /* Create temporary buffer */
    uint8_t *temp = (uint8_t *)malloc(size_bytes);
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
    
    free(temp);
}

/* Initialize 127 permutation operations (same as other versions) */
static void init_operations(WBC1OriginalCipher *cipher) {
    /* Allocate operations array */
    cipher->operations = (Operation *)calloc(NUM_OPERATIONS, sizeof(Operation));
    cipher->base_operations = (Operation *)calloc(127, sizeof(Operation));
    cipher->base_ops_count = 107;  /* 87 base + 20 dynamic */
    
    /* Initialize with simple permutations for this implementation */
    /* In full implementation, this would match the 127 operations from other versions */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        snprintf(cipher->operations[i].type, sizeof(cipher->operations[i].type), "perm");
        snprintf(cipher->operations[i].desc, sizeof(cipher->operations[i].desc), "Operation %d", i);
        cipher->operations[i].chain_length = 0;
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
void wbc1_original_init(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len, int block_size_bits) {
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
    
    /* Initialize operations table */
    init_operations(cipher);
}

/* Free cipher resources */
void wbc1_original_free(WBC1OriginalCipher *cipher) {
    if (cipher->key) free(cipher->key);
    if (cipher->operations) free(cipher->operations);
    if (cipher->base_operations) free(cipher->base_operations);
    memset(cipher, 0, sizeof(WBC1OriginalCipher));
}

/* Encrypt single block using original algorithm */
void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher, const uint8_t *plaintext, uint8_t *ciphertext) {
    /* Copy plaintext to ciphertext (working buffer) */
    memcpy(ciphertext, plaintext, cipher->block_size_bytes);
    
    /* Process each bit of the key */
    for (int bit_idx = 0; bit_idx < cipher->key_len_bits; bit_idx++) {
        /* Step 1: Get key bit and select operation */
        int key_bit = get_key_bit(cipher->key, bit_idx, cipher->key_len_bytes);
        int op_id = key_bit % NUM_OPERATIONS;  /* In real implementation: use key_bit to index table */
        
        /* Step 2: Apply selected operation */
        apply_operation(cipher, ciphertext, op_id, 0);
        
        /* Step 3: Cyclic bitwise shift by d bits */
        cyclic_bitwise_shift(ciphertext, cipher->block_size_bytes, cipher->cube_d);
    }
}

/* Decrypt single block (reverse process) */
void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher, const uint8_t *ciphertext, uint8_t *plaintext) {
    /* Copy ciphertext to plaintext (working buffer) */
    memcpy(plaintext, ciphertext, cipher->block_size_bytes);
    
    /* Process key bits in reverse order */
    for (int bit_idx = cipher->key_len_bits - 1; bit_idx >= 0; bit_idx--) {
        /* Step 1: Reverse cyclic shift */
        cyclic_bitwise_shift(plaintext, cipher->block_size_bytes, -cipher->cube_d);
        
        /* Step 2: Get key bit and select operation */
        int key_bit = get_key_bit(cipher->key, bit_idx, cipher->key_len_bytes);
        int op_id = key_bit % NUM_OPERATIONS;
        
        /* Step 3: Apply inverse operation */
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

/* Print hex data */
static void print_hex(const uint8_t *data, int len, int max_bytes) {
    for (int i = 0; i < len && i < max_bytes; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len > max_bytes) printf("...\n");
    else if (len % 32 != 0) printf("\n");
}

/* Print operations table */
static void print_operations_table(WBC1OriginalCipher *cipher) {
    printf("\n========================================\n");
    printf("WBC1 Original - Operations Table / Таблица операций\n");
    printf("========================================\n");
    printf("Total operations / Всего операций: %d\n\n", NUM_OPERATIONS);
    
    for (int i = 0; i < NUM_OPERATIONS && i < 20; i++) {
        printf("Operation %d: %s\n", i, cipher->operations[i].desc);
    }
    printf("...\n");
    printf("(Showing first 20 of %d operations)\n", NUM_OPERATIONS);
}

/* Main function */
int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    if (argc < 5) {
        if (rank == 0) {
            printf("Usage: %s <task> <key_size> <key_source> <block_size_bits> [mode] [data_size_kb]\n", argv[0]);
            printf("  task: 0=encrypt/decrypt, 1=statistical tests\n");
            printf("  key_size: key size in bits (128, 192, 256)\n");
            printf("  key_source: 0=random, 1=from file\n");
            printf("  block_size_bits: block size in bits (32, 64, 128, 512)\n");
            printf("  mode: (for task 0) 0=use demo text, 1=generate random data\n");
            printf("         (for task 1) 0=simple, 1=full\n");
            printf("  data_size_kb: amount of data in KB (for task 0 with mode=1, or task 1)\n");
            printf("\nExamples:\n");
            printf("  %s 0 256 0 128          # Encrypt demo text\n", argv[0]);
            printf("  %s 0 256 0 128 1 10     # Encrypt 10KB random data\n", argv[0]);
            printf("  %s 1 256 0 128 1 100    # Statistical tests with 100KB data\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }
    
    int task = atoi(argv[1]);
    int key_size = atoi(argv[2]);
    int key_source = atoi(argv[3]);
    int block_size_bits = atoi(argv[4]);
    
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
    wbc1_original_init(&cipher, key, key_len, block_size_bits);
    
    if (task == 0) {
        /* Text encryption/decryption */
        int mode = 0;  /* 0 = demo text, 1 = random data */
        int data_kb = 1;
        if (argc >= 6) {
            mode = atoi(argv[5]);
        }
        if (argc >= 7 && mode == 1) {
            data_kb = atoi(argv[6]);
            if (data_kb < 1) data_kb = 1;
            if (data_kb > 10000) data_kb = 10000;  /* Max 10MB - original algorithm is slow for large data */
        }
        
        /* Performance warning for large data (task 0, mode 1 - random data) */
        if (rank == 0 && mode == 1 && data_kb > 1000) {
            int block_size_bytes = block_size_bits / 8;
            long long estimated_blocks = ((long long)data_kb * 1024) / block_size_bytes;
            long long estimated_ops = estimated_blocks * key_size;
            printf("\n⚠ Performance Warning / Предупреждение о производительности:\n");
            printf("  Data size: %d KB (~%lld blocks)\n", data_kb, estimated_blocks);
            printf("  Estimated operations: %.2f billion (block × key_bits)\n", estimated_ops / 1e9);
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
                printf("Throughput: %.2f MB/s\n", throughput_mb);
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
        /* Statistical analysis with configurable data size */
        int data_kb = 10;  /* Default 10KB */
        if (argc >= 7) {
            data_kb = atoi(argv[6]);
            if (data_kb < 1) data_kb = 1;
            if (data_kb > 1000) data_kb = 1000;  /* Max 1MB - original algorithm is slow for large data */
        }
        
        /* Performance warning for statistical analysis with large data */
        if (rank == 0 && data_kb > 100) {
            int block_size_bytes = block_size_bits / 8;
            long long estimated_blocks = ((long long)data_kb * 1024) / block_size_bytes;
            long long estimated_ops = estimated_blocks * key_size;
            printf("\n⚠ Performance Warning / Предупреждение о производительности:\n");
            printf("  Data size: %d KB (~%lld blocks)\n", data_kb, estimated_blocks);
            printf("  Estimated operations: %.2f billion (blocks × key_bits)\n", estimated_ops / 1e9);
            printf("  Processing may take a while...\n");
            printf("  Обработка может занять некоторое время...\n\n");
        }
        
        if (rank == 0) {
            printf("\n========================================\n");
            printf("WBC1 Original - Statistical Analysis / Статистический анализ\n");
            printf("========================================\n");
            printf("Data size / Размер данных: %d KB\n", data_kb);
            printf("Block size / Размер блока: %d bits\n", block_size_bits);
            printf("Key size / Размер ключа: %d bits\n", key_size);
            printf("\n");
            
            int data_size = data_kb * 1024;
            uint8_t *test_data = generate_random_bytes(data_size);
            uint8_t *ciphertext = NULL;
            int cipher_len = 0;
            
            printf("Encrypting / Шифрование...\n");
            double start_time = MPI_Wtime();
            parallel_original_encrypt(&cipher, test_data, data_size, &ciphertext, &cipher_len);
            double encrypt_time = MPI_Wtime() - start_time;
            
            printf("Encryption completed in %.3f seconds\n", encrypt_time);
            printf("Throughput: %.2f MB/s\n\n", (data_size / 1024.0 / 1024.0) / encrypt_time);
            
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
            printf("   Mean / Среднее: %.2f (expected ~127.5)\n", freq_mean);
            printf("   Std Dev / Ст. откл.: %.2f (expected ~73.9)\n", freq_std);
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
            
            free(test_data);
            free(ciphertext);
        } else {
            /* Other processes participate in encryption */
            uint8_t *dummy_cipher = NULL;
            int dummy_len = 0;
            parallel_original_encrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
        }
    } else if (task == 2) {
        /* Print operations table */
        if (rank == 0) {
            print_operations_table(&cipher);
        }
    }
    
    wbc1_original_free(&cipher);
    free(key);
    
    MPI_Finalize();
    return 0;
}
