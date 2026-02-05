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
        *plaintext_len = ciphertext_len - padding_len;
        *plaintext = (uint8_t *)malloc(*plaintext_len);
        memcpy(*plaintext, gathered_plaintext, *plaintext_len);
        free(gathered_plaintext);
        free(sendcounts);
        free(displs);
    }
    
    free(my_ciphertext);
    free(my_plaintext);
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
            printf("  mode: (for task 1) 0=simple, 1=full\n");
            printf("  data_size_kb: (for task 1) amount of data in KB\n");
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
        if (rank == 0) {
            const char *demo_text = "Це тестове повідомлення для демонстрації шифрування оригінальним алгоритмом WBC1.";
            int text_len = strlen(demo_text);
            
            printf("\n========================================\n");
            printf("WBC1 Original Algorithm - Text Encryption Demo\n");
            printf("========================================\n");
            printf("Block size: %d bits (%d bytes)\n", block_size_bits, block_size_bits / 8);
            printf("Key size: %d bits\n", key_size);
            printf("Cube dimension: %d×%d×%d\n", cipher.cube_d, cipher.cube_d, cipher.cube_d);
            printf("Key bits processed: %d\n", cipher.key_len_bits);
            printf("\nOriginal text: %s\n", demo_text);
            
            uint8_t *ciphertext = NULL;
            int ciphertext_len = 0;
            
            double start_time = MPI_Wtime();
            parallel_original_encrypt(&cipher, (const uint8_t *)demo_text, text_len, &ciphertext, &ciphertext_len);
            double encrypt_time = MPI_Wtime() - start_time;
            
            printf("\nEncrypted (%d bytes):\n", ciphertext_len);
            for (int i = 0; i < ciphertext_len && i < 64; i++) {
                printf("%02x", ciphertext[i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            if (ciphertext_len > 64) printf("...\n");
            
            uint8_t *decrypted = NULL;
            int decrypted_len = 0;
            
            start_time = MPI_Wtime();
            parallel_original_decrypt(&cipher, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
            double decrypt_time = MPI_Wtime() - start_time;
            
            printf("\nDecrypted text: %.*s\n", decrypted_len, decrypted);
            printf("\nEncryption time: %.6f seconds\n", encrypt_time);
            printf("Decryption time: %.6f seconds\n", decrypt_time);
            
            /* Verify */
            if (decrypted_len == text_len && memcmp(demo_text, decrypted, text_len) == 0) {
                printf("✓ Success: Decrypted text matches original!\n");
            } else {
                printf("✗ Error: Decrypted text does not match original!\n");
            }
            
            free(ciphertext);
            free(decrypted);
        } else {
            uint8_t *dummy_cipher = NULL;
            int dummy_len = 0;
            parallel_original_encrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
            parallel_original_decrypt(&cipher, NULL, 0, &dummy_cipher, &dummy_len);
        }
    } else if (task == 1) {
        /* Statistical tests */
        if (rank == 0) {
            printf("\n========================================\n");
            printf("WBC1 Original - Statistical Tests\n");
            printf("========================================\n");
            printf("Not implemented in this simplified version\n");
        }
    }
    
    wbc1_original_free(&cipher);
    free(key);
    
    MPI_Finalize();
    return 0;
}
