/*
 * CLI MPI wrapper for wbc1_original_parallel.c  (PWBC1.1 backend)
 * Same protocol as cli_pwbc0.c
 * Run:  mpirun -n 4 ./cli_pwbc1 < input > output
 */

#define main wbc1_orig_main_unused
#include "../wbc1_original_parallel.c"
#undef main

static uint8_t *cli_unpad_pkcs7(const uint8_t *data, size_t len,
                                 int block_sz, size_t *out_len) {
    if (len == 0 || (int)len < block_sz) { *out_len = 0; return NULL; }
    int pad = data[len - 1];
    int valid = (pad >= 1 && pad <= block_sz);
    if (valid) {
        for (int i = (int)len - pad; i < (int)len; i++)
            if (data[i] != (uint8_t)pad) { valid = 0; break; }
    }
    *out_len = valid ? len - pad : len;
    uint8_t *r = (uint8_t *)malloc(*out_len + 1);
    memcpy(r, data, *out_len);
    r[*out_len] = 0;
    return r;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    char hex_key[128] = {0};
    char mode_line[16] = {0};
    uint8_t *data = NULL;
    size_t data_len = 0;
    int do_encrypt = 1;
    int block_size_bits = 128;

    if (rank == 0) {
        if (!fgets(hex_key, sizeof(hex_key), stdin)) { MPI_Abort(MPI_COMM_WORLD, 1); }
        hex_key[strcspn(hex_key, "\r\n")] = 0;
        if (strlen(hex_key) != 64) {
            fprintf(stderr, "ERROR: key must be 64 hex chars\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        if (!fgets(mode_line, sizeof(mode_line), stdin)) { MPI_Abort(MPI_COMM_WORLD, 1); }
        mode_line[strcspn(mode_line, "\r\n")] = 0;
        do_encrypt = (mode_line[0] == 'e' || mode_line[0] == 'E');

        size_t cap = 1 << 20;
        data = (uint8_t *)malloc(cap);
        int c;
        while ((c = fgetc(stdin)) != EOF) {
            if (data_len >= cap) { cap *= 2; data = (uint8_t *)realloc(data, cap); }
            data[data_len++] = (uint8_t)c;
        }
        if (data_len == 0) { fprintf(stderr, "ERROR: no data\n"); MPI_Abort(MPI_COMM_WORLD, 1); }
    }

    MPI_Bcast(hex_key, 128, MPI_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&do_encrypt, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&block_size_bits, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b; sscanf(hex_key + i * 2, "%02x", &b); key[i] = (uint8_t)b;
    }

    WBC1OriginalCipher cipher;
    wbc1_original_init(&cipher, key, 32, block_size_bits);
    int block_sz = cipher.block_size_bytes;

    uint8_t *result = NULL;
    size_t result_len = 0;

    if (do_encrypt) {
        int ilen = (rank == 0) ? (int)data_len : 0;
        MPI_Bcast(&ilen, 1, MPI_INT, 0, MPI_COMM_WORLD);
        int enc_len = 0;
        uint8_t *enc = NULL;
        parallel_original_encrypt(&cipher, rank == 0 ? data : NULL,
                                   ilen, &enc, &enc_len);
        if (rank == 0) { result = enc; result_len = (size_t)enc_len; }
    } else {
        int ilen = (rank == 0) ? (int)data_len : 0;
        MPI_Bcast(&ilen, 1, MPI_INT, 0, MPI_COMM_WORLD);
        int dec_len = 0;
        uint8_t *dec = NULL;
        parallel_original_decrypt(&cipher, rank == 0 ? data : NULL,
                                   ilen, &dec, &dec_len);
        if (rank == 0) {
            /* parallel_original_decrypt already removed PKCS7 padding */
            result = dec;
            result_len = (size_t)dec_len;
        }
    }

    wbc1_original_free(&cipher);
    if (rank == 0) { free(data); }

    if (rank == 0 && result) {
        fwrite(result, 1, result_len, stdout);
        fflush(stdout);
        free(result);
    }
    MPI_Finalize();
    return 0;
}
