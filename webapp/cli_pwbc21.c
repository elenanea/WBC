/*
 * CLI MPI wrapper for wbc1_parallel_cached.c (PWBC2.1)
 * Protocol (stdin):
 *   Line 1: hex key (64 hex chars = 256 bits)
 *   Line 2: 'e' for encrypt, 'd' for decrypt
 *   Line 3: algorithm_mode = FULL (default) | SIMPLIFIED
 *   stdin remainder: raw binary data
 * stdout: raw binary result
 *
 * Run: mpirun -n 4 ./cli_pwbc21 < input > output
 */

#define main pwbc21_main_unused
#include "../wbc1_parallel_cached.c"
#undef main

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    char hex_key[128]     = {0};
    char mode_line[16]    = {0};
    char algo_mode_line[32] = {0};
    uint8_t *data = NULL;
    size_t data_len = 0;
    int do_encrypt   = 1;
    int algorithm_mode = MODE_FULL;   /* default: 5-operation mode */

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

        if (fgets(algo_mode_line, sizeof(algo_mode_line), stdin)) {
            algo_mode_line[strcspn(algo_mode_line, "\r\n")] = 0;
            if (strncasecmp(algo_mode_line, "SIMPLIFIED", 10) == 0 ||
                strncasecmp(algo_mode_line, "0", 1) == 0)
                algorithm_mode = MODE_SIMPLIFIED;
            /* else MODE_FULL */
        }

        size_t cap = 1 << 20;
        data = (uint8_t *)malloc(cap);
        int c;
        while ((c = fgetc(stdin)) != EOF) {
            if (data_len >= cap) { cap *= 2; data = (uint8_t *)realloc(data, cap); }
            data[data_len++] = (uint8_t)c;
        }
        if (data_len == 0) { fprintf(stderr, "ERROR: no data\n"); MPI_Abort(MPI_COMM_WORLD, 1); }
    }

    /* Broadcast parameters */
    MPI_Bcast(hex_key, 128, MPI_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&do_encrypt,    1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&algorithm_mode, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b; sscanf(hex_key + i * 2, "%02x", &b); key[i] = (uint8_t)b;
    }

    /* default: 16 rounds for FULL, 8 for SIMPLIFIED */
    int num_rounds = (algorithm_mode == MODE_FULL) ? 16 : 8;

    WBC1Cipher cipher;
    wbc1_init(&cipher, key, 32, num_rounds, algorithm_mode);

    int ilen = (rank == 0) ? (int)data_len : 0;
    MPI_Bcast(&ilen, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t *result = NULL;
    int result_len  = 0;

    if (do_encrypt) {
        parallel_encrypt(&cipher, rank == 0 ? data : NULL, ilen, &result, &result_len);
    } else {
        parallel_decrypt(&cipher, rank == 0 ? data : NULL, ilen, &result, &result_len);
    }

    wbc1_free(&cipher);
    if (rank == 0) {
        free(data);
        if (result && result_len > 0) {
            fwrite(result, 1, (size_t)result_len, stdout);
            fflush(stdout);
        } else {
            fprintf(stderr, "ERROR: operation produced no output\n");
        }
        free(result);
    }

    MPI_Finalize();
    return 0;
}
