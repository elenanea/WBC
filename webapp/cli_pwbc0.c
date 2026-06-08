/*
 * CLI MPI wrapper for wbc0_original_parallel.c  (PWBC1 backend)
 * Protocol:
 *   line 1: hex key (64 chars = 256 bits)
 *   line 2: 'e' encrypt | 'd' decrypt
 *   remaining stdin: raw binary data
 * stdout: raw binary result
 *
 * Run: mpirun -n 4 ./cli_pwbc0 < input > output
 *      (or -n 1 for single process)
 *
 * Uses parallel_original_encrypt / parallel_original_decrypt which
 * distribute blocks across MPI processes and gather on rank 0.
 * Result is written to stdout only from rank 0.
 */

/* Suppress the existing main() */
#define main wbc0_orig_main_unused
#include "../wbc0_original_parallel.c"
#undef main

/* ── framing helpers (PKCS-like + magic header for detection) ────────────── */
#define CLI_MAGIC "PWBC\x00"
#define CLI_MAGIC_LEN 5

static uint8_t *cli_pad(const uint8_t *data, size_t len,
                        int block_sz, size_t *out_len) {
    int pad = block_sz - (int)(len % block_sz);
    *out_len = len + pad;
    uint8_t *buf = (uint8_t *)malloc(*out_len);
    memcpy(buf, data, len);
    memset(buf + len, (uint8_t)pad, pad);
    return buf;
}

static uint8_t *cli_unpad(const uint8_t *data, size_t len,
                           int block_sz, size_t *out_len) {
    if (len == 0 || (int)len < block_sz) { *out_len = 0; return NULL; }
    int pad = data[len - 1];
    if (pad < 1 || pad > block_sz || (int)len < pad) {
        /* no valid padding — return as-is */
        *out_len = len;
        uint8_t *r = (uint8_t *)malloc(len);
        memcpy(r, data, len);
        return r;
    }
    *out_len = len - pad;
    uint8_t *r = (uint8_t *)malloc(*out_len + 1);
    memcpy(r, data, *out_len);
    r[*out_len] = 0;
    return r;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    /* ── rank 0: read protocol header ──────────────────────────────────── */
    char hex_key[128] = {0};
    char mode_line[16] = {0};
    char shift_line[16] = {0};
    uint8_t *data = NULL;
    size_t data_len = 0;
    int do_encrypt = 1;
    int block_size_bits = 128;  /* 128-bit = 16-byte blocks */
    int key_len_bytes = 32;
    int shift_mode = 0;  /* 0=baseline, 1=uniform, 2=alpha+beta */

    if (rank == 0) {
        if (fgets(hex_key, sizeof(hex_key), stdin) == NULL) {
            fprintf(stderr, "ERROR: cannot read key\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        hex_key[strcspn(hex_key, "\r\n")] = 0;
        if (strlen(hex_key) != 64) {
            fprintf(stderr, "ERROR: key must be 64 hex chars\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        if (fgets(mode_line, sizeof(mode_line), stdin) == NULL) {
            fprintf(stderr, "ERROR: cannot read mode\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        mode_line[strcspn(mode_line, "\r\n")] = 0;
        do_encrypt = (mode_line[0] == 'e' || mode_line[0] == 'E');

        /* line 3: shift_mode (0=baseline,1=uniform,2=alpha+beta), default 0 */
        if (fgets(shift_line, sizeof(shift_line), stdin) != NULL) {
            shift_line[strcspn(shift_line, "\r\n")] = 0;
            int v = atoi(shift_line);
            if (v >= 0 && v <= 2) shift_mode = v;
        }

        /* read binary data */
        size_t cap = 1 << 20;
        data = (uint8_t *)malloc(cap);
        int c;
        while ((c = fgetc(stdin)) != EOF) {
            if (data_len >= cap) { cap *= 2; data = (uint8_t *)realloc(data, cap); }
            data[data_len++] = (uint8_t)c;
        }
        if (data_len == 0) {
            fprintf(stderr, "ERROR: no data\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }

    /* ── broadcast key and mode to all ranks ────────────────────────────── */
    MPI_Bcast(hex_key, 128, MPI_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&do_encrypt, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&block_size_bits, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&shift_mode, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b; sscanf(hex_key + i * 2, "%02x", &b);
        key[i] = (uint8_t)b;
    }

    /* ── init cipher on all ranks ────────────────────────────────────────── */
    WBC1OriginalCipher cipher;
    wbc1_original_init(&cipher, key, key_len_bytes, block_size_bits);
    cipher.shift_mode = shift_mode;

    int block_sz = cipher.block_size_bytes;

    uint8_t *result = NULL;
    size_t result_len = 0;

    if (do_encrypt) {
        /* parallel_original_encrypt applies PKCS7 padding internally */
        int ilen = (rank == 0) ? (int)data_len : 0;
        MPI_Bcast(&ilen, 1, MPI_INT, 0, MPI_COMM_WORLD);
        int enc_len = 0;
        uint8_t *enc = NULL;
        parallel_original_encrypt(&cipher,
                                   rank == 0 ? data : NULL,
                                   ilen,
                                   &enc, &enc_len);
        if (rank == 0) {
            result = enc;
            result_len = (size_t)enc_len;
        }
    } else {
        /* parallel_original_decrypt removes PKCS7 padding internally */
        int ilen = (rank == 0) ? (int)data_len : 0;
        MPI_Bcast(&ilen, 1, MPI_INT, 0, MPI_COMM_WORLD);
        int dec_len = 0;
        uint8_t *dec = NULL;
        parallel_original_decrypt(&cipher,
                                   rank == 0 ? data : NULL,
                                   ilen,
                                   &dec, &dec_len);
        if (rank == 0) {
            result = dec;
            result_len = (size_t)dec_len;
        }
    }

    wbc1_original_free(&cipher);
    if (rank == 0) { free(data); }

    /* ── rank 0 writes output ─────────────────────────────────────────── */
    if (rank == 0 && result) {
        fwrite(result, 1, result_len, stdout);
        fflush(stdout);
        free(result);
    }

    MPI_Finalize();
    return 0;
}
