/*
 * CLI wrapper for wbc1_fixed.c
 * Protocol (stdin):
 *   line 1: hex key (64 hex chars = 32 bytes)
 *   line 2: 'e' for encrypt, 'd' for decrypt
 *   remaining bytes: raw binary data
 * Protocol (stdout):
 *   raw binary result
 * Exit code: 0=ok, 1=error (error message on stderr)
 */

#define main wbc1_fixed_main_unused
#include "../wbc1_fixed.c"
#undef main

/* suppress unused warning for interactive main */
static void __attribute__((unused)) suppress_unused(void) {
    (void)wbc1_fixed_main_unused;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* Read hex key (64 hex chars) */
    char hex_key[128] = {0};
    if (fgets(hex_key, sizeof(hex_key), stdin) == NULL) {
        fprintf(stderr, "ERROR: cannot read key\n");
        return 1;
    }
    /* strip newline */
    hex_key[strcspn(hex_key, "\r\n")] = 0;
    if (strlen(hex_key) != 64) {
        fprintf(stderr, "ERROR: key must be 64 hex chars (256 bits), got %zu\n", strlen(hex_key));
        return 1;
    }
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(hex_key + i * 2, "%02x", &byte);
        key[i] = (uint8_t)byte;
    }

    /* Read mode: 'e' or 'd' */
    char mode_line[16] = {0};
    if (fgets(mode_line, sizeof(mode_line), stdin) == NULL) {
        fprintf(stderr, "ERROR: cannot read mode\n");
        return 1;
    }
    mode_line[strcspn(mode_line, "\r\n")] = 0;
    int do_encrypt = (mode_line[0] == 'e' || mode_line[0] == 'E');

    /* Read remaining binary data */
    size_t cap = 1 << 20; /* 1 MB initial */
    uint8_t *data = (uint8_t *)malloc(cap);
    size_t data_len = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (data_len >= cap) {
            cap *= 2;
            data = (uint8_t *)realloc(data, cap);
            if (!data) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }
        }
        data[data_len++] = (uint8_t)c;
    }

    if (data_len == 0) {
        fprintf(stderr, "ERROR: no data provided\n");
        free(data);
        return 1;
    }

    /* Build operation table */
    build_op_table(key);

    size_t out_len = 0;
    uint8_t *result = NULL;

    if (do_encrypt) {
        result = wbc1_encrypt_ctr_hmac(key, data, data_len, auto_block_size((int)data_len), &out_len);
    } else {
        result = wbc1_decrypt_ctr_hmac(key, data, data_len, &out_len);
    }

    free(data);

    if (!result) {
        fprintf(stderr, "ERROR: cipher operation failed\n");
        return 1;
    }

    /* Write binary result to stdout */
    fwrite(result, 1, out_len, stdout);
    fflush(stdout);
    free(result);
    return 0;
}
