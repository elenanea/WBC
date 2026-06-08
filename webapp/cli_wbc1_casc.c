/*
 * CLI wrapper for wbc1_fixed_cascade.c (WBC1.0 - cascade with mix)
 * Usage: cli_wbc1_casc [enc_mode]
 *   enc_mode (argv[1]): CTR_HMAC (default) | ECB | CBC | CTR | OFB | CFB
 * Protocol (stdin):
 *   Line 1: hex key (64 hex chars = 256 bits)
 *   Line 2: 'e' for encrypt, 'd' for decrypt
 *   stdin remainder: raw binary data
 * stdout: raw binary result
 *
 * Output format:
 *   CTR_HMAC : nonce(12) | "WBC1"(4) | ver(1) | bsz_BE(2) | ct | MAC(32)
 *   CBC/CTR/OFB/CFB : IV(16) | bsz_BE(2) | ciphertext
 *   ECB : bsz_BE(2) | ciphertext
 */

#define main cascade_main_unused
#include "../wbc1_fixed_cascade.c"
#undef main

#include "cli_wbc_serial_common.h"

static void __attribute__((unused)) suppress_unused(void) {
    (void)cascade_main_unused;
}

int main(int argc, char *argv[]) {
    EncMode enc_mode = parse_enc_mode(argc >= 2 ? argv[1] : "");

    char hex_key[128] = {0};
    if (fgets(hex_key, sizeof(hex_key), stdin) == NULL) {
        fprintf(stderr, "ERROR: cannot read key\n"); return 1;
    }
    hex_key[strcspn(hex_key, "\r\n")] = 0;
    if (strlen(hex_key) != 64) {
        fprintf(stderr, "ERROR: key must be 64 hex chars\n"); return 1;
    }
    uint8_t key[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) {
        unsigned int b; sscanf(hex_key + i * 2, "%02x", &b); key[i] = (uint8_t)b;
    }

    char mode_line[16] = {0};
    if (fgets(mode_line, sizeof(mode_line), stdin) == NULL) {
        fprintf(stderr, "ERROR: cannot read op\n"); return 1;
    }
    mode_line[strcspn(mode_line, "\r\n")] = 0;
    int do_encrypt = (mode_line[0] == 'e' || mode_line[0] == 'E');

    size_t cap = 1 << 20;
    uint8_t *data = (uint8_t *)malloc(cap);
    size_t data_len = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (data_len >= cap) { cap *= 2; data = (uint8_t *)realloc(data, cap); }
        data[data_len++] = (uint8_t)c;
    }
    if (data_len == 0) { fprintf(stderr, "ERROR: no data\n"); free(data); return 1; }

    size_t out_len = 0;
    uint8_t *result = NULL;
    if (do_encrypt)
        result = serial_encrypt_with_mode(key, data, data_len, enc_mode, &out_len);
    else
        result = serial_decrypt_with_mode(key, data, data_len, enc_mode, &out_len);

    free(data);
    if (!result) { fprintf(stderr, "ERROR: cipher operation failed\n"); return 1; }
    fwrite(result, 1, out_len, stdout);
    fflush(stdout);
    free(result);
    return 0;
}
