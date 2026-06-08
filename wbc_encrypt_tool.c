/*
 * wbc_encrypt_tool.c  —  stdin→stdout raw encryptor for NIST STS testing
 *
 * Usage:
 *   ./wbc_encrypt_tool [block_size] < plaintext.bin > ciphertext.bin
 *
 * Reads all of stdin, encrypts with a fixed test key using cascade ECB,
 * outputs raw ciphertext bytes (no header, no MAC, no padding block).
 *
 * Build:
 *   gcc -O2 -o wbc_encrypt_tool wbc_encrypt_tool.c -lssl -lcrypto -lm
 */

/* ── pull in the entire cipher implementation ─────────────────────────── */
#define WBC_TOOL_MODE   /* suppresses main() in the included file */

/* We need all the static functions but not main().
   Strategy: compile the .c directly but rename main via macro. */
#define main wbc1_cascade_main_unused
#include "wbc1_fixed_cascade.c"
#undef main

/* ── tool main ────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    int block_size = 64; /* default: 4³ */
    if (argc > 1) block_size = atoi(argv[1]);

    /* validate block size is a perfect cube in CUBE_SIZES */
    int found = 0;
    for (int i = 0; i < (int)(sizeof(CUBE_SIZES)/sizeof(CUBE_SIZES[0])); i++) {
        if (CUBE_SIZES[i].n == block_size) { found = 1; break; }
    }
    if (!found) {
        fprintf(stderr, "Invalid block size %d. Must be a perfect cube: "
                "8,27,64,125,216,343,512,1000,...\n", block_size);
        return 1;
    }

    /* fixed test key (deterministic for reproducibility) */
    uint8_t key[KEY_SIZE] = {
        0x42,0x13,0x87,0xAF,0x6C,0x55,0xD2,0x91,
        0xE0,0xF4,0x28,0x73,0xBC,0x09,0x5E,0x14,
        0x77,0x3A,0xCC,0x51,0x8B,0xF0,0x22,0x69,
        0xD5,0x4E,0x30,0x9C,0x1B,0xA7,0x64,0x08
    };

    build_op_table(key);

    /* read all of stdin */
    size_t cap = 1 << 20, len = 0;
    uint8_t *pt = malloc(cap);
    int ch;
    while ((ch = fgetc(stdin)) != EOF) {
        if (len == cap) { cap *= 2; pt = realloc(pt, cap); }
        pt[len++] = (uint8_t)ch;
    }

    if (len == 0) { free(pt); return 0; }

    /* encrypt */
    size_t ct_len = 0;
    uint8_t *iv_out = NULL; size_t iv_len = 0;
    uint8_t *ct = cascade_encrypt(key, pt, len, MODE_ECB, NULL,
                                   block_size, &iv_out, &iv_len, &ct_len);
    free(pt);
    if (!ct) { fprintf(stderr, "Encryption failed\n"); return 1; }

    /* strip the trailing pad block — we want only the actual encrypted data */
    size_t raw_len = ct_len > (size_t)block_size ? ct_len - block_size : ct_len;
    fwrite(ct, 1, raw_len, stdout);

    free(ct);
    if (iv_out) free(iv_out);
    return 0;
}
