/*
 * CLI wrapper for wbc2_serial.c (WBC2 — sequential Rubik's-cube block cipher)
 *
 * Usage: cli_wbc2_serial [enc_mode]
 *   enc_mode (argv[1]): CTR_HMAC (default) | ECB | CBC | CTR | OFB | CFB
 * Protocol (stdin):
 *   Line 1: hex key (64 hex chars = 256 bits)
 *   Line 2: 'e' for encrypt, 'd' for decrypt
 *   stdin remainder: raw binary data
 * stdout: raw binary result
 *
 * Output format (enc_mode NOT stored in ciphertext — pass via argv[1] for decrypt):
 *   CTR_HMAC : nonce(12) | "WBC2"(4) | ver=0x01(1) | bsz_BE=0x0010(2) | ct | MAC(32)
 *   ECB      : bsz_BE(2) | ciphertext
 *   CBC/CTR/OFB/CFB : IV(16) | bsz_BE(2) | ciphertext
 */

/* Prevent wbc2_serial.c from compiling its own main() */
#define WBC2_NO_MAIN
#include "../wbc2_serial.c"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* ── Constants ───────────────────────────────────────────────────────────── */
#define WBC2_MAGIC        "WBC2"
#define WBC2_VERSION      0x01
#define WBC2_NONCE_SIZE   12
#define WBC2_MAC_SIZE     32

/* Header sizes */
#define WBC2_CTR_HMAC_HDR 19   /* nonce(12) + magic(4) + ver(1) + bsz_BE(2) */
#define WBC2_IV_HDR       18   /* IV(16) + bsz_BE(2) */
#define WBC2_ECB_HDR       2   /* bsz_BE(2) */

/* ── Enc mode enum ───────────────────────────────────────────────────────── */
typedef enum {
    WBC2_MODE_CTR_HMAC = 0,
    WBC2_MODE_ECB,
    WBC2_MODE_CBC,
    WBC2_MODE_CTR,
    WBC2_MODE_OFB,
    WBC2_MODE_CFB,
} WBC2EncMode;

static WBC2EncMode wbc2_parse_mode(const char *s) {
    if (!s || !*s)                    return WBC2_MODE_CTR_HMAC;
    if (strncasecmp(s,"CTR_HMAC",8)==0) return WBC2_MODE_CTR_HMAC;
    if (strncasecmp(s,"ECB",3)==0)      return WBC2_MODE_ECB;
    if (strncasecmp(s,"CBC",3)==0)      return WBC2_MODE_CBC;
    if (strncasecmp(s,"OFB",3)==0)      return WBC2_MODE_OFB;
    if (strncasecmp(s,"CFB",3)==0)      return WBC2_MODE_CFB;
    if (strncasecmp(s,"CTR",3)==0)      return WBC2_MODE_CTR;
    return WBC2_MODE_CTR_HMAC;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
static void wbc2_random_bytes(uint8_t *buf, int len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { (void)fread(buf, 1, (size_t)len, f); fclose(f); }
    else   { memset(buf, 0, (size_t)len); }
}

/* HMAC-SHA256 */
static void wbc2_hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *out) {
    unsigned int out_len = WBC2_MAC_SIZE;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
}

/* KDF: SHA-512(master_key || nonce) → first 32 bytes = enc key, next 32 = mac key */
static void wbc2_kdf(const uint8_t *master_key, const uint8_t *nonce,
                     uint8_t *key_enc, uint8_t *key_mac) {
    uint8_t input[WBC2_KEY_SIZE + WBC2_NONCE_SIZE];
    memcpy(input, master_key, WBC2_KEY_SIZE);
    memcpy(input + WBC2_KEY_SIZE, nonce, WBC2_NONCE_SIZE);
    uint8_t digest[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, input, sizeof(input));
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);
    memcpy(key_enc, digest,      32);
    memcpy(key_mac, digest + 32, 32);
}

/* Constant-time compare */
static int wbc2_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff != 0;
}

/* ── Encrypt ─────────────────────────────────────────────────────────────── */
static uint8_t *wbc2_encrypt(const uint8_t *key, const uint8_t *data, size_t data_len,
                              WBC2EncMode mode, size_t *out_len) {
    WBC2Cipher cipher;

    if (mode == WBC2_MODE_CTR_HMAC) {
        /* Derive enc/mac keys from random nonce */
        uint8_t nonce[WBC2_NONCE_SIZE];
        wbc2_random_bytes(nonce, WBC2_NONCE_SIZE);
        uint8_t key_enc[32], key_mac[32];
        wbc2_kdf(key, nonce, key_enc, key_mac);
        wbc2_init(&cipher, key_enc, 32);

        /* Pad */
        size_t pad_len;
        uint8_t *padded = wbc2_pad(data, data_len, &pad_len);
        size_t n_blocks = pad_len / WBC2_BLOCK_SIZE;
        uint8_t *ct_buf = (uint8_t *)malloc(pad_len);

        /* CTR mode: encrypt (nonce || counter_BE) */
        uint8_t ctr_block[WBC2_BLOCK_SIZE];
        size_t ctr_suffix = WBC2_BLOCK_SIZE - WBC2_NONCE_SIZE;
        memcpy(ctr_block, nonce, WBC2_NONCE_SIZE);
        for (size_t b = 0; b < n_blocks; b++) {
            /* counter big-endian in the last bytes */
            size_t cnt = b;
            for (int j = (int)ctr_suffix - 1; j >= 0; j--) {
                ctr_block[WBC2_NONCE_SIZE + j] = (uint8_t)(cnt & 0xFF);
                cnt >>= 8;
            }
            uint8_t ks[WBC2_BLOCK_SIZE];
            wbc2_encrypt_block(&cipher, ctr_block, ks);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++)
                ct_buf[b * WBC2_BLOCK_SIZE + j] = padded[b * WBC2_BLOCK_SIZE + j] ^ ks[j];
        }
        free(padded);
        wbc2_free(&cipher);

        /* MAC = HMAC-SHA256(key_mac, magic||ver||bsz||nonce||ct) */
        uint8_t hdr_raw[7];
        memcpy(hdr_raw, WBC2_MAGIC, 4);
        hdr_raw[4] = WBC2_VERSION;
        hdr_raw[5] = (uint8_t)(WBC2_BLOCK_SIZE >> 8);
        hdr_raw[6] = (uint8_t)(WBC2_BLOCK_SIZE & 0xFF);
        uint8_t mac[WBC2_MAC_SIZE];
        /* mac covers: magic+ver+bsz + nonce + ciphertext */
        uint8_t *mac_input = (uint8_t *)malloc(7 + WBC2_NONCE_SIZE + pad_len);
        memcpy(mac_input, hdr_raw, 7);
        memcpy(mac_input + 7, nonce, WBC2_NONCE_SIZE);
        memcpy(mac_input + 7 + WBC2_NONCE_SIZE, ct_buf, pad_len);
        wbc2_hmac_sha256(key_mac, 32, mac_input, 7 + WBC2_NONCE_SIZE + pad_len, mac);
        free(mac_input);

        /* Output: nonce(12) | magic(4) | ver(1) | bsz(2) | ct | MAC(32) */
        *out_len = (size_t)WBC2_CTR_HMAC_HDR + pad_len + WBC2_MAC_SIZE;
        uint8_t *out = (uint8_t *)malloc(*out_len);
        memcpy(out,                                       nonce,   WBC2_NONCE_SIZE);
        memcpy(out + WBC2_NONCE_SIZE,                     hdr_raw, 7);
        memcpy(out + WBC2_NONCE_SIZE + 7,                 ct_buf,  pad_len);
        memcpy(out + WBC2_NONCE_SIZE + 7 + pad_len,       mac,     WBC2_MAC_SIZE);
        free(ct_buf);
        return out;
    }

    /* All other modes: init cipher with master key */
    wbc2_init(&cipher, key, WBC2_KEY_SIZE);

    /* Pad */
    size_t pad_len;
    uint8_t *padded = wbc2_pad(data, data_len, &pad_len);
    size_t n_blocks = pad_len / WBC2_BLOCK_SIZE;
    uint8_t *ct_buf = (uint8_t *)malloc(pad_len);

    uint8_t iv[WBC2_BLOCK_SIZE] = {0};
    if (mode != WBC2_MODE_ECB) wbc2_random_bytes(iv, WBC2_BLOCK_SIZE);

    uint8_t prev[WBC2_BLOCK_SIZE];
    memcpy(prev, iv, WBC2_BLOCK_SIZE);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk = padded + b * WBC2_BLOCK_SIZE;
        uint8_t *out_blk   = ct_buf + b * WBC2_BLOCK_SIZE;
        uint8_t tmp[WBC2_BLOCK_SIZE];

        switch (mode) {
        case WBC2_MODE_ECB:
            wbc2_encrypt_block(&cipher, blk, out_blk);
            break;
        case WBC2_MODE_CBC:
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) tmp[j] = blk[j] ^ prev[j];
            wbc2_encrypt_block(&cipher, tmp, out_blk);
            memcpy(prev, out_blk, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_CFB:
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            memcpy(prev, out_blk, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_OFB:
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            memcpy(prev, tmp, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_CTR: {
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            /* increment counter big-endian */
            int carry = 1;
            for (int j = WBC2_BLOCK_SIZE-1; j >= 0 && carry; j--) {
                int v = prev[j] + carry; prev[j] = (uint8_t)(v & 0xFF); carry = v >> 8;
            }
            break;
        }
        default: break;
        }
    }
    free(padded);
    wbc2_free(&cipher);

    /* Build output */
    if (mode == WBC2_MODE_ECB) {
        *out_len = WBC2_ECB_HDR + pad_len;
        uint8_t *out = (uint8_t *)malloc(*out_len);
        out[0] = (uint8_t)(WBC2_BLOCK_SIZE >> 8);
        out[1] = (uint8_t)(WBC2_BLOCK_SIZE & 0xFF);
        memcpy(out + WBC2_ECB_HDR, ct_buf, pad_len);
        free(ct_buf);
        return out;
    } else {
        *out_len = WBC2_IV_HDR + pad_len;
        uint8_t *out = (uint8_t *)malloc(*out_len);
        memcpy(out, iv, WBC2_BLOCK_SIZE);
        out[16] = (uint8_t)(WBC2_BLOCK_SIZE >> 8);
        out[17] = (uint8_t)(WBC2_BLOCK_SIZE & 0xFF);
        memcpy(out + WBC2_IV_HDR, ct_buf, pad_len);
        free(ct_buf);
        return out;
    }
}

/* ── Decrypt ─────────────────────────────────────────────────────────────── */
static uint8_t *wbc2_decrypt(const uint8_t *key, const uint8_t *data, size_t data_len,
                              WBC2EncMode mode, size_t *out_len) {
    WBC2Cipher cipher;

    if (mode == WBC2_MODE_CTR_HMAC) {
        /* New format: nonce(12) | "WBC2"(4) | ver(1) | bsz(2) | ct | MAC(32) */
        if (data_len < (size_t)WBC2_CTR_HMAC_HDR + WBC2_MAC_SIZE) {
            fprintf(stderr, "ERROR: CTR_HMAC input too short\n"); *out_len = 0; return NULL;
        }
        if (memcmp(data + WBC2_NONCE_SIZE, WBC2_MAGIC, 4) != 0) {
            fprintf(stderr, "ERROR: invalid WBC2 magic\n"); *out_len = 0; return NULL;
        }
        const uint8_t *nonce = data;
        /* bsz not needed — always WBC2_BLOCK_SIZE */
        size_t ct_len = data_len - WBC2_CTR_HMAC_HDR - WBC2_MAC_SIZE;
        const uint8_t *ct_buf = data + WBC2_CTR_HMAC_HDR;
        const uint8_t *mac_in = data + WBC2_CTR_HMAC_HDR + ct_len;

        uint8_t key_enc[32], key_mac[32];
        wbc2_kdf(key, nonce, key_enc, key_mac);

        /* Verify MAC */
        uint8_t mac_expected[WBC2_MAC_SIZE];
        uint8_t *mac_data = (uint8_t *)malloc(7 + WBC2_NONCE_SIZE + ct_len);
        memcpy(mac_data,                           data + WBC2_NONCE_SIZE, 7); /* magic+ver+bsz */
        memcpy(mac_data + 7,                       nonce, WBC2_NONCE_SIZE);
        memcpy(mac_data + 7 + WBC2_NONCE_SIZE,     ct_buf, ct_len);
        wbc2_hmac_sha256(key_mac, 32, mac_data, 7 + WBC2_NONCE_SIZE + ct_len, mac_expected);
        free(mac_data);
        if (wbc2_ct_memcmp(mac_in, mac_expected, WBC2_MAC_SIZE)) {
            fprintf(stderr, "ERROR: MAC verification failed\n"); *out_len = 0; return NULL;
        }

        wbc2_init(&cipher, key_enc, 32);
        size_t n_blocks = ct_len / WBC2_BLOCK_SIZE;
        uint8_t *pt_buf = (uint8_t *)malloc(ct_len);

        uint8_t ctr_block[WBC2_BLOCK_SIZE];
        size_t ctr_suffix = WBC2_BLOCK_SIZE - WBC2_NONCE_SIZE;
        memcpy(ctr_block, nonce, WBC2_NONCE_SIZE);
        for (size_t b = 0; b < n_blocks; b++) {
            size_t cnt = b;
            for (int j = (int)ctr_suffix-1; j >= 0; j--) {
                ctr_block[WBC2_NONCE_SIZE+j] = (uint8_t)(cnt & 0xFF); cnt >>= 8;
            }
            uint8_t ks[WBC2_BLOCK_SIZE];
            wbc2_encrypt_block(&cipher, ctr_block, ks);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++)
                pt_buf[b * WBC2_BLOCK_SIZE + j] = ct_buf[b * WBC2_BLOCK_SIZE + j] ^ ks[j];
        }
        wbc2_free(&cipher);

        uint8_t *result = wbc2_unpad(pt_buf, ct_len, out_len);
        free(pt_buf);
        return result;
    }

    /* ECB / IV-based modes */
    const uint8_t *ct_buf;
    size_t ct_len;
    uint8_t iv[WBC2_BLOCK_SIZE] = {0};

    if (mode == WBC2_MODE_ECB) {
        if (data_len < WBC2_ECB_HDR) { *out_len = 0; return NULL; }
        /* bsz at bytes 0-1 — always WBC2_BLOCK_SIZE, validate anyway */
        ct_buf = data + WBC2_ECB_HDR;
        ct_len = data_len - WBC2_ECB_HDR;
    } else {
        if (data_len < (size_t)WBC2_IV_HDR) { *out_len = 0; return NULL; }
        memcpy(iv, data, WBC2_BLOCK_SIZE);
        ct_buf = data + WBC2_IV_HDR;
        ct_len = data_len - WBC2_IV_HDR;
    }

    wbc2_init(&cipher, key, WBC2_KEY_SIZE);
    size_t n_blocks = ct_len / WBC2_BLOCK_SIZE;
    uint8_t *pt_buf = (uint8_t *)malloc(ct_len);

    uint8_t prev[WBC2_BLOCK_SIZE];
    memcpy(prev, iv, WBC2_BLOCK_SIZE);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk = ct_buf + b * WBC2_BLOCK_SIZE;
        uint8_t *out_blk   = pt_buf + b * WBC2_BLOCK_SIZE;
        uint8_t tmp[WBC2_BLOCK_SIZE];

        switch (mode) {
        case WBC2_MODE_ECB:
            wbc2_decrypt_block(&cipher, blk, out_blk);
            break;
        case WBC2_MODE_CBC:
            wbc2_decrypt_block(&cipher, blk, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = tmp[j] ^ prev[j];
            memcpy(prev, blk, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_CFB:
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            memcpy(prev, blk, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_OFB:
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            memcpy(prev, tmp, WBC2_BLOCK_SIZE);
            break;
        case WBC2_MODE_CTR: {
            wbc2_encrypt_block(&cipher, prev, tmp);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++) out_blk[j] = blk[j] ^ tmp[j];
            int carry = 1;
            for (int j = WBC2_BLOCK_SIZE-1; j >= 0 && carry; j--) {
                int v = prev[j] + carry; prev[j] = (uint8_t)(v & 0xFF); carry = v >> 8;
            }
            break;
        }
        default: break;
        }
    }
    wbc2_free(&cipher);

    uint8_t *result = wbc2_unpad(pt_buf, ct_len, out_len);
    free(pt_buf);
    return result;
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    WBC2EncMode enc_mode = wbc2_parse_mode(argc >= 2 ? argv[1] : "");

    /* Read key */
    char hex_key[128] = {0};
    if (!fgets(hex_key, sizeof(hex_key), stdin)) {
        fprintf(stderr, "ERROR: cannot read key\n"); return 1;
    }
    hex_key[strcspn(hex_key, "\r\n")] = 0;
    if (strlen(hex_key) != 64) {
        fprintf(stderr, "ERROR: key must be 64 hex chars\n"); return 1;
    }
    uint8_t key[WBC2_KEY_SIZE];
    for (int i = 0; i < WBC2_KEY_SIZE; i++) {
        unsigned int b; sscanf(hex_key + i * 2, "%02x", &b); key[i] = (uint8_t)b;
    }

    /* Read operation */
    char op_line[16] = {0};
    if (!fgets(op_line, sizeof(op_line), stdin)) {
        fprintf(stderr, "ERROR: cannot read op\n"); return 1;
    }
    op_line[strcspn(op_line, "\r\n")] = 0;
    int do_encrypt = (op_line[0] == 'e' || op_line[0] == 'E');

    /* Read input data */
    size_t cap = 1 << 20;
    uint8_t *data = (uint8_t *)malloc(cap);
    size_t data_len = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (data_len >= cap) { cap *= 2; data = (uint8_t *)realloc(data, cap); }
        data[data_len++] = (uint8_t)c;
    }
    if (data_len == 0) { fprintf(stderr, "ERROR: no data\n"); free(data); return 1; }

    /* Encrypt or decrypt */
    size_t out_len = 0;
    uint8_t *result = do_encrypt
        ? wbc2_encrypt(key, data, data_len, enc_mode, &out_len)
        : wbc2_decrypt(key, data, data_len, enc_mode, &out_len);
    free(data);

    if (!result) { fprintf(stderr, "ERROR: cipher operation failed\n"); return 1; }
    fwrite(result, 1, out_len, stdout);
    fflush(stdout);
    free(result);
    return 0;
}
