/*
 * Shared mode-aware encrypt/decrypt helpers for WBC serial CLI wrappers.
 * Include this AFTER including the algorithm .c file so the types/functions
 * (cascade_encrypt, cascade_decrypt, cascade_encrypt_ctr_hmac,
 *  cascade_decrypt_ctr_hmac, EncMode, build_op_table, auto_block_size)
 * are already visible.
 *
 * Output framing (enc_mode passed via argv[1], NOT stored in ciphertext)
 * =======================================================================
 *  CTR_HMAC : nonce(12) | "WBC1"(4) | ver(1) | block_size_BE(2) | ct | MAC(32)
 *             First 12 bytes = random nonce → differs for every encryption.
 *             Backward-compat: old format ("WBC1" at offset 0) also decrypts.
 *
 *  CBC/CTR/OFB/CFB : IV(16) | block_size_BE(2) | ciphertext
 *             First 16 bytes = random IV → differs for every encryption.
 *
 *  ECB       : block_size_BE(2) | ciphertext
 *             Deterministic by nature; block_size at start (2 bytes).
 *
 * Mode must be supplied at decrypt time (argv[1]) – it is not embedded.
 */

#ifndef CLI_WBC_SERIAL_COMMON_H
#define CLI_WBC_SERIAL_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Header sizes for the new format */
#define WBCM_CTR_HMAC_HDR 19  /* nonce(12) + "WBC1"(4) + ver(1) + bsz_BE(2) */
#define WBCM_IV_HDR       18  /* IV(16) + bsz_BE(2) — for CBC/CTR/OFB/CFB   */
#define WBCM_ECB_HDR       2  /* bsz_BE(2) — for ECB                        */

static EncMode parse_enc_mode(const char *s) {
    if (!s || *s == '\0') return MODE_WBC_CTR_HMAC;
    if (strncasecmp(s, "ECB", 3) == 0) return MODE_ECB;
    if (strncasecmp(s, "CBC", 3) == 0) return MODE_CBC;
    if (strncasecmp(s, "OFB", 3) == 0) return MODE_OFB;
    if (strncasecmp(s, "CFB", 3) == 0) return MODE_CFB;
    if (strncasecmp(s, "CTR_HMAC", 8) == 0) return MODE_WBC_CTR_HMAC;
    if (strncasecmp(s, "CTR", 3) == 0) return MODE_CTR;
    return MODE_WBC_CTR_HMAC;  /* default */
}

/* Random bytes from /dev/urandom (falls back to zeros on error). */
static void random_bytes(uint8_t *buf, int len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, (size_t)len, f); fclose(f); }
    else   { memset(buf, 0, (size_t)len); }
}

/*
 * serial_encrypt_with_mode
 * Returns malloc'd buffer; sets *out_len.
 */
static uint8_t *serial_encrypt_with_mode(const uint8_t key[32],
                                          const uint8_t *data, size_t data_len,
                                          EncMode mode, size_t *out_len) {
    build_op_table(key);
    int block_size = auto_block_size((int)data_len);

    if (mode == MODE_WBC_CTR_HMAC) {
        /* cascade_encrypt_ctr_hmac output:
         *   "WBC1"(4) + ver(1) + bsz_BE(2) + nonce(12) + ct + MAC(32)
         * Rearrange to put nonce first so bytes 0-11 are always random: */
        size_t raw_len = 0;
        uint8_t *raw = cascade_encrypt_ctr_hmac(key, data, data_len,
                                                block_size, NULL, &raw_len);
        if (!raw) { *out_len = 0; return NULL; }
        /* raw[0..6] = "WBC1"+ver+bsz_BE, raw[7..18] = nonce, raw[19..] = ct+MAC */
        uint8_t *out = (uint8_t *)malloc(raw_len);
        if (!out) { free(raw); *out_len = 0; return NULL; }
        memcpy(out,      raw + 7,  12);              /* nonce        → [0..11]  */
        memcpy(out + 12, raw,       7);              /* WBC1+ver+bsz → [12..18] */
        memcpy(out + 19, raw + 19,  raw_len - 19);   /* ct+MAC       → [19..]   */
        free(raw);
        *out_len = raw_len;
        return out;
    }

    uint8_t iv_short[16] = {0};  /* 16 random bytes stored in header */
    if (mode != MODE_ECB) random_bytes(iv_short, 16);

    /* Build full block_size IV: first 16 bytes random, rest zeroed */
    uint8_t *iv_full = (uint8_t *)calloc((size_t)block_size, 1);
    if (!iv_full) { *out_len = 0; return NULL; }
    if (mode != MODE_ECB) memcpy(iv_full, iv_short, 16);

    size_t enc_len = 0;
    size_t iv_out_len = 0;
    uint8_t *iv_out = NULL;
    uint8_t *enc = cascade_encrypt(key, data, data_len, mode,
                                   (mode == MODE_ECB ? NULL : iv_full), block_size,
                                   &iv_out, &iv_out_len, &enc_len);
    free(iv_full);
    if (!enc) { *out_len = 0; if (iv_out) free(iv_out); return NULL; }

    uint8_t *out;
    size_t total;
    if (mode == MODE_ECB) {
        /* ECB: block_size_BE(2) | ciphertext */
        total = (size_t)WBCM_ECB_HDR + enc_len;
        out = (uint8_t *)malloc(total);
        out[0] = (uint8_t)((unsigned)block_size >> 8);
        out[1] = (uint8_t)((unsigned)block_size & 0xFF);
        memcpy(out + WBCM_ECB_HDR, enc, enc_len);
    } else {
        /* CBC/CTR/OFB/CFB: IV_16(16) | block_size_BE(2) | ciphertext
         * First 16 bytes = random IV → output starts with random data */
        total = (size_t)WBCM_IV_HDR + enc_len;
        out = (uint8_t *)malloc(total);
        memcpy(out, iv_short, 16);
        out[16] = (uint8_t)((unsigned)block_size >> 8);
        out[17] = (uint8_t)((unsigned)block_size & 0xFF);
        memcpy(out + WBCM_IV_HDR, enc, enc_len);
    }
    *out_len = total;
    free(enc);
    if (iv_out) free(iv_out);
    return out;
}

/*
 * serial_decrypt_with_mode
 * mode_hint MUST be the mode used during encryption (from argv[1]).
 */
static uint8_t *serial_decrypt_with_mode(const uint8_t key[32],
                                          const uint8_t *data, size_t data_len,
                                          EncMode mode_hint, size_t *out_len) {
    build_op_table(key);

    if (mode_hint == MODE_WBC_CTR_HMAC) {
        /* New format: nonce(12) | "WBC1"(4) | ver(1) | bsz_BE(2) | ct | MAC */
        if (data_len >= (size_t)WBCM_CTR_HMAC_HDR &&
                memcmp(data + 12, "WBC1", 4) == 0) {
            uint8_t *tmp = (uint8_t *)malloc(data_len);
            if (!tmp) { *out_len = 0; return NULL; }
            memcpy(tmp,      data + 12, 7);           /* WBC1+ver+bsz → [0..6]  */
            memcpy(tmp + 7,  data,      12);           /* nonce        → [7..18] */
            memcpy(tmp + 19, data + 19, data_len - 19);/* ct+MAC       → [19..] */
            uint8_t *result = cascade_decrypt_ctr_hmac(key, tmp, data_len, out_len);
            free(tmp);
            return result;
        }
        /* Backward-compat: old format "WBC1" at offset 0 */
        if (data_len >= 4 &&
                (memcmp(data, "WBC1", 4) == 0 || memcmp(data, "WBC2", 4) == 0)) {
            return cascade_decrypt_ctr_hmac(key, data, data_len, out_len);
        }
        *out_len = 0;
        return NULL;
    }

    if (mode_hint == MODE_ECB) {
        /* ECB: block_size_BE(2) | ciphertext */
        if (data_len < (size_t)WBCM_ECB_HDR) { *out_len = 0; return NULL; }
        int bsz = (int)(((unsigned)data[0] << 8) | data[1]);
        return cascade_decrypt(key, data + WBCM_ECB_HDR,
                               data_len - (size_t)WBCM_ECB_HDR,
                               MODE_ECB, NULL, bsz, out_len);
    }

    /* CBC/CTR/OFB/CFB: IV_16(16) | block_size_BE(2) | ciphertext */
    if (data_len < (size_t)WBCM_IV_HDR) { *out_len = 0; return NULL; }
    int bsz = (int)(((unsigned)data[16] << 8) | data[17]);
    /* Reconstruct full block_size IV: stored 16 bytes + zeroes */
    uint8_t *iv_full = (uint8_t *)calloc((size_t)bsz, 1);
    if (!iv_full) { *out_len = 0; return NULL; }
    memcpy(iv_full, data, 16);
    uint8_t *result = cascade_decrypt(key, data + WBCM_IV_HDR,
                                      data_len - (size_t)WBCM_IV_HDR,
                                      mode_hint, iv_full, bsz, out_len);
    free(iv_full);
    return result;
}

#endif /* CLI_WBC_SERIAL_COMMON_H */
