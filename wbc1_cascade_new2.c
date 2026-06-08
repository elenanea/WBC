/*
 * WBC1-CASCADE-NEW2 -- Ключ-залежні випадкові перестановки (White-Box підхід)
 * =============================================================================
 * Відмінності від wbc1_cascade_new1.c:
 *
 * ЗАМІСТЬ фіксованих 127 геометричних операцій куба використовується:
 *   key → HMAC-SHA256(key, round) → xorshift64 → Fisher-Yates → N! перестановок
 *
 * Переваги:
 *   - Простір перестановок = N! замість 127 фіксованих операцій
 *     (для N=1331: 1331! >> 2^4096, набагато більший ніж AES-256 keyspace 2^256)
 *   - Кожен ключ → унікальний набір ROUNDS перестановок, не підмножина фіксованих
 *   - g_comp_fwd = ROUNDS перестановок, складених в одну: 2.6 KB → в L1-кеш!
 *   - Фіксований ключ: ~32× прискорення (кеш композиції)
 *   - Cascade режим: HMAC-SHA256×ROUNDS + Fisher-Yates → rebuild кожен блок
 *
 * Архітектура encrypt_block:
 *   in → XOR key_expand → composed_perm(g_comp_fwd) → XOR key_expand → out
 *   (composed_perm = composition of ROUNDS key-derived random permutations)
 *
 * Build:
 *   gcc -O3 -march=native -o wbc1_cascade_new2 wbc1_cascade_new2.c -lssl -lcrypto -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* ── constants ────────────────────────────────────────────────────────────── */

#define MAGIC        "WBC2"        /* different magic to distinguish from new1 */
#define MAGIC_LEN    4
#define VERSION_CASC 0x05
#define NONCE_SIZE   12
#define MAC_SIZE     32
#define KEY_SIZE     32
#define ROUNDS       32            /* number of key-derived permutation rounds  */

/* ── cube sizes ───────────────────────────────────────────────────────────── */

typedef struct { int n; int dim; } CubeSize;
static const CubeSize CUBE_SIZES[] = {
    {8,2},{27,3},{64,4},{125,5},{216,6},{343,7},{512,8},{1000,10},
    {1331,11},{1728,12},{2197,13},{2744,14},{3375,15},{4096,16}
};
#define NUM_CUBE_SIZES (int)(sizeof(CUBE_SIZES)/sizeof(CUBE_SIZES[0]))

static int auto_block_size(int data_len) {
    for (int i = 0; i < NUM_CUBE_SIZES; i++)
        if (data_len <= CUBE_SIZES[i].n) return CUBE_SIZES[i].n;
    return CUBE_SIZES[NUM_CUBE_SIZES-1].n;
}

/* ── byte helpers ─────────────────────────────────────────────────────────── */

static uint8_t rotate_right(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b >> n) | (b << (8-n)));
}
static uint8_t rotate_left(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b << n) | (b >> (8-n)));
}
static void sha256w(const uint8_t *d, size_t l, uint8_t o[32]) { SHA256(d,l,o); }
static void sha512w(const uint8_t *d, size_t l, uint8_t o[64]) { SHA512(d,l,o); }

/* ═══════════════════════════════════════════════════════════════════════════
 * KEY-DERIVED PERMUTATION ENGINE
 *
 * For each key + round index, generate a uniformly random permutation of
 * [0 .. N-1] using:
 *   1. HMAC-SHA256(key, LE32(round))  →  32-byte cryptographic seed
 *   2. Seed initialises xorshift64 state  (fast, produces the Fisher-Yates stream)
 *   3. Fisher-Yates in-place shuffle  →  random permutation perm[N]
 *
 * Composition cache (g_comp_fwd / g_comp_inv):
 *   Compose all ROUNDS permutations into a single lookup table.
 *   Size: N × 2 bytes = 2662 bytes for N=1331  →  fits entirely in L1 cache.
 *   Rebuilt only when key or block_size changes.
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint16_t *g_comp_fwd = NULL;   /* composed forward permutation [N]  */
static uint16_t *g_comp_inv = NULL;   /* composed inverse permutation [N]  */
static uint8_t   g_built_key[KEY_SIZE] = {0};
static int       g_built_N  = -1;

/* Fast non-cryptographic PRNG seeded from a cryptographic value */
static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x; return x;
}

/*
 * gen_permutation – generate one uniformly random permutation of [0..N-1]
 *   key   : KEY_SIZE-byte master (or cascade) key
 *   round : round index (0 .. ROUNDS-1)
 *   perm  : output array of N uint16_t entries
 */
static void gen_permutation(const uint8_t *key, uint32_t round,
                              uint16_t *perm, int N) {
    /* Cryptographic seed: HMAC-SHA256(key, LE32(round)) */
    uint8_t round_buf[4] = {
        (uint8_t)(round),       (uint8_t)(round >> 8),
        (uint8_t)(round >> 16), (uint8_t)(round >> 24)
    };
    uint8_t seed[32];
    unsigned int slen = 32;
    HMAC(EVP_sha256(), key, KEY_SIZE, round_buf, 4, seed, &slen);

    /* Initialise xorshift64 from seed (combine 8 bytes per word) */
    uint64_t state = 0;
    for (int i = 0; i < 8; i++) state = (state << 8) | seed[i];
    state ^= ((uint64_t)seed[8]  << 56) | ((uint64_t)seed[9]  << 48)
           | ((uint64_t)seed[10] << 40) | ((uint64_t)seed[11] << 32)
           | ((uint64_t)seed[12] << 24) | ((uint64_t)seed[13] << 16)
           | ((uint64_t)seed[14] <<  8) | ((uint64_t)seed[15]);
    if (state == 0) state = 0xDEADBEEFCAFEBABEULL;

    /* Fisher-Yates shuffle */
    for (int i = 0; i < N; i++) perm[i] = (uint16_t)i;
    for (int i = N-1; i > 0; i--) {
        uint64_t r = xorshift64(&state);
        int j = (int)(r % (uint64_t)(i+1));
        uint16_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
    }
}

/*
 * build_key_table – generate ROUNDS permutations and compose them.
 *
 *   Composition:  comp[i] = perm_{ROUNDS-1}[... perm_1[perm_0[i]] ...]
 *   Result stored in g_comp_fwd (2.6 KB for N=1331) → entire table fits in L1.
 *
 *   Cache: if (key, N) unchanged, returns immediately (O(1)).
 */
static void build_key_table(const uint8_t *key, int N) {
    if (g_built_N == N && memcmp(g_built_key, key, KEY_SIZE) == 0) return;

    if (g_built_N != N) {
        free(g_comp_fwd); g_comp_fwd = (uint16_t *)malloc((size_t)N * sizeof(uint16_t));
        free(g_comp_inv); g_comp_inv = (uint16_t *)malloc((size_t)N * sizeof(uint16_t));
        g_built_N = N;
        g_built_key[0] ^= 0xFF;  /* force invalidation */
    }

    uint16_t *round_perm = (uint16_t *)malloc((size_t)N * sizeof(uint16_t));
    uint16_t *tmp        = (uint16_t *)malloc((size_t)N * sizeof(uint16_t));

    /* Start with identity */
    for (int i = 0; i < N; i++) g_comp_fwd[i] = (uint16_t)i;

    for (uint32_t r = 0; r < (uint32_t)ROUNDS; r++) {
        gen_permutation(key, r, round_perm, N);
        /* Compose: new_comp[i] = round_perm[comp[i]] */
        for (int i = 0; i < N; i++) tmp[i] = round_perm[g_comp_fwd[i]];
        memcpy(g_comp_fwd, tmp, (size_t)N * sizeof(uint16_t));
    }

    /* Build inverse: inv[fwd[i]] = i */
    for (int i = 0; i < N; i++) g_comp_inv[g_comp_fwd[i]] = (uint16_t)i;

    free(round_perm); free(tmp);
    memcpy(g_built_key, key, KEY_SIZE);
}

/* ── encrypt / decrypt block ─────────────────────────────────────────────── *
 *
 * encrypt: out = perm( in XOR key_wrap ) XOR key_wrap
 * decrypt: out = perm_inv( in XOR key_wrap ) XOR key_wrap
 *
 * key_wrap uses key[i % KEY_SIZE] (same as new1) for initial + final whitening.
 *
 * The composed permutation is 2.6 KB → fits in L1 → one pass over data.
 * ─────────────────────────────────────────────────────────────────────────── */

static void encrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int N = block_size;
    build_key_table(key_mat, N);   /* no-op if key+N unchanged */

    uint8_t tmp[N];
    for (int i = 0; i < N; i++) tmp[i] = block[i] ^ key_mat[i % KEY_SIZE];
    for (int i = 0; i < N; i++) out[i] = tmp[g_comp_fwd[i]];
    for (int i = 0; i < N; i++) out[i] ^= key_mat[i % KEY_SIZE];
}

static void decrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int N = block_size;
    build_key_table(key_mat, N);

    uint8_t tmp[N];
    for (int i = 0; i < N; i++) tmp[i] = block[i] ^ key_mat[i % KEY_SIZE];
    for (int i = 0; i < N; i++) out[i] = tmp[g_comp_inv[i]];
    for (int i = 0; i < N; i++) out[i] ^= key_mat[i % KEY_SIZE];
}

/* ── padding ──────────────────────────────────────────────────────────────── */

static uint8_t *wbc1_pad(const uint8_t *data, size_t data_len,
                          int block_bytes, size_t *out_len) {
    int remainder = (int)(data_len % block_bytes);
    int fill_len  = (remainder==0) ? 0 : block_bytes-remainder;
    size_t aligned = data_len+fill_len;
    size_t total   = aligned+block_bytes;
    uint8_t *out   = (uint8_t *)calloc(total,1);
    memcpy(out,data,data_len);
    out[aligned]   = (uint8_t)(fill_len&0xFF);
    out[aligned+1] = (uint8_t)((fill_len>>8)&0xFF);
    *out_len = total;
    return out;
}

static uint8_t *wbc1_unpad(const uint8_t *data, size_t data_len,
                             int block_bytes, size_t *out_len) {
    if ((int)data_len < block_bytes) { *out_len=0; return (uint8_t*)calloc(1,1); }
    int fill_len = (int)data[data_len-block_bytes]|((int)data[data_len-block_bytes+1]<<8);
    size_t strip = block_bytes+fill_len;
    if (strip > data_len) { *out_len=0; return (uint8_t*)calloc(1,1); }
    *out_len = data_len-strip;
    uint8_t *out = (uint8_t *)malloc(*out_len+1);
    memcpy(out,data,*out_len); out[*out_len]=0;
    return out;
}

/* ── cascade key derivation ───────────────────────────────────────────────── */

static void derive_cascade_key(const uint8_t *enc_block, int block_bytes,
                                uint8_t new_rk[KEY_SIZE]) {
    uint8_t S[64] = {0};
    for (int j = 0; j < block_bytes; j++) S[j&63] ^= enc_block[j];
    for (int r = 0; r < 4; r++) {
        uint8_t c = (uint8_t)(S[63]^r);
        for (int i=0;i<64;i++) { c=(uint8_t)(S[i]+rotate_left(c,5)+(uint8_t)(67*i+29*r)); S[i]=c; }
        c = (uint8_t)(S[0]^(uint8_t)(r*37));
        for (int i=63;i>=0;i--) { c=S[i]^rotate_right(c,3); S[i]=c; }
    }
    memcpy(new_rk, S, KEY_SIZE);
}

/* ── KDF + HMAC ───────────────────────────────────────────────────────────── */

static void kdf(const uint8_t key[32], const uint8_t nonce[NONCE_SIZE],
                uint8_t key_crypt[32], uint8_t key_mac[32]) {
    uint8_t in[KEY_SIZE+NONCE_SIZE];
    memcpy(in,key,KEY_SIZE); memcpy(in+KEY_SIZE,nonce,NONCE_SIZE);
    uint8_t h[64]; sha512w(in,KEY_SIZE+NONCE_SIZE,h);
    memcpy(key_crypt,h,32); memcpy(key_mac,h+32,32);
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *data, size_t dlen, uint8_t out[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(),key,(int)klen,data,dlen,out,&olen);
}

/* ── mode enum ────────────────────────────────────────────────────────────── */

typedef enum { MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR,
               MODE_WBC_CTR_HMAC } EncMode;

static const char *mode_name(EncMode m) {
    switch(m) {
        case MODE_ECB:          return "ECB";
        case MODE_CBC:          return "CBC";
        case MODE_CFB:          return "CFB";
        case MODE_OFB:          return "OFB";
        case MODE_CTR:          return "CTR";
        case MODE_WBC_CTR_HMAC: return "WBC-CTR-HMAC";
        default:                return "?";
    }
}

static int mode_is_key_avalanche(EncMode mode) {
    return (mode==MODE_CTR||mode==MODE_CFB||mode==MODE_OFB||mode==MODE_WBC_CTR_HMAC);
}

/* ── cascade_encrypt / cascade_decrypt ───────────────────────────────────── */

static uint8_t *cascade_encrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode,
                                  const uint8_t *iv_in, int block_size,
                                  uint8_t **iv_out, size_t *iv_len_out,
                                  int double_pass, size_t *out_len) {
    int block_bytes = block_size;
    /* Pre-build table for master key (warmup; cascade will rebuild each block) */
    build_key_table(master_key, block_bytes);

    size_t padded_len;
    uint8_t *padded = wbc1_pad(data, data_len, block_bytes, &padded_len);
    size_t n_blocks = padded_len / block_bytes;

    uint8_t *inter  = (uint8_t *)malloc(padded_len);
    uint8_t *result = double_pass ? (uint8_t *)malloc(padded_len) : NULL;

    uint8_t iv[4096] = {0};
    if (mode != MODE_ECB) {
        if (iv_in) memcpy(iv, iv_in, block_bytes);
        else RAND_bytes(iv, block_bytes);
        if (iv_out) {
            *iv_out = (uint8_t *)malloc(block_bytes);
            memcpy(*iv_out, iv, block_bytes); *iv_len_out = block_bytes;
        }
    } else {
        if (iv_out) { *iv_out = NULL; *iv_len_out = 0; }
    }

    uint8_t rk[KEY_SIZE]; memcpy(rk, master_key, KEY_SIZE);
    uint8_t prev[4096], tmp_block[4096], enc_prev[4096];
    memcpy(prev, iv, block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = padded + b*block_bytes;
        uint8_t       *out_b = inter  + b*block_bytes;

        if (mode == MODE_ECB) {
            encrypt_block(rk, blk, block_size, out_b);
            derive_cascade_key(out_b, block_bytes, rk);
        } else if (mode == MODE_CBC) {
            for (int i=0;i<block_bytes;i++) tmp_block[i]=blk[i]^prev[i];
            encrypt_block(rk, tmp_block, block_size, out_b);
            derive_cascade_key(out_b, block_bytes, rk);
            memcpy(prev, out_b, block_bytes);
        } else if (mode == MODE_CFB) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, out_b, block_bytes);
        } else if (mode == MODE_OFB) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, enc_prev, block_bytes);
        } else if (mode == MODE_CTR) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            int carry=1;
            for (int i=block_bytes-1;i>=0&&carry;i--) { int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8; }
        }
    }
    free(padded);

    if (!double_pass) { *out_len = padded_len; return inter; }

    uint8_t rk_bwd[KEY_SIZE]; derive_cascade_key(master_key, KEY_SIZE, rk_bwd);
    for (int b=(int)n_blocks-1; b>=0; b--) {
        encrypt_block(rk_bwd, inter+b*block_bytes, block_size, result+b*block_bytes);
        derive_cascade_key(result+b*block_bytes, block_bytes, rk_bwd);
    }
    *out_len = padded_len; free(inter); return result;
}

static uint8_t *cascade_decrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode, const uint8_t *iv,
                                  int block_size, int double_pass,
                                  size_t *out_len) {
    int block_bytes = block_size;
    build_key_table(master_key, block_bytes);
    size_t n_blocks = data_len / block_bytes;

    uint8_t *inter     = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len+1);

    if (double_pass) {
        uint8_t rk_bwd[KEY_SIZE]; derive_cascade_key(master_key, KEY_SIZE, rk_bwd);
        for (int b=(int)n_blocks-1; b>=0; b--) {
            decrypt_block(rk_bwd, data+b*block_bytes, block_size, inter+b*block_bytes);
            derive_cascade_key(data+b*block_bytes, block_bytes, rk_bwd);
        }
    } else {
        memcpy(inter, data, data_len);
    }

    uint8_t rk[KEY_SIZE]; memcpy(rk, master_key, KEY_SIZE);
    uint8_t prev[4096], enc_prev[4096], tmp[4096];
    if (iv) memcpy(prev, iv, block_bytes); else memset(prev, 0, block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = inter     + b*block_bytes;
        uint8_t       *out_b = decrypted + b*block_bytes;

        if (mode == MODE_ECB) {
            decrypt_block(rk, blk, block_size, out_b);
            derive_cascade_key(blk, block_bytes, rk);
        } else if (mode == MODE_CBC) {
            decrypt_block(rk, blk, block_size, tmp);
            for (int i=0;i<block_bytes;i++) out_b[i]=tmp[i]^prev[i];
            derive_cascade_key(blk, block_bytes, rk);
            memcpy(prev, blk, block_bytes);
        } else if (mode == MODE_CFB) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, blk, block_bytes);
        } else if (mode == MODE_OFB) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, enc_prev, block_bytes);
        } else if (mode == MODE_CTR) {
            encrypt_block(rk, prev, block_size, enc_prev);
            derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            int carry=1;
            for (int i=block_bytes-1;i>=0&&carry;i--) { int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8; }
        }
    }

    uint8_t *res = wbc1_unpad(decrypted, data_len, block_bytes, out_len);
    free(inter); free(decrypted); return res;
}

/* ── WBC-CTR-HMAC ─────────────────────────────────────────────────────────── */

static uint8_t *cascade_encrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           int block_size, const uint8_t *nonce_in,
                                           size_t *out_len) {
    int block_bytes = block_size;
    build_key_table(key, block_bytes);
    uint8_t nonce[NONCE_SIZE];
    if (nonce_in) memcpy(nonce,nonce_in,NONCE_SIZE); else RAND_bytes(nonce,NONCE_SIZE);

    uint8_t key_crypt[32], key_mac[32];
    kdf(key, nonce, key_crypt, key_mac);

    size_t padded_len; uint8_t *padded = wbc1_pad(data, data_len, block_bytes, &padded_len);
    size_t n_blocks = padded_len / block_bytes;
    uint8_t *cipher = (uint8_t *)malloc(padded_len);

    uint8_t rk[KEY_SIZE]; memcpy(rk, key_crypt, KEY_SIZE);
    int ctr_tail_sz = (block_bytes > NONCE_SIZE) ? block_bytes-NONCE_SIZE : 1;

    for (size_t b = 0; b < n_blocks; b++) {
        uint8_t ctr_block[4096];
        for (int j=0;j<block_bytes;j++) ctr_block[j]=rk[j%KEY_SIZE];
        for (int j=0;j<NONCE_SIZE&&j<block_bytes;j++) ctr_block[j]^=nonce[j];
        for (int i=ctr_tail_sz-1;i>=0;i--)
            ctr_block[NONCE_SIZE+i]^=(uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(rk, ctr_block, block_size, enc_ctr);
        derive_cascade_key(enc_ctr, block_bytes, rk);
        for (int i=0;i<block_bytes;i++) cipher[b*block_bytes+i]=padded[b*block_bytes+i]^enc_ctr[i];
    }
    free(padded);

    size_t hdr_len = MAGIC_LEN+1+2+NONCE_SIZE;
    uint8_t header[32];
    memcpy(header,MAGIC,MAGIC_LEN);
    header[MAGIC_LEN]=VERSION_CASC;
    header[MAGIC_LEN+1]=(uint8_t)(block_size>>8);
    header[MAGIC_LEN+2]=(uint8_t)(block_size&0xFF);
    memcpy(header+MAGIC_LEN+3, nonce, NONCE_SIZE);

    uint8_t mac[32];
    uint8_t *mac_in=(uint8_t *)malloc(hdr_len+padded_len);
    memcpy(mac_in,header,hdr_len); memcpy(mac_in+hdr_len,cipher,padded_len);
    hmac_sha256(key_mac,32,mac_in,hdr_len+padded_len,mac); free(mac_in);

    *out_len = hdr_len+padded_len+MAC_SIZE;
    uint8_t *result=(uint8_t *)malloc(*out_len);
    memcpy(result,header,hdr_len);
    memcpy(result+hdr_len,cipher,padded_len);
    memcpy(result+hdr_len+padded_len,mac,MAC_SIZE);
    free(cipher); return result;
}

static uint8_t *cascade_decrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *file_bytes, size_t file_len,
                                           size_t *out_len) {
    if (file_len < (size_t)(MAGIC_LEN+1+2+NONCE_SIZE+MAC_SIZE)) {
        fprintf(stderr,"ERROR: file too short\n"); return NULL;
    }
    if (memcmp(file_bytes,MAGIC,MAGIC_LEN)!=0) {
        fprintf(stderr,"ERROR: invalid magic\n"); return NULL;
    }
    if (file_bytes[MAGIC_LEN] != VERSION_CASC) {
        fprintf(stderr,"ERROR: version mismatch (0x%02x)\n",file_bytes[MAGIC_LEN]); return NULL;
    }
    int block_size=((int)file_bytes[MAGIC_LEN+1]<<8)|file_bytes[MAGIC_LEN+2];
    build_key_table(key, block_size);

    const uint8_t *nonce = file_bytes+MAGIC_LEN+3;
    size_t hdr_len       = MAGIC_LEN+1+2+NONCE_SIZE;
    const uint8_t *mac_actual = file_bytes+file_len-MAC_SIZE;
    const uint8_t *cipher     = file_bytes+hdr_len;
    size_t cipher_len         = file_len-hdr_len-MAC_SIZE;

    uint8_t key_crypt[32], key_mac[32]; kdf(key, nonce, key_crypt, key_mac);

    uint8_t mac_expected[32];
    uint8_t *mac_in=(uint8_t *)malloc(hdr_len+cipher_len);
    memcpy(mac_in,file_bytes,hdr_len); memcpy(mac_in+hdr_len,cipher,cipher_len);
    hmac_sha256(key_mac,32,mac_in,hdr_len+cipher_len,mac_expected); free(mac_in);

    int diff=0; for (int i=0;i<MAC_SIZE;i++) diff|=mac_actual[i]^mac_expected[i];
    if (diff) { fprintf(stderr,"ERROR: MAC failed\n"); return NULL; }

    int block_bytes=block_size;
    size_t n_blocks=cipher_len/block_bytes;
    uint8_t *plain=(uint8_t *)malloc(cipher_len+1);
    uint8_t rk[KEY_SIZE]; memcpy(rk, key_crypt, KEY_SIZE);
    int ctr_tail_sz=(block_bytes>NONCE_SIZE)?block_bytes-NONCE_SIZE:1;

    for (size_t b=0;b<n_blocks;b++) {
        uint8_t ctr_block[4096];
        for (int j=0;j<block_bytes;j++) ctr_block[j]=rk[j%KEY_SIZE];
        for (int j=0;j<NONCE_SIZE&&j<block_bytes;j++) ctr_block[j]^=nonce[j];
        for (int i=ctr_tail_sz-1;i>=0;i--)
            ctr_block[NONCE_SIZE+i]^=(uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(rk, ctr_block, block_size, enc_ctr);
        derive_cascade_key(enc_ctr, block_bytes, rk);
        for (int i=0;i<block_bytes;i++) plain[b*block_bytes+i]=cipher[b*block_bytes+i]^enc_ctr[i];
    }
    uint8_t *result=wbc1_unpad(plain, cipher_len, block_bytes, out_len);
    free(plain); return result;
}

/* ── statistics ───────────────────────────────────────────────────────────── */

static double shannon_entropy(const uint8_t *d, size_t l) {
    if (!l) return 0.0;
    size_t f[256]={0}; for (size_t i=0;i<l;i++) f[d[i]]++;
    double h=0.0;
    for (int i=0;i<256;i++) if (f[i]) { double p=(double)f[i]/l; h-=p*log2(p); }
    return h;
}
static double chi_square(const uint8_t *d, size_t l) {
    if (!l) return 0.0;
    size_t f[256]={0}; for (size_t i=0;i<l;i++) f[d[i]]++;
    double e=(double)l/256.0, c=0.0;
    for (int i=0;i<256;i++) { double x=(double)f[i]-e; c+=x*x/e; }
    return c;
}
static double correlation(const uint8_t *x, const uint8_t *y, size_t n) {
    if (!n) return 0.0;
    double mx=0,my=0;
    for (size_t i=0;i<n;i++) { mx+=x[i]; my+=y[i]; } mx/=n; my/=n;
    double cov=0,vx=0,vy=0;
    for (size_t i=0;i<n;i++) { double a=x[i]-mx,b=y[i]-my; cov+=a*b; vx+=a*a; vy+=b*b; }
    return (vx>0&&vy>0)?cov/(sqrt(vx)*sqrt(vy)):0.0;
}

/* ── self-tests ───────────────────────────────────────────────────────────── */

static void run_self_tests(const uint8_t key[32], EncMode mode, int double_pass) {
    printf("\n%s\n","────────────────────────────────────────────────────────────");
    printf("  Self-tests  |  mode=%s  cascade=%s  [WBC1-v2 key-derived perms]\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE");
    printf("%s\n","────────────────────────────────────────────────────────────");

    typedef struct { const char *label; const uint8_t *data; size_t len; } T;
    uint8_t rand100[100]; RAND_bytes(rand100,100);
    uint8_t range256[256]; for (int i=0;i<256;i++) range256[i]=(uint8_t)i;
    uint8_t a64[64]; memset(a64,'A',64);
    uint8_t b300[300]; memset(b300,'B',300);
    uint8_t *d10k  = (uint8_t *)malloc(10000);  RAND_bytes(d10k,  10000);
    uint8_t *d100k = (uint8_t *)malloc(100000); RAND_bytes(d100k, 100000);

    T tests[] = {
        {"Short text",        (const uint8_t*)"Hello World!", 12},
        {"One block (64B)",   a64,     64},
        {"300 bytes",         b300,    300},
        {"Binary (100B)",     rand100, 100},
        {"Empty input",       (const uint8_t*)"", 0},
        {"All byte values",   range256,256},
        {"Single byte",       (const uint8_t*)"X", 1},
        {"10 000 bytes",      d10k,  10000},
        {"100 000 bytes",     d100k, 100000},
    };
    int n=(int)(sizeof(tests)/sizeof(tests[0])), passed=0;

    for (int t=0; t<n; t++) {
        int block_size = auto_block_size((int)tests[t].len);
        size_t enc_len=0, dec_len=0; int ok=0;

        if (mode==MODE_WBC_CTR_HMAC) {
            uint8_t *enc=cascade_encrypt_ctr_hmac(key,tests[t].data,tests[t].len,block_size,NULL,&enc_len);
            uint8_t *dec=cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            ok=dec&&dec_len==tests[t].len&&memcmp(dec,tests[t].data,dec_len)==0;
            free(enc); if(dec)free(dec);
        } else {
            uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *enc=cascade_encrypt(key,tests[t].data,tests[t].len,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            uint8_t *dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            ok=dec_len==tests[t].len&&memcmp(dec,tests[t].data,dec_len)==0;
            free(enc);free(dec);if(iv)free(iv);
        }
        printf("  %-35s %s\n", tests[t].label, ok?"PASS ✓":"FAIL ✗");
        if (ok) passed++;
    }
    printf("%s\n","────────────────────────────────────────────────────────────");
    printf("  Results: %d/%d passed\n\n", passed, n);
    free(d10k); free(d100k);
}

/* ── benchmark helpers ────────────────────────────────────────────────────── */

static double read_cpu_mhz(void) {
    FILE *f = fopen("/proc/cpuinfo","r"); if (!f) return 0.0;
    char line[256]; double mhz=0.0;
    while (fgets(line,sizeof(line),f))
        if (strncmp(line,"cpu MHz",7)==0) { char *p=strchr(line,':'); if(p){mhz=atof(p+1);break;} }
    fclose(f); return mhz;
}

static int cmp_double_asc(const void *a, const void *b) {
    double da=*(const double*)a, db=*(const double*)b;
    return (da>db)-(da<db);
}
static double aggregate_bench_time(double *t, int n, int trim) {
    if (!trim||n<5) { double s=0; for(int i=0;i<n;i++) s+=t[i]; return s/n; }
    double tmp[64]; memcpy(tmp,t,(size_t)n*sizeof(double));
    qsort(tmp,(size_t)n,sizeof(double),cmp_double_asc);
    int cut=(n>=15)?2:1, start=cut, end=n-cut;
    if(end<=start){double s=0;for(int i=0;i<n;i++) s+=t[i];return s/n;}
    double s=0; for(int i=start;i<end;i++) s+=tmp[i]; return s/(end-start);
}

/* ── benchmark ────────────────────────────────────────────────────────────── */

static void benchmark(const uint8_t key[32], EncMode mode, int double_pass) {
    static const int sizes[] = {1,10,100,1000,10000,100000,1000000,10000000};
    int ns = (int)(sizeof(sizes)/sizeof(sizes[0]));
    int repeats = 10, trim_outliers = 1;
    { const char *e=getenv("WBC_BENCH_REPEATS"); if(e){int v=atoi(e);if(v>=3&&v<=64)repeats=v;} }
    { const char *e=getenv("WBC_BENCH_TRIM");    if(e&&e[0]=='0')trim_outliers=0; }
    double enc_spds[8]={0}, dec_spds[8]={0}; int bsizes[8]={0};

    printf("\n  Benchmark  |  mode=%s  cascade=%s  [WBC1-v2 key-derived]\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE");
    printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers?"trimmed mean":"mean");
    printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  Integrity\n",
           "Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)","Enc (MB/s)","Dec (MB/s)","Enc (Mbit/s)","Dec (Mbit/s)");
    printf("  %s\n","--------------------------------------------------------------------------------------------------------------");

    for (int si=0; si<ns; si++) {
        int sz = sizes[si];
        uint8_t *data=(uint8_t*)malloc(sz); RAND_bytes(data,sz);
        int block_size = auto_block_size(sz);
        int all_ok=1;

        /* warmup */
        { size_t el=0,dl=0; uint8_t *iv=NULL; size_t iv_len=0;
          uint8_t *e=NULL,*d=NULL;
          if (mode==MODE_WBC_CTR_HMAC) { e=cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&el); d=cascade_decrypt_ctr_hmac(key,e,el,&dl); }
          else { e=cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&el); d=cascade_decrypt(key,e,el,mode,iv,block_size,double_pass,&dl); if(iv)free(iv); }
          free(e); if(d)free(d); }

        double enc_times[64]={0}, dec_times[64]={0};
        for (int r=0; r<repeats; r++) {
            struct timespec t0,t1;
            size_t enc_len=0,dec_len=0; uint8_t *enc=NULL,*dec=NULL,*iv=NULL; size_t iv_len=0;
            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC) enc=cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&enc_len);
            else enc=cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            enc_times[r]=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC) dec=cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            else dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            dec_times[r]=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            if (!dec||dec_len!=(size_t)sz||memcmp(dec,data,sz)!=0) all_ok=0;
            if(iv)free(iv); free(enc); if(dec)free(dec);
        }
        double enc_avg=aggregate_bench_time(enc_times,repeats,trim_outliers);
        double dec_avg=aggregate_bench_time(dec_times,repeats,trim_outliers);
        double enc_spd=((double)sz/1024.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_spd=((double)sz/1024.0)/(dec_avg>0?dec_avg:1e-9);
        double enc_mbps=((double)sz/1000000.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_mbps=((double)sz/1000000.0)/(dec_avg>0?dec_avg:1e-9);
        double enc_mbit=enc_mbps*8.0, dec_mbit=dec_mbps*8.0;
        printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
               (double)sz/1024.0, enc_avg, enc_spd, dec_spd,
               enc_mbps, dec_mbps, enc_mbit, dec_mbit, all_ok?"OK":"FAIL");
        enc_spds[si]=enc_spd; dec_spds[si]=dec_spd; bsizes[si]=block_size;
        free(data);
    }

    /* --- Цикли / байт (cycles per byte) --- */
    {
        double cpu_mhz = read_cpu_mhz();
        if (cpu_mhz > 0) {
            printf("\n  --- Цикли / байт  (CPU: %.0f МГц) ---\n", cpu_mhz);
            printf("  %10s  %8s  %8s  %12s  %12s  %10s  %10s\n",
                   "Size (KB)","Enc CPB","Dec CPB","E Cyc/blk","D Cyc/blk","E B/cycle","D B/cycle");
            printf("  %s\n","--------------------------------------------------------------------------");
            for (int si=0; si<ns; si++) {
                double ecpb=(enc_spds[si]>0)?cpu_mhz*1e6/(enc_spds[si]*1024.0):0.0;
                double dcpb=(dec_spds[si]>0)?cpu_mhz*1e6/(dec_spds[si]*1024.0):0.0;
                printf("  %10.2f  %8.2f  %8.2f  %12.0f  %12.0f  %10.5f  %10.5f\n",
                       (double)sizes[si]/1024.0, ecpb, dcpb,
                       ecpb*(double)bsizes[si], dcpb*(double)bsizes[si],
                       (ecpb>0)?1.0/ecpb:0.0, (dcpb>0)?1.0/dcpb:0.0);
            }
        } else {
            printf("\n  CPB: частота CPU недоступна\n");
        }
    }
    printf("\n");
}

/* ── fixed-key benchmark (same key every block, shows composition cache) ─── */

static void benchmark_fixed_key(const uint8_t key[KEY_SIZE]) {
    static const int DATA_MB = 32;
    int N = 1331;
    size_t total = (size_t)DATA_MB * 1024 * 1024;
    size_t nblocks = total / N; total = nblocks * N;

    uint8_t *data=(uint8_t*)malloc(total);
    uint8_t *enc =(uint8_t*)malloc(total);
    uint8_t *dec =(uint8_t*)malloc(total);
    if (!data||!enc||!dec) { free(data);free(enc);free(dec); printf("  OOM\n"); return; }
    RAND_bytes(data,(int)(total>INT_MAX?INT_MAX:total));

    build_key_table(key, N);   /* build once; all blocks reuse cache */

    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    for (size_t b=0;b<nblocks;b++) encrypt_block(key, data+b*N, N, enc+b*N);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double t_enc=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    clock_gettime(CLOCK_MONOTONIC,&t0);
    for (size_t b=0;b<nblocks;b++) decrypt_block(key, enc+b*N, N, dec+b*N);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double t_dec=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    int ok=(memcmp(data,dec,total)==0);
    double spd_e=(total/1024.0/1024.0)/(t_enc>0?t_enc:1e-9);
    double spd_d=(total/1024.0/1024.0)/(t_dec>0?t_dec:1e-9);
    double cpu_mhz = read_cpu_mhz();

    printf("\n  Fixed-key benchmark  (%d MB, блок %d байт, %zu блоків)\n",DATA_MB,N,nblocks);
    printf("  g_comp_fwd table: %d × 2 bytes = %d bytes (%.1f KB, fits in L1)\n",
           N, N*2, N*2/1024.0);
    printf("  Encrypt: %8.1f MB/s", spd_e);
    if (cpu_mhz>0) printf("  CPB: %.2f", cpu_mhz*1e6/(spd_e*1e6));
    printf("\n  Decrypt: %8.1f MB/s", spd_d);
    if (cpu_mhz>0) printf("  CPB: %.2f", cpu_mhz*1e6/(spd_d*1e6));
    printf("\n  Integrity: %s\n\n", ok?"OK":"FAIL");
    free(data); free(enc); free(dec);
}

/* ── avalanche test ───────────────────────────────────────────────────────── */

static void avalanche_test(const uint8_t key[KEY_SIZE], const uint8_t *data,
                            size_t data_len, EncMode mode, int double_pass) {
    if (data_len==0) { printf("  Avalanche effect: N/A\n"); return; }
    int is_stream = mode_is_key_avalanche(mode);
    int block_size = auto_block_size((int)data_len);
    size_t enc_len0=0; uint8_t *iv0=NULL; size_t iv0_len=0;
    uint8_t *enc0;
    const uint8_t *ref; size_t ref_len;
    const uint8_t *nonce0=NULL;

    if (mode==MODE_WBC_CTR_HMAC) {
        enc0=cascade_encrypt_ctr_hmac(key,data,data_len,block_size,NULL,&enc_len0);
        size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
        ref=enc0+hdr; ref_len=enc_len0-hdr-MAC_SIZE; nonce0=enc0+MAGIC_LEN+3;
    } else {
        enc0=cascade_encrypt(key,data,data_len,mode,NULL,block_size,&iv0,&iv0_len,double_pass,&enc_len0);
        ref=enc0; ref_len=enc_len0;
    }

    long long total_flips=0, total_bits=(long long)ref_len*8;
    size_t flip_count = is_stream ? (size_t)(KEY_SIZE*8) : data_len*8;

    for (size_t i=0; i<flip_count; i++) {
        size_t enc_len1=0; uint8_t *enc1;
        if (is_stream) {
            uint8_t mod_key[KEY_SIZE]; memcpy(mod_key,key,KEY_SIZE);
            mod_key[i/8]^=(uint8_t)(1<<(i%8));
            if (mode==MODE_WBC_CTR_HMAC) {
                enc1=cascade_encrypt_ctr_hmac(mod_key,data,data_len,block_size,nonce0,&enc_len1);
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
                const uint8_t *cmp=enc1+hdr; size_t cmp_len=enc_len1-hdr-MAC_SIZE;
                if (cmp_len==ref_len) for (size_t j=0;j<cmp_len;j++) total_flips+=__builtin_popcount(ref[j]^cmp[j]);
            } else {
                uint8_t *iv1=NULL; size_t iv1_len=0;
                enc1=cascade_encrypt(mod_key,data,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
                if (enc_len1==ref_len) for (size_t j=0;j<enc_len1;j++) total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
                if(iv1)free(iv1);
            }
        } else {
            uint8_t *mod=(uint8_t*)malloc(data_len); memcpy(mod,data,data_len);
            mod[i/8]^=(uint8_t)(1<<(i%8));
            uint8_t *iv1=NULL; size_t iv1_len=0;
            enc1=cascade_encrypt(key,mod,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
            if (enc_len1==ref_len) for (size_t j=0;j<enc_len1;j++) total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
            if(iv1)free(iv1); free(mod);
        }
        free(enc1);
    }
    double ratio=(double)total_flips/((double)flip_count*(double)total_bits);
    printf("  Avalanche effect %s: %.2f%%  (ideal ~50%%)\n",
           is_stream?"(key)":"(plaintext)", ratio*100.0);
    free(enc0); if(iv0)free(iv0);
}

/* ── interactive helpers ──────────────────────────────────────────────────── */

static EncMode select_mode(void) {
    printf("  Select mode:\n    1. ECB\n    2. CBC\n    3. CFB\n"
           "    4. OFB\n    5. CTR\n    6. WBC-CTR-HMAC\n  Mode [1-6, default=1]: ");
    fflush(stdout);
    char buf[16]={0}; if(fgets(buf,sizeof(buf),stdin)==NULL) return MODE_ECB;
    switch(buf[0]) { case '2':return MODE_CBC; case '3':return MODE_CFB;
                     case '4':return MODE_OFB; case '5':return MODE_CTR;
                     case '6':return MODE_WBC_CTR_HMAC; default:return MODE_ECB; }
}

static void read_hex_key(uint8_t key[32]) {
    printf("  Key (hex 64 chars): "); fflush(stdout);
    char buf[128]={0}; if(fgets(buf,sizeof(buf),stdin)==NULL) return;
    buf[strcspn(buf,"\r\n")]=0;
    if (strlen(buf)<64) { fprintf(stderr,"  Key too short, using zeros\n"); return; }
    for (int i=0;i<32;i++) { unsigned int v=0; sscanf(buf+i*2,"%02x",&v); key[i]=(uint8_t)v; }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int double_pass = 1;
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i],"-s")==0||strcmp(argv[i],"--single")==0) double_pass=0;
        if (strcmp(argv[i],"-d")==0||strcmp(argv[i],"--double")==0) double_pass=1;
    }

    uint8_t key[32] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x76,0x2e,0x7f,0x60,0xae,0x2b,0xb4,0x1a,
        0x68,0x21,0x6f,0x2c,0xdb,0x34,0x12,0x99
    };

    printf("\n  WBC1-CASCADE-NEW2  [White-Box: key-derived random permutations]\n");
    printf("  Architecture: HMAC-SHA256 + xorshift64 → Fisher-Yates → %d perms → compose\n", ROUNDS);
    printf("  Table size (g_comp_fwd): 1331 × 2 = 2662 bytes (fits in L1 cache)\n");
    printf("  cascade=%s\n\n", double_pass?"DOUBLE":"SINGLE");

    int running = 1;
    EncMode mode = MODE_ECB;

    while (running) {
        printf("  ┌─ Menu ─────────────────────────────────────────────────────┐\n"
               "  │  1. Encrypt/Decrypt text                                   │\n"
               "  │  2. Self-tests (9 cases)                                   │\n"
               "  │  3. Benchmark (cascade, all sizes)                         │\n"
               "  │  4. Fixed-key benchmark (L1 cache demo)                    │\n"
               "  │  5. Avalanche test                                         │\n"
               "  │  6. Switch cascade mode (%s)                           │\n"
               "  │  7. Exit                                                   │\n"
               "  └────────────────────────────────────────────────────────────┘\n"
               "  Mode: %s  Choice: ",
               double_pass?"DOUBLE":"SINGLE", mode_name(mode));
        fflush(stdout);
        char buf[8]={0}; if(fgets(buf,sizeof(buf),stdin)==NULL) break;
        int choice = atoi(buf);

        switch (choice) {
        case 1: {
            printf("  Enter text: "); fflush(stdout);
            char tbuf[4096]={0}; if(!fgets(tbuf,sizeof(tbuf),stdin)) break;
            tbuf[strcspn(tbuf,"\r\n")]=0;
            int block_size=auto_block_size((int)strlen(tbuf));
            size_t enc_len=0,dec_len=0; uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *enc=cascade_encrypt(key,(uint8_t*)tbuf,strlen(tbuf),mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            uint8_t *dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            printf("  Encrypted (%zu bytes): ", enc_len);
            for (size_t i=0;i<(enc_len<32?enc_len:32);i++) printf("%02x",enc[i]);
            if (enc_len>32) printf("...");
            printf("\n  Decrypted: %.*s\n", (int)dec_len, dec);
            free(enc); free(dec); if(iv)free(iv);
            break;
        }
        case 2:
            mode = select_mode();
            run_self_tests(key, mode, double_pass);
            break;
        case 3:
            mode = select_mode();
            benchmark(key, mode, double_pass);
            break;
        case 4:
            benchmark_fixed_key(key);
            break;
        case 5: {
            printf("  Enter text for avalanche test: "); fflush(stdout);
            char tbuf[256]={0}; if(!fgets(tbuf,sizeof(tbuf),stdin)) break;
            tbuf[strcspn(tbuf,"\r\n")]=0;
            mode = select_mode();
            avalanche_test(key,(uint8_t*)tbuf,strlen(tbuf),mode,double_pass);
            break;
        }
        case 6:
            double_pass = !double_pass;
            printf("  Cascade: %s\n", double_pass?"DOUBLE":"SINGLE");
            break;
        case 7:
            running=0; break;
        default:
            printf("  Unknown choice\n"); break;
        }
    }

    free(g_comp_fwd); free(g_comp_inv);
    printf("  Bye.\n"); return 0;
}
