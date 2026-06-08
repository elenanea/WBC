/*
 * WBC2 Sequential Block Cipher
 *
 * Sequential (non-MPI) version of wbc1_parallel_cached.c.
 * Mirrors the Python implementation in "хорошая лавина WBC2.py".
 *
 * Key properties:
 *   - Block size  : 16 bytes (fixed)
 *   - Key size    : 32 bytes (256 bit)
 *   - Rounds      : 32 (FULL mode: 5 operations per round)
 *   - Operations  : 127 dynamic Rubik's-cube-inspired permutations
 *                   (pre-computed and cached at init time)
 *   - Per-round   : perm → XOR(round_key) → S-box → cumulative-XOR → rotate-right
 *
 * To build standalone (test mode):
 *   gcc -O2 -o wbc2_serial wbc2_serial.c -lm -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define WBC2_BLOCK_SIZE    16
#define WBC2_KEY_SIZE      32
#define WBC2_NUM_ROUNDS    32
#define WBC2_NUM_OPERATIONS 127
#define WBC2_MAX_OP_STR    256

/* ── Mersenne Twister MT19937 ─────────────────────────────────────────────── */
#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A   0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

typedef struct { uint32_t mt[MT_N]; int mti; } MT19937State;

static void mt_init(MT19937State *s, uint32_t seed) {
    s->mt[0] = seed & 0xffffffffUL;
    for (s->mti = 1; s->mti < MT_N; s->mti++) {
        s->mt[s->mti] = (1812433253UL *
            (s->mt[s->mti-1] ^ (s->mt[s->mti-1] >> 30)) + s->mti)
            & 0xffffffffUL;
    }
}

static uint32_t mt_random(MT19937State *s) {
    static const uint32_t mag01[2] = {0x0UL, MT_MATRIX_A};
    uint32_t y;
    if (s->mti >= MT_N) {
        int kk;
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (s->mt[kk] & MT_UPPER_MASK) | (s->mt[kk+1] & MT_LOWER_MASK);
            s->mt[kk] = s->mt[kk+MT_M] ^ (y >> 1) ^ mag01[y & 1];
        }
        for (; kk < MT_N-1; kk++) {
            y = (s->mt[kk] & MT_UPPER_MASK) | (s->mt[kk+1] & MT_LOWER_MASK);
            s->mt[kk] = s->mt[kk+(MT_M-MT_N)] ^ (y >> 1) ^ mag01[y & 1];
        }
        y = (s->mt[MT_N-1] & MT_UPPER_MASK) | (s->mt[0] & MT_LOWER_MASK);
        s->mt[MT_N-1] = s->mt[MT_M-1] ^ (y >> 1) ^ mag01[y & 1];
        s->mti = 0;
    }
    y = s->mt[s->mti++];
    y ^= (y >> 11);
    y ^= (y <<  7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return y;
}

/* Second MT state used during init_operations (matches numpy RandomState) */
typedef struct { uint32_t mt[624]; int index; } MT19937InitState;

static void mt_init_seed(MT19937InitState *s, uint32_t seed) {
    s->mt[0] = seed;
    for (int i = 1; i < 624; i++)
        s->mt[i] = 1812433253UL * (s->mt[i-1] ^ (s->mt[i-1] >> 30)) + i;
    s->index = 624;
}

static void mt_generate_init(MT19937InitState *s) {
    for (int i = 0; i < 624; i++) {
        uint32_t y = (s->mt[i] & 0x80000000UL) + (s->mt[(i+1)%624] & 0x7FFFFFFFUL);
        s->mt[i] = s->mt[(i+397)%624] ^ (y >> 1);
        if (y & 1) s->mt[i] ^= 0x9908B0DFUL;
    }
    s->index = 0;
}

static uint32_t mt_random_init(MT19937InitState *s) {
    if (s->index >= 624) mt_generate_init(s);
    uint32_t y = s->mt[s->index++];
    y ^= y >> 11;
    y ^= (y <<  7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= y >> 18;
    return y;
}

/* ── SHA-256 wrapper ─────────────────────────────────────────────────────── */
static void wbc2_sha256(const uint8_t *data, size_t len, uint8_t *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* ── byte-level utilities ─────────────────────────────────────────────────── */
static uint8_t wbc2_rotate_right(uint8_t b, int n) {
    n &= 7;
    return (uint8_t)((b >> n) | (b << (8 - n)));
}

/* ── Operations ──────────────────────────────────────────────────────────── */
typedef struct {
    char type[32];
    char param1[64];
    char param2[64];
    char desc[128];
    char str_repr[WBC2_MAX_OP_STR];
    int  chain_length;
    int  chain[8];
} WBC2Operation;

typedef struct {
    int forward_perm[WBC2_BLOCK_SIZE];
    int inverse_perm[WBC2_BLOCK_SIZE];
} WBC2OpCache;

/* file-scope globals (initialised once per process with the first key used) */
static WBC2Operation wbc2_g_ops[WBC2_NUM_OPERATIONS];
static WBC2Operation wbc2_g_base_ops[300];
static int           wbc2_g_base_ops_count = 0;
static int           wbc2_g_ops_init = 0;

/* ── Cipher structure ─────────────────────────────────────────────────────── */
typedef struct {
    uint8_t     sbox[256];
    uint8_t     inv_sbox[256];
    uint8_t     round_keys[WBC2_NUM_ROUNDS][WBC2_BLOCK_SIZE];
    uint8_t    *key;
    int         key_len;
    WBC2OpCache *cache;          /* per-cipher, malloc'd */
    int          cache_size;
} WBC2Cipher;

/* ── init_operations ────────────────────────────────────────────────────── */
static void wbc2_init_operations(const uint8_t *key, int key_len) {
    if (wbc2_g_ops_init) return;
    WBC2Operation *tmp = wbc2_g_base_ops;
    int idx = 0;

    const char *faces[]      = {"U","D","L","R","F","B"};
    const char *dirs[]       = {"","'","2","3"};
    const char *slices[]     = {"M","E","S"};
    const char *wide_moves[] = {"u","d","l","r","f","b"};
    const char *cube_rot[]   = {"x","y","z"};

    /* face moves: 6×4 = 24 */
    for (int f = 0; f < 6; f++) for (int d = 0; d < 4; d++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "face");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%s",faces[f]);
        snprintf(tmp[idx].param2,sizeof(tmp[idx].param2),"%s",dirs[d]);
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Rotate %s face %s",faces[f],dirs[d]);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('face', '%s', '%s', 'Rotate %s face %s')",faces[f],dirs[d],faces[f],dirs[d]);
        tmp[idx].chain_length = 0; idx++;
    }
    /* slice moves: 3×4 = 12 */
    for (int s = 0; s < 3; s++) for (int d = 0; d < 4; d++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "slice");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%s",slices[s]);
        snprintf(tmp[idx].param2,sizeof(tmp[idx].param2),"%s",dirs[d]);
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Rotate %s slice %s",slices[s],dirs[d]);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('slice', '%s', '%s', 'Rotate %s slice %s')",slices[s],dirs[d],slices[s],dirs[d]);
        tmp[idx].chain_length = 0; idx++;
    }
    /* wide moves: 6×4 = 24 */
    for (int w = 0; w < 6; w++) for (int d = 0; d < 4; d++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "wide");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%s",wide_moves[w]);
        snprintf(tmp[idx].param2,sizeof(tmp[idx].param2),"%s",dirs[d]);
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Wide move %s%s",wide_moves[w],dirs[d]);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('wide', '%s', '%s', 'Wide move %s%s')",wide_moves[w],dirs[d],wide_moves[w],dirs[d]);
        tmp[idx].chain_length = 0; idx++;
    }
    /* cube rotations: 3×4 = 12 */
    for (int r = 0; r < 3; r++) for (int d = 0; d < 4; d++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "cube");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%s",cube_rot[r]);
        snprintf(tmp[idx].param2,sizeof(tmp[idx].param2),"%s",dirs[d]);
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Cube rotation %s%s",cube_rot[r],dirs[d]);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('cube', '%s', '%s', 'Cube rotation %s%s')",cube_rot[r],dirs[d],cube_rot[r],dirs[d]);
        tmp[idx].chain_length = 0; idx++;
    }
    /* swap ops: 3×4 = 12 */
    for (int axis = 0; axis < 3; axis++) for (int k = 0; k < 4; k++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "swap");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%d",axis);
        snprintf(tmp[idx].param2,sizeof(tmp[idx].param2),"%d",k);
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Swap axis=%d, offset=%d",axis,k);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('swap', %d, %d, 'Swap axis=%d, offset=%d')",axis,k,axis,k);
        tmp[idx].chain_length = 0; idx++;
    }
    /* diagflip: 3 */
    for (int axis = 0; axis < 3; axis++) {
        snprintf(tmp[idx].type,  sizeof(tmp[idx].type),  "diagflip");
        snprintf(tmp[idx].param1,sizeof(tmp[idx].param1),"%d",axis);
        tmp[idx].param2[0] = '\0';
        snprintf(tmp[idx].desc,  sizeof(tmp[idx].desc),  "Diagonal flip axis=%d",axis);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('diagflip', %d, '', 'Diagonal flip axis=%d')",axis,axis);
        tmp[idx].chain_length = 0; idx++;
    }
    int static_count = idx;  /* 87 */

    /* 20 key-dependent dynamic ops built from static pool */
    for (int i = 0; i < 20; i++) {
        uint8_t seed_in[256];
        memcpy(seed_in, key, (size_t)key_len);
        seed_in[key_len]   = (uint8_t)(i & 0xFF);
        seed_in[key_len+1] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        wbc2_sha256(seed_in, (size_t)(key_len + 2), hash);
        uint32_t seed = ((uint32_t)hash[0]<<24)|((uint32_t)hash[1]<<16)|
                        ((uint32_t)hash[2]<< 8)|((uint32_t)hash[3]);
        MT19937InitState rng; mt_init_seed(&rng, seed);
        int n_ops = 4 + (int)(mt_random_init(&rng) % 4);

        snprintf(tmp[idx].type,   sizeof(tmp[idx].type),   "dynamic");
        snprintf(tmp[idx].param1, sizeof(tmp[idx].param1), "%d", i);
        snprintf(tmp[idx].param2, sizeof(tmp[idx].param2), "ops");
        snprintf(tmp[idx].desc,   sizeof(tmp[idx].desc),   "Dynamic pattern %d", i);
        snprintf(tmp[idx].str_repr,sizeof(tmp[idx].str_repr),
            "('dynamic', %d, 'ops', 'Dynamic pattern %d')", i, i);
        tmp[idx].chain_length = n_ops;
        for (int j = 0; j < n_ops; j++)
            tmp[idx].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)static_count);
        idx++;
    }
    wbc2_g_base_ops_count = idx;  /* 107 */

    /* Generate 127 final chain operations */
    for (int i = 0; i < WBC2_NUM_OPERATIONS; i++) {
        for (int attempt = 0; attempt < 1000; attempt++) {
            uint8_t seed_in[256];
            memcpy(seed_in, key, (size_t)key_len);
            memcpy(seed_in + key_len, "WBC1_OP", 7);
            seed_in[key_len+7]  = (uint8_t)(i & 0xFF);
            seed_in[key_len+8]  = (uint8_t)((i >> 8) & 0xFF);
            seed_in[key_len+9]  = (uint8_t)(attempt & 0xFF);
            seed_in[key_len+10] = (uint8_t)((attempt >> 8) & 0xFF);
            uint8_t hash[SHA256_DIGEST_LENGTH];
            wbc2_sha256(seed_in, (size_t)(key_len + 11), hash);
            uint32_t seed = ((uint32_t)hash[0]<<24)|((uint32_t)hash[1]<<16)|
                            ((uint32_t)hash[2]<< 8)|((uint32_t)hash[3]);
            MT19937InitState rng; mt_init_seed(&rng, seed);
            int chain_len = 3 + (int)(mt_random_init(&rng) % 4);

            snprintf(wbc2_g_ops[i].type,   sizeof(wbc2_g_ops[i].type),   "dynamic");
            snprintf(wbc2_g_ops[i].param1, sizeof(wbc2_g_ops[i].param1), "%d", i);
            snprintf(wbc2_g_ops[i].param2, sizeof(wbc2_g_ops[i].param2), "chain");
            snprintf(wbc2_g_ops[i].desc,   sizeof(wbc2_g_ops[i].desc),   "Dynamic ASCII op %d", i+1);
            snprintf(wbc2_g_ops[i].str_repr,sizeof(wbc2_g_ops[i].str_repr),
                "('dynamic', %d, 'chain', 'Dynamic ASCII op %d')", i, i+1);
            wbc2_g_ops[i].chain_length = chain_len;
            for (int j = 0; j < chain_len; j++)
                wbc2_g_ops[i].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)wbc2_g_base_ops_count);
            break; /* use first attempt (uniqueness not strictly required) */
            (void)attempt;
        }
    }
    wbc2_g_ops_init = 1;
}

/* ── S-box generation ─────────────────────────────────────────────────────── */
static void wbc2_gen_sbox(WBC2Cipher *c) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    wbc2_sha256(c->key, (size_t)c->key_len, hash);
    uint32_t seed = ((uint32_t)hash[0]<<24)|((uint32_t)hash[1]<<16)|
                    ((uint32_t)hash[2]<< 8)|((uint32_t)hash[3]);
    for (int i = 0; i < 256; i++) c->sbox[i] = (uint8_t)i;
    MT19937State mt; mt_init(&mt, seed);
    for (int i = 255; i > 0; i--) {
        int j = (int)(mt_random(&mt) % (uint32_t)(i + 1));
        uint8_t t = c->sbox[i]; c->sbox[i] = c->sbox[j]; c->sbox[j] = t;
    }
    for (int i = 0; i < 256; i++) c->inv_sbox[c->sbox[i]] = (uint8_t)i;
}

/* ── Round key generation ─────────────────────────────────────────────────── */
static void wbc2_gen_round_keys(WBC2Cipher *c) {
    for (int r = 0; r < WBC2_NUM_ROUNDS; r++) {
        uint8_t in[WBC2_KEY_SIZE + 4];
        memcpy(in, c->key, (size_t)c->key_len);
        in[c->key_len]   = (uint8_t)((r >> 24) & 0xFF);
        in[c->key_len+1] = (uint8_t)((r >> 16) & 0xFF);
        in[c->key_len+2] = (uint8_t)((r >>  8) & 0xFF);
        in[c->key_len+3] = (uint8_t)( r         & 0xFF);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        wbc2_sha256(in, (size_t)(c->key_len + 4), hash);
        memcpy(c->round_keys[r], hash, WBC2_BLOCK_SIZE);
    }
}

/* ── Operation cache ──────────────────────────────────────────────────────── */
static void wbc2_precompute_cache(WBC2Cipher *c) {
    c->cache_size = wbc2_g_base_ops_count;
    c->cache = (WBC2OpCache *)malloc((size_t)c->cache_size * sizeof(WBC2OpCache));
    for (int i = 0; i < c->cache_size; i++) {
        WBC2Operation *op = &wbc2_g_base_ops[i];
        uint8_t in[WBC2_MAX_OP_STR + WBC2_KEY_SIZE];
        int slen = (int)strlen(op->str_repr);
        memcpy(in, op->str_repr, (size_t)slen);
        memcpy(in + slen, c->key, (size_t)c->key_len);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        wbc2_sha256(in, (size_t)(slen + c->key_len), hash);
        uint32_t seed = ((uint32_t)hash[0]<<24)|((uint32_t)hash[1]<<16)|
                        ((uint32_t)hash[2]<< 8)|((uint32_t)hash[3]);
        MT19937State mt; mt_init(&mt, seed);
        for (int j = 0; j < WBC2_BLOCK_SIZE; j++) c->cache[i].forward_perm[j] = j;
        for (int j = WBC2_BLOCK_SIZE-1; j > 0; j--) {
            int k = (int)(mt_random(&mt) % (uint32_t)(j + 1));
            int t = c->cache[i].forward_perm[j];
            c->cache[i].forward_perm[j] = c->cache[i].forward_perm[k];
            c->cache[i].forward_perm[k] = t;
        }
        for (int j = 0; j < WBC2_BLOCK_SIZE; j++)
            c->cache[i].inverse_perm[c->cache[i].forward_perm[j]] = j;
    }
}

/* ── Apply operation (cached) ─────────────────────────────────────────────── */
static void wbc2_apply_op(WBC2Cipher *c, uint8_t *block, int op_id, int inv) {
    uint8_t tmp[WBC2_BLOCK_SIZE];
    WBC2Operation *op = &wbc2_g_ops[op_id];
    int  start = inv ? (op->chain_length - 1) : 0;
    int  end   = inv ? -1                      : op->chain_length;
    int  step  = inv ? -1                      : 1;

    for (int ci = start; ci != end; ci += step) {
        int subop_idx = op->chain[ci];
        if (subop_idx < 0 || subop_idx >= wbc2_g_base_ops_count) continue;
        WBC2Operation *sub = &wbc2_g_base_ops[subop_idx];

        if (sub->chain_length > 0) {
            int ss = inv ? (sub->chain_length-1) : 0;
            int se = inv ? -1 : sub->chain_length;
            int sv = inv ? -1 : 1;
            for (int si = ss; si != se; si += sv) {
                int ni = sub->chain[si];
                if (ni < 0 || ni >= wbc2_g_base_ops_count) continue;
                memcpy(tmp, block, WBC2_BLOCK_SIZE);
                for (int j = 0; j < WBC2_BLOCK_SIZE; j++)
                    block[j] = tmp[inv ? c->cache[ni].inverse_perm[j]
                                      : c->cache[ni].forward_perm[j]];
            }
        } else {
            memcpy(tmp, block, WBC2_BLOCK_SIZE);
            for (int j = 0; j < WBC2_BLOCK_SIZE; j++)
                block[j] = tmp[inv ? c->cache[subop_idx].inverse_perm[j]
                                   : c->cache[subop_idx].forward_perm[j]];
        }
    }
}

/* ── Cipher init / free ───────────────────────────────────────────────────── */
void wbc2_init(WBC2Cipher *c, const uint8_t *key, int key_len) {
    wbc2_init_operations(key, key_len);
    c->key     = (uint8_t *)malloc((size_t)key_len);
    memcpy(c->key, key, (size_t)key_len);
    c->key_len = key_len;
    c->cache   = NULL;
    c->cache_size = 0;
    wbc2_gen_sbox(c);
    wbc2_gen_round_keys(c);
    wbc2_precompute_cache(c);
}

void wbc2_free(WBC2Cipher *c) {
    if (c->key)   { free(c->key);   c->key   = NULL; }
    if (c->cache) { free(c->cache); c->cache = NULL; }
}

/* ── Block encrypt / decrypt ─────────────────────────────────────────────── */
void wbc2_encrypt_block(WBC2Cipher *c, const uint8_t *pt, uint8_t *ct) {
    memcpy(ct, pt, WBC2_BLOCK_SIZE);
    for (int r = 0; r < WBC2_NUM_ROUNDS; r++) {
        int op_id = c->round_keys[r][0] % WBC2_NUM_OPERATIONS;
        wbc2_apply_op(c, ct, op_id, 0);
        /* XOR round key */
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++) ct[i] ^= c->round_keys[r][i];
        /* S-box */
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++) ct[i] = c->sbox[ct[i]];
        /* Cumulative XOR diffusion (forward) */
        for (int i = 1; i < WBC2_BLOCK_SIZE; i++) ct[i] ^= ct[i-1];
        /* Cyclic bitwise rotate right */
        int shift = c->round_keys[r][1] % 8;
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++) ct[i] = wbc2_rotate_right(ct[i], shift);
    }
}

void wbc2_decrypt_block(WBC2Cipher *c, const uint8_t *ct, uint8_t *pt) {
    memcpy(pt, ct, WBC2_BLOCK_SIZE);
    for (int r = WBC2_NUM_ROUNDS-1; r >= 0; r--) {
        /* Inverse rotate */
        int shift = c->round_keys[r][1] % 8;
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++)
            pt[i] = (uint8_t)((pt[i] << shift) | (pt[i] >> (8 - shift)));
        /* Inverse cumulative XOR (backward) */
        for (int i = WBC2_BLOCK_SIZE-1; i > 0; i--) pt[i] ^= pt[i-1];
        /* Inverse S-box */
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++) pt[i] = c->inv_sbox[pt[i]];
        /* XOR round key */
        for (int i = 0; i < WBC2_BLOCK_SIZE; i++) pt[i] ^= c->round_keys[r][i];
        int op_id = c->round_keys[r][0] % WBC2_NUM_OPERATIONS;
        wbc2_apply_op(c, pt, op_id, 1);
    }
}

/* ── PKCS7 padding ───────────────────────────────────────────────────────── */
static uint8_t *wbc2_pad(const uint8_t *data, size_t data_len, size_t *out_len) {
    int pad = WBC2_BLOCK_SIZE - (int)(data_len % WBC2_BLOCK_SIZE);
    if (pad == 0) pad = WBC2_BLOCK_SIZE;
    *out_len = data_len + (size_t)pad;
    uint8_t *buf = (uint8_t *)malloc(*out_len);
    memcpy(buf, data, data_len);
    memset(buf + data_len, pad, (size_t)pad);
    return buf;
}

static uint8_t *wbc2_unpad(const uint8_t *data, size_t data_len, size_t *out_len) {
    if (data_len == 0) { *out_len = 0; return NULL; }
    int pad = data[data_len - 1];
    if (pad <= 0 || pad > WBC2_BLOCK_SIZE) { pad = 0; }
    *out_len = data_len - (size_t)pad;
    uint8_t *buf = (uint8_t *)malloc(*out_len + 1);
    memcpy(buf, data, *out_len);
    return buf;
}

/* ── Benchmark ───────────────────────────────────────────────────────────── */
#include <time.h>
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void wbc2_benchmark(void) {
    static const int sizes_def[]  = {1,10,100,1000,10000,100000,1000000,10000000};
    static const int sizes_1gb[]  = {1,10,100,1000,10000,100000,1000000,10000000,1073741824};
    const int *sizes = sizes_def;
    int ns = (int)(sizeof(sizes_def)/sizeof(sizes_def[0]));
    int repeats = 10;
    int trim_outliers = 1;
    { const char *e = getenv("WBC_BENCH_REPEATS"); if (e) { int v=atoi(e); if(v>=3&&v<=64) repeats=v; } }
    { const char *e = getenv("WBC_BENCH_TRIM"); if (e && e[0]=='0') trim_outliers=0; }
    { const char *e = getenv("WBC_BENCH_1GB"); if (e && e[0]=='1') { sizes=sizes_1gb; ns=(int)(sizeof(sizes_1gb)/sizeof(sizes_1gb[0])); } }

    uint8_t key[WBC2_KEY_SIZE];
    for (int i = 0; i < WBC2_KEY_SIZE; i++) key[i] = (uint8_t)(i * 37 + 13);
    WBC2Cipher c;
    wbc2_init(&c, key, WBC2_KEY_SIZE);

    printf("\n  WBC2 Serial Benchmark\n");
    printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers ? "trimmed mean" : "mean");
    printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  Integrity\n",
           "Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)","Enc (MB/s)","Dec (MB/s)","Enc (Mbit/s)","Dec (Mbit/s)");
    printf("  %s\n","--------------------------------------------------------------------------------------------------------------");

    for (int si = 0; si < ns; si++) {
        int sz = sizes[si];
        uint8_t *plain = (uint8_t *)malloc((size_t)sz);
        if (!plain) { fprintf(stderr, "alloc failed at size %d\n", sz); break; }
        for (int i = 0; i < sz; i++) plain[i] = (uint8_t)(i & 0xff);

        size_t padded_len; uint8_t *padded = wbc2_pad(plain, (size_t)sz, &padded_len);
        size_t nblocks = padded_len / WBC2_BLOCK_SIZE;

        double enc_t[64] = {0}, dec_t[64] = {0};
        int all_ok = 1;

        for (int r = 0; r < repeats; r++) {
            uint8_t *ct = (uint8_t *)malloc(padded_len);
            double t0 = now_sec();
            for (size_t b = 0; b < nblocks; b++)
                wbc2_encrypt_block(&c, padded + b*WBC2_BLOCK_SIZE, ct + b*WBC2_BLOCK_SIZE);
            enc_t[r] = now_sec() - t0;

            uint8_t *rt = (uint8_t *)malloc(padded_len);
            double t1 = now_sec();
            for (size_t b = 0; b < nblocks; b++)
                wbc2_decrypt_block(&c, ct + b*WBC2_BLOCK_SIZE, rt + b*WBC2_BLOCK_SIZE);
            dec_t[r] = now_sec() - t1;

            if (memcmp(padded, rt, padded_len) != 0) all_ok = 0;
            free(ct); free(rt);
        }

        /* aggregate */
        double et[64], dt[64];
        for (int r = 0; r < repeats; r++) { et[r] = enc_t[r]; dt[r] = dec_t[r]; }
        if (trim_outliers && repeats >= 5) {
            /* simple: sort, drop first and last */
            for (int a=0;a<repeats-1;a++) for (int b=a+1;b<repeats;b++) {
                if (et[a]>et[b]) { double t=et[a]; et[a]=et[b]; et[b]=t; }
                if (dt[a]>dt[b]) { double t=dt[a]; dt[a]=dt[b]; dt[b]=t; }
            }
            double es=0,ds=0; for (int r=1;r<repeats-1;r++){es+=et[r];ds+=dt[r];}
            double ea=es/(repeats-2), da=ds/(repeats-2);
            double skb=(double)sz/1024.0;
            double ekbs=skb/(ea>0?ea:1e-9), dkbs=skb/(da>0?da:1e-9);
            double embs=(double)sz/1e6/(ea>0?ea:1e-9), dmbs=(double)sz/1e6/(da>0?da:1e-9);
            printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
                   skb, ea, ekbs, dkbs, embs, dmbs, embs*8, dmbs*8, all_ok?"OK":"FAIL");
        } else {
            double es=0,ds=0; for (int r=0;r<repeats;r++){es+=enc_t[r];ds+=dec_t[r];}
            double ea=es/repeats, da=ds/repeats;
            double skb=(double)sz/1024.0;
            double ekbs=skb/(ea>0?ea:1e-9), dkbs=skb/(da>0?da:1e-9);
            double embs=(double)sz/1e6/(ea>0?ea:1e-9), dmbs=(double)sz/1e6/(da>0?da:1e-9);
            printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
                   skb, ea, ekbs, dkbs, embs, dmbs, embs*8, dmbs*8, all_ok?"OK":"FAIL");
        }

        free(plain); free(padded);
    }
    printf("\n");
    wbc2_free(&c);
}

/* ── Standalone main ─────────────────────────────────────────────────────── */
#ifndef WBC2_NO_MAIN
int main(int argc, char *argv[]) {
    int do_bench = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--benchmark") == 0 || strcmp(argv[i], "--bench") == 0
            || strcmp(argv[i], "--task-benchmark") == 0) do_bench = 1;
        else if (strcmp(argv[i], "--bench-1gb") == 0) {
            do_bench = 1; setenv("WBC_BENCH_1GB", "1", 1);
        }
    }

    if (do_bench) { wbc2_benchmark(); return 0; }

    /* default: round-trip self-test */
    uint8_t key[WBC2_KEY_SIZE];
    for (int i = 0; i < WBC2_KEY_SIZE; i++) key[i] = (uint8_t)i;
    WBC2Cipher c;
    wbc2_init(&c, key, WBC2_KEY_SIZE);
    uint8_t pt[WBC2_BLOCK_SIZE] = {0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x42,
                                   0x43,0x32,0x20,0x74,0x65,0x73,0x74,0x21};
    uint8_t ct[WBC2_BLOCK_SIZE], rt[WBC2_BLOCK_SIZE];
    wbc2_encrypt_block(&c, pt, ct);
    wbc2_decrypt_block(&c, ct, rt);
    printf("PT:  "); for (int i=0;i<WBC2_BLOCK_SIZE;i++) printf("%02x ",pt[i]);
    printf("\nCT:  "); for (int i=0;i<WBC2_BLOCK_SIZE;i++) printf("%02x ",ct[i]);
    printf("\nRT:  "); for (int i=0;i<WBC2_BLOCK_SIZE;i++) printf("%02x ",rt[i]);
    int ok = memcmp(pt, rt, WBC2_BLOCK_SIZE) == 0;
    printf("\nRound-trip: %s\n", ok ? "OK" : "FAIL");
    wbc2_free(&c);
    return ok ? 0 : 1;
}
#endif /* WBC2_NO_MAIN */
