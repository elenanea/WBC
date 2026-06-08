/*
 * WBC0 Original Algorithm - Sequential Implementation (no MPI)
 *
 * Based on wbc0_original_parallel.c with MPI removed.
 *
 * Unique features vs wbc1_original_p.c:
 * - Sub-block processing: block is divided into sub-blocks, each encrypted
 *   with a derived key; the encrypted sub-block feeds the next key.
 * - shift_mode 0/1/2: three schedules for cyclic-shift amount.
 * - expand_round_key_byte: full mixing of neighbouring key bytes.
 * - derive_round_key_from_subblock_bits: key chaining after each sub-block.
 * - Real permutation engine: rotate + affine + swap + diagflip.
 *
 * Usage: ./wbc0_original_p <task> <key_size> <key_source> <block_size_bits>
 *                         [mode] [data_size_kb] [seed] [avalanche_tests]
 *                         [subblock_size_bytes] [shift_mode]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_BLOCK_SIZE         64
#define MAX_KEY_SIZE_BYTES     32
#define NUM_OPERATIONS         127
#define MAX_OP_STRING          256
#define OP_PARAM_CACHE_SIZE    4096
#define SHIFT_MAP_CACHE_SIZE   32

/* ── Operation structure ─────────────────────────────────────────────────── */
typedef struct {
    char type[32];
    char param1[64];
    char param2[64];
    char desc[128];
    char str_repr[MAX_OP_STRING];
    int  chain_length;
    int  chain[8];
} Operation;

/* ── init_operations cache ───────────────────────────────────────────────── */
typedef struct {
    int valid;
    int key_len;
    uint8_t   key[MAX_KEY_SIZE_BYTES];
    int       base_ops_count;
    Operation operations[NUM_OPERATIONS];
    Operation base_operations[300];
} InitOpsCache;
static InitOpsCache g_init_ops_cache;

/* ── Cipher structure (includes wbc0 extras) ─────────────────────────────── */
typedef struct {
    uint8_t   *key;
    int        key_len_bytes;
    int        key_len_bits;
    int        block_size_bits;
    int        block_size_bytes;
    int        cube_d;
    int        shift_mode;    /* 0=baseline, 1=uniform, 2=alpha+beta */
    Operation *operations;
    Operation *base_operations;
    int        base_ops_count;
} WBC1OriginalCipher;

/* ── Timing helper ───────────────────────────────────────────────────────── */
static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ── SHA-256 wrapper ─────────────────────────────────────────────────────── */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

/* ── MT19937 ─────────────────────────────────────────────────────────────── */
typedef struct { uint32_t mt[624]; int index; } MT19937InitState;
static void mt_init_seed(MT19937InitState *s, uint32_t seed) {
    s->mt[0] = seed;
    for (int i = 1; i < 624; i++)
        s->mt[i] = 1812433253UL * (s->mt[i-1] ^ (s->mt[i-1] >> 30)) + i;
    s->index = 624;
}
static void mt_generate(MT19937InitState *s) {
    for (int i = 0; i < 624; i++) {
        uint32_t y = (s->mt[i] & 0x80000000UL) + (s->mt[(i+1)%624] & 0x7FFFFFFFUL);
        s->mt[i] = s->mt[(i+397)%624] ^ (y >> 1);
        if (y & 1) s->mt[i] ^= 0x9908B0DFUL;
    }
    s->index = 0;
}
static uint32_t mt_random_init(MT19937InitState *s) {
    if (s->index >= 624) mt_generate(s);
    uint32_t y = s->mt[s->index++];
    y ^= y >> 11; y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL; y ^= y >> 18;
    return y;
}

/* ── Small helpers ───────────────────────────────────────────────────────── */
static int min_int(int a, int b) { return a < b ? a : b; }

static uint8_t rotl8(uint8_t v, int s) { s &= 7; return (uint8_t)((v << s) | (v >> (8-s))); }
static uint8_t rotr8(uint8_t v, int s) { s &= 7; return (uint8_t)((v >> s) | (v << (8-s))); }

static int gcd_int(int a, int b) {
    if (a < 0) a = -a; if (b < 0) b = -b;
    while (b) { int t = a % b; a = b; b = t; }
    return a == 0 ? 1 : a;
}
static int mod_inverse(int a, int n) {
    a %= n; if (a < 0) a += n;
    for (int x = 1; x < n; x++) if ((a * x) % n == 1) return x;
    return 1;
}

static int get_key_bit(const uint8_t *key, int bit_index, int key_len_bytes) {
    int byte_idx = (bit_index / 8) % key_len_bytes;
    int bit_pos  = 7 - (bit_index % 8);
    return (key[byte_idx] >> bit_pos) & 1;
}

/* ── Shift-bitmap cache ──────────────────────────────────────────────────── */
typedef struct {
    int     valid, size_bytes, shift_bits, total_bits;
    uint8_t src_byte[MAX_BLOCK_SIZE * 8];
    uint8_t src_mask[MAX_BLOCK_SIZE * 8];
    uint8_t dst_byte[MAX_BLOCK_SIZE * 8];
    uint8_t dst_mask[MAX_BLOCK_SIZE * 8];
} ShiftBitMap;

static ShiftBitMap g_shift_map_cache[SHIFT_MAP_CACHE_SIZE];
static unsigned int g_shift_map_cursor = 0;

static const ShiftBitMap *get_shift_bitmap(int size_bytes, int shift_bits, int total_bits) {
    for (int i = 0; i < SHIFT_MAP_CACHE_SIZE; i++) {
        ShiftBitMap *s = &g_shift_map_cache[i];
        if (s->valid && s->size_bytes == size_bytes && s->shift_bits == shift_bits) return s;
    }
    ShiftBitMap *slot = &g_shift_map_cache[g_shift_map_cursor++ % SHIFT_MAP_CACHE_SIZE];
    slot->valid = 1; slot->size_bytes = size_bytes;
    slot->shift_bits = shift_bits; slot->total_bits = total_bits;
    for (int i = 0; i < total_bits; i++) {
        int sb = ((i + shift_bits) % total_bits);
        slot->src_byte[i] = (uint8_t)(sb / 8);
        slot->src_mask[i] = (uint8_t)(1u << (7 - sb % 8));
        slot->dst_byte[i] = (uint8_t)(i / 8);
        slot->dst_mask[i] = (uint8_t)(1u << (7 - i % 8));
    }
    return slot;
}

/* ── Cyclic bitwise shift ────────────────────────────────────────────────── */
/* MixCube: chain-XOR diffusion — each byte XORed with the previous.
 * Invertible for any block size. */
static void mix_cube(uint8_t *data, int n) {
    for (int i = 1; i < n; i++) data[i] ^= data[i-1];
}
static void inv_mix_cube(uint8_t *data, int n) {
    for (int i = n-1; i >= 1; i--) data[i] ^= data[i-1];
}

static void cyclic_bitwise_shift(uint8_t *block, int size_bytes, int shift_bits) {
    if (shift_bits == 0 || size_bytes <= 0) return;
    int total_bits = size_bytes * 8;
    shift_bits = shift_bits % total_bits;
    if (shift_bits < 0) shift_bits += total_bits;

    uint8_t local_temp[MAX_BLOCK_SIZE];
    uint8_t *temp = local_temp;
    int use_heap = 0;
    if (size_bytes > MAX_BLOCK_SIZE) { temp = (uint8_t *)malloc((size_t)size_bytes); use_heap = 1; }
    memcpy(temp, block, (size_t)size_bytes);

    const ShiftBitMap *bm = get_shift_bitmap(size_bytes, shift_bits, total_bits);
    memset(block, 0, (size_t)size_bytes);
    for (int i = 0; i < total_bits; i++)
        if (temp[bm->src_byte[i]] & bm->src_mask[i])
            block[bm->dst_byte[i]] |= bm->dst_mask[i];
    if (use_heap) free(temp);
}

/* ── init_operations ─────────────────────────────────────────────────────── */
static void init_operations(WBC1OriginalCipher *cipher, const uint8_t *key, int key_len) {
    cipher->operations      = (Operation *)calloc(NUM_OPERATIONS, sizeof(Operation));
    cipher->base_operations = (Operation *)calloc(300,            sizeof(Operation));
    if (!cipher->operations || !cipher->base_operations) {
        fprintf(stderr, "Error: Memory allocation failed\n"); return;
    }

    /* Check cache */
    if (g_init_ops_cache.valid && g_init_ops_cache.key_len == key_len &&
        memcmp(g_init_ops_cache.key, key, (size_t)key_len) == 0) {
        memcpy(cipher->operations,      g_init_ops_cache.operations,      sizeof(Operation) * NUM_OPERATIONS);
        memcpy(cipher->base_operations, g_init_ops_cache.base_operations,  sizeof(Operation) * 300);
        cipher->base_ops_count = g_init_ops_cache.base_ops_count;
        return;
    }

    Operation temp_ops[300]; int temp_idx = 0;

    const char *faces[] = {"U","D","L","R","F","B"};
    const char *dirs[]  = {"","'","2","3"};
    for (int f = 0; f < 6; f++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "face");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", faces[f]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Rotate %s face %s", faces[f], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('face','%s','%s','Rotate %s face %s')", faces[f],dirs[d],faces[f],dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    const char *slices[] = {"M","E","S"};
    for (int s = 0; s < 3; s++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "slice");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", slices[s]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Rotate %s slice %s", slices[s], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('slice','%s','%s','Rotate %s slice %s')", slices[s],dirs[d],slices[s],dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    const char *wide[] = {"u","d","l","r","f","b"};
    for (int w = 0; w < 6; w++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "wide");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", wide[w]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Wide move %s%s", wide[w], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('wide','%s','%s','Wide move %s%s')", wide[w],dirs[d],wide[w],dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    const char *cube_rot[] = {"x","y","z"};
    for (int r = 0; r < 3; r++) for (int d = 0; d < 4; d++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "cube");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%s", cube_rot[r]);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%s", dirs[d]);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Cube rotation %s%s", cube_rot[r], dirs[d]);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('cube','%s','%s','Cube rotation %s%s')", cube_rot[r],dirs[d],cube_rot[r],dirs[d]);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    for (int axis = 0; axis < 3; axis++) for (int k = 0; k < 4; k++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "swap");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", axis);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"%d", k);
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Swap axis=%d, offset=%d", axis, k);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('swap',%d,%d,'Swap axis=%d, offset=%d')", axis,k,axis,k);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    for (int axis = 0; axis < 3; axis++) {
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "diagflip");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", axis);
        temp_ops[temp_idx].param2[0] = '\0';
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Diagonal flip axis=%d", axis);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('diagflip',%d,'','Diagonal flip axis=%d')", axis, axis);
        temp_ops[temp_idx].chain_length = 0; temp_idx++;
    }
    int static_ops_count = temp_idx; /* 87 */

    for (int i = 0; i < 20; i++) {
        uint8_t si[256]; memcpy(si, key, (size_t)key_len);
        si[key_len] = (uint8_t)(i & 0xFF); si[key_len+1] = (uint8_t)((i>>8)&0xFF);
        uint8_t h[SHA256_DIGEST_LENGTH]; sha256_hash(si, (size_t)(key_len+2), h);
        uint32_t seed = ((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
        MT19937InitState rng; mt_init_seed(&rng, seed);
        int n_ops = 4 + (int)(mt_random_init(&rng) % 4);
        snprintf(temp_ops[temp_idx].type,  sizeof(temp_ops[0].type),  "dynamic");
        snprintf(temp_ops[temp_idx].param1,sizeof(temp_ops[0].param1),"%d", i);
        snprintf(temp_ops[temp_idx].param2,sizeof(temp_ops[0].param2),"ops");
        snprintf(temp_ops[temp_idx].desc,  sizeof(temp_ops[0].desc),  "Dynamic pattern %d", i);
        snprintf(temp_ops[temp_idx].str_repr,sizeof(temp_ops[0].str_repr),
                 "('dynamic',%d,'ops','Dynamic pattern %d')", i, i);
        temp_ops[temp_idx].chain_length = n_ops;
        for (int j = 0; j < n_ops; j++)
            temp_ops[temp_idx].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)static_ops_count);
        temp_idx++;
    }
    int all_ops_count = temp_idx; /* 107 */
    memcpy(cipher->base_operations, temp_ops, sizeof(Operation) * (size_t)all_ops_count);
    cipher->base_ops_count = all_ops_count;

    for (int i = 0; i < NUM_OPERATIONS; i++) {
        uint8_t si[256]; memcpy(si, key, (size_t)key_len);
        memcpy(si + key_len, "WBC1_OP", 7);
        si[key_len+7] = (uint8_t)(i&0xFF); si[key_len+8] = (uint8_t)((i>>8)&0xFF);
        uint8_t h[SHA256_DIGEST_LENGTH]; sha256_hash(si, (size_t)(key_len+9), h);
        uint32_t seed = ((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
        MT19937InitState rng; mt_init_seed(&rng, seed);
        int chain_len = 3 + (int)(mt_random_init(&rng) % 4);
        snprintf(cipher->operations[i].type,    sizeof(cipher->operations[0].type),  "dynamic");
        snprintf(cipher->operations[i].param1,  sizeof(cipher->operations[0].param1),"%d", i);
        snprintf(cipher->operations[i].param2,  sizeof(cipher->operations[0].param2),"chain");
        snprintf(cipher->operations[i].desc,    sizeof(cipher->operations[0].desc),  "Operation %d", i);
        snprintf(cipher->operations[i].str_repr,sizeof(cipher->operations[0].str_repr),
                 "('dynamic',%d,'chain','Operation %d')", i, i);
        cipher->operations[i].chain_length = chain_len;
        for (int j = 0; j < chain_len; j++)
            cipher->operations[i].chain[j] = (int)(mt_random_init(&rng) % (uint32_t)all_ops_count);
    }

    if (key_len <= MAX_KEY_SIZE_BYTES) {
        g_init_ops_cache.valid = 1;
        g_init_ops_cache.key_len = key_len;
        memcpy(g_init_ops_cache.key, key, (size_t)key_len);
        g_init_ops_cache.base_ops_count = cipher->base_ops_count;
        memcpy(g_init_ops_cache.operations,      cipher->operations,      sizeof(Operation)*NUM_OPERATIONS);
        memcpy(g_init_ops_cache.base_operations, cipher->base_operations, sizeof(Operation)*300);
    }
}

/* ── CachedOpParams ──────────────────────────────────────────────────────── */
typedef struct {
    int valid, op_id, size;
    uint8_t op_kind; /* 0=general, 1=swap, 2=diagflip */
    uint32_t seed;
    int shift, a, b, inv_a;
} CachedOpParams;

static CachedOpParams g_op_param_cache[OP_PARAM_CACHE_SIZE];

static uint32_t hash_operation_seed(const Operation *op, int op_id, int size) {
    uint32_t h = 2166136261u;
    h ^= (uint32_t)op_id; h *= 16777619u;
    h ^= (uint32_t)size;  h *= 16777619u;
    const unsigned char *fields[3] = {
        (const unsigned char *)op->type,
        (const unsigned char *)op->param1,
        (const unsigned char *)op->param2
    };
    for (int f = 0; f < 3; f++) {
        const unsigned char *p = fields[f];
        while (*p) { h ^= (uint32_t)*p++; h *= 16777619u; }
        h ^= 0xFFu; h *= 16777619u;
    }
    return h;
}

static int parse_turn(const char *t) {
    if (!t || !t[0]) return 1;
    if (strcmp(t,"'") == 0) return -1;
    if (strcmp(t,"2") == 0) return 2;
    if (strcmp(t,"3") == 0) return 3;
    return 1;
}

static const CachedOpParams *get_cached_op_params(const Operation *op, int op_id, int size) {
    uint32_t h = 2166136261u;
    h ^= (uint32_t)op_id; h *= 16777619u;
    h ^= (uint32_t)size;  h *= 16777619u;
    uint32_t idx = h % OP_PARAM_CACHE_SIZE;
    CachedOpParams *slot = &g_op_param_cache[idx];
    if (slot->valid && slot->op_id == op_id && slot->size == size) return slot;

    uint32_t seed = hash_operation_seed(op, op_id, size);
    slot->valid = 1; slot->op_id = op_id; slot->size = size; slot->seed = seed;
    slot->shift = 0; slot->a = 1; slot->b = 0; slot->inv_a = 1;

    if (strcmp(op->type, "swap") == 0)     { slot->op_kind = 1; return slot; }
    if (strcmp(op->type, "diagflip") == 0) { slot->op_kind = 2; return slot; }
    slot->op_kind = 0;

    int turn = parse_turn(op->param2);
    int base = (int)((seed >> 16) % (uint32_t)size) + 1;
    slot->shift = base * (turn < 0 ? -turn : turn);
    if (turn < 0) slot->shift = -slot->shift;

    int a = ((int)(seed % (uint32_t)size)) | 1;
    while (gcd_int(a, size) != 1) a += 2;
    a %= size; if (a == 0) a = 1;
    slot->a = a;
    slot->b = (int)((seed >> 8) % (uint32_t)size);
    slot->inv_a = mod_inverse(a, size);
    return slot;
}

/* ── Base permutation apply ──────────────────────────────────────────────── */
static void rotate_block_bytes(uint8_t *block, int size, int shift) {
    if (size <= 1) return;
    shift %= size; if (shift < 0) shift += size; if (!shift) return;
    uint8_t temp[MAX_BLOCK_SIZE]; memcpy(temp, block, (size_t)size);
    for (int i = 0; i < size; i++) block[i] = temp[(i + shift) % size];
}

static void apply_affine_permutation(uint8_t *block, int size, int a, int b, int inverse) {
    if (size <= 1) return;
    uint8_t temp[MAX_BLOCK_SIZE]; memcpy(temp, block, (size_t)size);
    if (!inverse) {
        for (int i = 0; i < size; i++) block[(a * i + b) % size] = temp[i];
    } else {
        int inv_a = mod_inverse(a, size);
        for (int dst = 0; dst < size; dst++) block[(inv_a * (dst - b + size)) % size] = temp[dst];
    }
}

static void apply_swap_style(uint8_t *block, int size, uint32_t seed) {
    if (size <= 1) return;
    int stride = (int)((seed % (uint32_t)(size - 1)) + 1);
    for (int i = 0; i + stride < size; i += 2 * stride) {
        uint8_t t = block[i]; block[i] = block[i + stride]; block[i + stride] = t;
    }
}

static void apply_diagflip_style(uint8_t *block, int size) {
    if (size <= 1) return;
    for (int i = 0; i < size / 2; i++) {
        uint8_t t = block[i]; block[i] = block[size-1-i]; block[size-1-i] = t;
    }
}

static void apply_base_op_perm(uint8_t *block, int size, const Operation *op, int op_id, int inverse) {
    if (size <= 1 || !op) return;
    const CachedOpParams *p = get_cached_op_params(op, op_id, size);
    if (p->op_kind == 1) { apply_swap_style(block, size, p->seed); return; }
    if (p->op_kind == 2) { apply_diagflip_style(block, size); return; }
    if (!inverse) {
        rotate_block_bytes(block, size, p->shift);
        apply_affine_permutation(block, size, p->a, p->b, 0);
    } else {
        uint8_t temp[MAX_BLOCK_SIZE]; memcpy(temp, block, (size_t)size);
        for (int dst = 0; dst < size; dst++)
            block[(p->inv_a * (dst - p->b + size)) % size] = temp[dst];
        rotate_block_bytes(block, size, -p->shift);
    }
}

static void apply_operation_sized(WBC1OriginalCipher *cipher, uint8_t *block, int size,
                                   int op_id, int inverse) {
    if (size <= 1 || !cipher || !cipher->operations || !cipher->base_operations) return;
    if (op_id < 0 || op_id >= NUM_OPERATIONS) return;
    Operation *op = &cipher->operations[op_id];
    if (op->chain_length > 0) {
        if (!inverse) {
            for (int i = 0; i < op->chain_length; i++) {
                int bi = op->chain[i];
                if (bi < 0 || bi >= cipher->base_ops_count) continue;
                apply_base_op_perm(block, size, &cipher->base_operations[bi], op_id * 257 + bi, 0);
            }
        } else {
            for (int i = op->chain_length - 1; i >= 0; i--) {
                int bi = op->chain[i];
                if (bi < 0 || bi >= cipher->base_ops_count) continue;
                apply_base_op_perm(block, size, &cipher->base_operations[bi], op_id * 257 + bi, 1);
            }
        }
        return;
    }
    apply_base_op_perm(block, size, op, op_id, inverse);
}

/* ── Cipher init/free ────────────────────────────────────────────────────── */
static void wbc1_original_init(WBC1OriginalCipher *cipher,
                                const uint8_t *key, int key_len, int block_size_bits) {
    memset(cipher, 0, sizeof(*cipher));
    cipher->key_len_bytes  = key_len;
    cipher->key_len_bits   = key_len * 8;
    cipher->key = (uint8_t *)malloc((size_t)key_len);
    memcpy(cipher->key, key, (size_t)key_len);
    cipher->block_size_bits  = block_size_bits;
    cipher->block_size_bytes = block_size_bits / 8;
    switch (block_size_bits) {
        case 32:  cipher->cube_d = 2; break;
        case 64:  cipher->cube_d = 4; break;
        case 128: cipher->cube_d = 4; break;
        case 512: cipher->cube_d = 8; break;
        default:  cipher->cube_d = 4; break;
    }
    init_operations(cipher, cipher->key, cipher->key_len_bytes);
}

static void wbc1_original_free(WBC1OriginalCipher *cipher) {
    if (cipher->key)             free(cipher->key);
    if (cipher->operations)      free(cipher->operations);
    if (cipher->base_operations) free(cipher->base_operations);
    memset(cipher, 0, sizeof(*cipher));
}

/* ── Key mixing functions (wbc0 exclusive) ───────────────────────────────── */
static uint8_t mix_key_byte(uint8_t byte) {
    uint8_t m = byte;
    m ^= byte >> 4;
    m ^= (uint8_t)((byte << 3) | (byte >> 5));
    m ^= byte >> 1;
    return m;
}

static uint8_t expand_round_key_byte(const uint8_t *rk, int rk_len, int index) {
    if (rk_len <= 0) return 0;
    uint8_t center = rk[index % rk_len];
    uint8_t left   = rk[(index - 1 + rk_len) % rk_len];
    uint8_t right  = rk[(index + 1) % rk_len];
    uint8_t mixed  = center
                   ^ rotl8(right, index & 7)
                   ^ rotr8(left,  (index + 3) & 7)
                   ^ (uint8_t)(index * 29);
    return mix_key_byte(mixed);
}

/* ── build_round_schedule (shift_mode 0/1/2) ─────────────────────────────── */
static void build_round_schedule(WBC1OriginalCipher *cipher,
                                  const uint8_t *rk, int rk_len,
                                  int subblock_size,
                                  int *op_ids, int *shifts) {
    int subblock_bits = subblock_size * 8;
    if (subblock_bits <= 0) subblock_bits = 8;
    for (int i = 0; i < rk_len; i++) {
        uint8_t mb = expand_round_key_byte(rk, rk_len, i);
        int key_bit = (mb >> 7) & 1;
        op_ids[i] = mb % NUM_OPERATIONS;
        if (cipher->shift_mode == 2) {
            int alpha = i % 8, beta = mb % 4;
            shifts[i] = (alpha + beta) % subblock_bits;
        } else if (cipher->shift_mode == 1) {
            shifts[i] = 1 + (mb % cipher->cube_d);
        } else {
            shifts[i] = key_bit ? cipher->cube_d : (cipher->cube_d / 2 + 1);
        }
    }
}

/* ── process_subblock_with_key ───────────────────────────────────────────── */
static void process_subblock_with_key(WBC1OriginalCipher *cipher,
                                       const uint8_t *input, uint8_t *output,
                                       int subblock_size,
                                       const uint8_t *rk, int rk_len, int inverse) {
    memcpy(output, input, (size_t)subblock_size);
    if (rk_len <= 0 || rk_len > MAX_BLOCK_SIZE) return;

    int op_ids[MAX_BLOCK_SIZE], shifts[MAX_BLOCK_SIZE];
    build_round_schedule(cipher, rk, rk_len, subblock_size, op_ids, shifts);

    if (!inverse) {
        for (int i = 0; i < rk_len; i++) {
            apply_operation_sized(cipher, output, subblock_size, op_ids[i], 0);
            mix_cube(output, subblock_size);
            cyclic_bitwise_shift(output, subblock_size, shifts[i]);
        }
    } else {
        for (int i = rk_len - 1; i >= 0; i--) {
            cyclic_bitwise_shift(output, subblock_size, -shifts[i]);
            inv_mix_cube(output, subblock_size);
            apply_operation_sized(cipher, output, subblock_size, op_ids[i], 1);
        }
    }
}

/* ── derive_round_key_from_subblock_bits ────────────────────────────────── */
static void derive_round_key_from_subblock_bits(const uint8_t *enc_sub, int sub_bytes,
                                                 uint8_t *rk, int rk_len) {
    int total_sub_bits = sub_bytes * 8;
    int required_bits  = rk_len * 8;
    memset(rk, 0, (size_t)rk_len);
    if (total_sub_bits <= 0 || required_bits <= 0) return;
    for (int bit = 0; bit < required_bits; bit++) {
        int src = bit % total_sub_bits;
        int sb  = src / 8, sp = 7 - src % 8;
        int db  = bit / 8, dp = 7 - bit % 8;
        if ((enc_sub[sb] >> sp) & 1) rk[db] |= (uint8_t)(1 << dp);
    }
}

/* ── Block encrypt/decrypt (whole block = one unit) ─────────────────────── */
/* For single-block tests (avalanche, differential) — uses cipher->key directly */
static void wbc1_original_encrypt_block(WBC1OriginalCipher *cipher,
                                         const uint8_t *plaintext, uint8_t *ciphertext) {
    process_subblock_with_key(cipher, plaintext, ciphertext,
                              cipher->block_size_bytes,
                              cipher->key, cipher->key_len_bytes, 0);
}

static void wbc1_original_decrypt_block(WBC1OriginalCipher *cipher,
                                         const uint8_t *ciphertext, uint8_t *plaintext) {
    process_subblock_with_key(cipher, ciphertext, plaintext,
                              cipher->block_size_bytes,
                              cipher->key, cipher->key_len_bytes, 1);
}

/* ── Sequential encrypt with cascade key between blocks ─────────────────── */
static uint8_t *seq_encrypt(WBC1OriginalCipher *cipher,
                             const uint8_t *plaintext, int plaintext_len,
                             int *out_len) {
    int bs         = cipher->block_size_bytes;
    int num_blocks = (plaintext_len + bs - 1) / bs;
    int padded_len = num_blocks * bs;
    int pad_len    = padded_len - plaintext_len;

    uint8_t *padded = (uint8_t *)calloc((size_t)padded_len, 1);
    memcpy(padded, plaintext, (size_t)plaintext_len);
    for (int i = 0; i < pad_len; i++)
        padded[plaintext_len + i] = (uint8_t)pad_len; /* PKCS7 */

    uint8_t *inter  = (uint8_t *)malloc((size_t)padded_len);
    uint8_t *result = (uint8_t *)malloc((size_t)padded_len);

    /* ── Pass 1: forward cascade (plaintext → inter) ──────────────────── */
    uint8_t fwd_key[MAX_KEY_SIZE_BYTES];
    int     key_len = cipher->key_len_bytes;
    memcpy(fwd_key, cipher->key, (size_t)key_len);

    for (int i = 0; i < num_blocks; i++) {
        process_subblock_with_key(cipher, padded + i*bs, inter + i*bs,
                                  bs, fwd_key, key_len, 0);
        derive_round_key_from_subblock_bits(inter + i*bs, bs, fwd_key, key_len);
    }

    /* ── Pass 2: backward cascade (inter → result, right→left) ────────── */
    /* Independent backward key: derived from cipher->key itself. */
    uint8_t bwd_key[MAX_KEY_SIZE_BYTES];
    derive_round_key_from_subblock_bits(cipher->key, key_len, bwd_key, key_len);

    for (int i = num_blocks - 1; i >= 0; i--) {
        process_subblock_with_key(cipher, inter + i*bs, result + i*bs,
                                  bs, bwd_key, key_len, 0);
        derive_round_key_from_subblock_bits(result + i*bs, bs, bwd_key, key_len);
    }

    free(inter); free(padded);
    *out_len = padded_len;
    return result;
}

/* Sequential decrypt with bidirectional cascade */
static uint8_t *seq_decrypt(WBC1OriginalCipher *cipher,
                             const uint8_t *ciphertext, int ciphertext_len,
                             int *out_len) {
    int bs         = cipher->block_size_bytes;
    int num_blocks = ciphertext_len / bs;
    int key_len    = cipher->key_len_bytes;

    uint8_t *inter = (uint8_t *)malloc((size_t)ciphertext_len);
    uint8_t *dec   = (uint8_t *)malloc((size_t)ciphertext_len);

    /* ── Undo Pass 2: backward cascade (ciphertext → inter) ───────────── */
    uint8_t bwd_key[MAX_KEY_SIZE_BYTES];
    derive_round_key_from_subblock_bits(cipher->key, key_len, bwd_key, key_len);

    for (int i = num_blocks - 1; i >= 0; i--) {
        process_subblock_with_key(cipher, ciphertext + i*bs, inter + i*bs,
                                  bs, bwd_key, key_len, 1);
        /* derive from CIPHERTEXT (known, same as during encryption) */
        derive_round_key_from_subblock_bits(ciphertext + i*bs, bs, bwd_key, key_len);
    }

    /* ── Undo Pass 1: forward cascade (inter → dec) ───────────────────── */
    uint8_t fwd_key[MAX_KEY_SIZE_BYTES];
    memcpy(fwd_key, cipher->key, (size_t)key_len);

    for (int i = 0; i < num_blocks; i++) {
        process_subblock_with_key(cipher, inter + i*bs, dec + i*bs,
                                  bs, fwd_key, key_len, 1);
        /* derive from inter (= pass-1 ciphertext, same as during encryption) */
        derive_round_key_from_subblock_bits(inter + i*bs, bs, fwd_key, key_len);
    }

    free(inter);

    int pad_len = dec[ciphertext_len - 1];
    int valid   = (pad_len > 0 && pad_len <= bs);
    if (valid)
        for (int i = ciphertext_len - pad_len; i < ciphertext_len; i++)
            if (dec[i] != (uint8_t)pad_len) { valid = 0; break; }

    *out_len = valid ? ciphertext_len - pad_len : ciphertext_len;
    uint8_t *result = (uint8_t *)malloc((size_t)(*out_len + 1));
    memcpy(result, dec, (size_t)*out_len);
    result[*out_len] = 0;
    free(dec);
    return result;
}

/* ── Statistical helpers (identical to wbc1_original_p.c) ───────────────── */
static uint8_t *generate_random_bytes(int size) {
    uint8_t *d = (uint8_t *)malloc((size_t)size);
    for (int i = 0; i < size; i++) d[i] = (uint8_t)(rand() % 256);
    return d;
}

static double shannon_entropy(const uint8_t *data, int len) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double e = 0;
    for (int i = 0; i < 256; i++) if (freq[i] > 0) {
        double p = (double)freq[i] / len; e -= p * log2(p);
    }
    return e;
}

static void frequency_test(const uint8_t *data, int len,
                            double *mean, double *std, double *chi_sq) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double sum = 0; for (int i = 0; i < 256; i++) sum += freq[i];
    *mean = sum / 256.0;
    double ss = 0; for (int i = 0; i < 256; i++) { double d = freq[i] - *mean; ss += d*d; }
    *std = sqrt(ss / 256.0);
    double exp_v = len / 256.0; *chi_sq = 0;
    for (int i = 0; i < 256; i++) { double d = freq[i] - exp_v; *chi_sq += d*d / exp_v; }
}

/* ── per-block avalanche ──────────────────────────────────────────────────────── */
static void per_block_avalanche(WBC1OriginalCipher *cipher,
                                 const uint8_t *data, int data_len) {
    if (data_len <= 0) { printf("  Per-block avalanche: N/A (empty)\n"); return; }
    int bs = cipher->block_size_bytes;
    int num_blocks = (data_len + bs - 1) / bs;
    uint8_t *padded = (uint8_t *)calloc((size_t)(num_blocks * bs), 1);
    memcpy(padded, data, (size_t)data_len);

    printf("  Per-block avalanche (cascade key, 1-bit flip per block):\n");
    uint8_t current_key[MAX_KEY_SIZE_BYTES];
    int key_len = cipher->key_len_bytes;
    memcpy(current_key, cipher->key, (size_t)key_len);

    double total = 0.0;
    uint8_t ct0[MAX_BLOCK_SIZE], ct1[MAX_BLOCK_SIZE], blk1[MAX_BLOCK_SIZE];
    for (int b = 0; b < num_blocks; b++) {
        const uint8_t *blk = padded + b * bs;
        process_subblock_with_key(cipher, blk, ct0, bs, current_key, key_len, 0);
        memcpy(blk1, blk, bs);
        blk1[0] ^= 0x01;
        process_subblock_with_key(cipher, blk1, ct1, bs, current_key, key_len, 0);
        int diff = 0;
        for (int i = 0; i < bs; i++) diff += __builtin_popcount(ct0[i] ^ ct1[i]);
        double pct = (100.0 * diff) / (bs * 8);
        printf("  Block %3d/%d:  %5.1f%%\n", b + 1, num_blocks, pct);
        total += pct;
        derive_round_key_from_subblock_bits(ct0, bs, current_key, key_len);
    }
    printf("  ──────────────────────────────\n");
    printf("  Average:        %5.1f%%  (ideal ~50%%)\n",
           num_blocks > 0 ? total / num_blocks : 0.0);
    free(padded);
}

static void avalanche_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total = 0, min_pct = 100, max_pct = 0;
    int bs = cipher->block_size_bytes;
    for (int t = 0; t < num_tests; t++) {
        uint8_t *pt1 = generate_random_bytes(bs);
        uint8_t *pt2 = (uint8_t *)malloc((size_t)bs); memcpy(pt2, pt1, (size_t)bs);
        pt2[rand() % bs] ^= (uint8_t)(1 << (rand() % 8));
        uint8_t *ct1 = (uint8_t *)malloc((size_t)bs);
        uint8_t *ct2 = (uint8_t *)malloc((size_t)bs);
        wbc1_original_encrypt_block(cipher, pt1, ct1);
        wbc1_original_encrypt_block(cipher, pt2, ct2);
        int diff = 0;
        for (int i = 0; i < bs; i++) { uint8_t x = ct1[i]^ct2[i]; for (int b=0;b<8;b++) if(x&(1<<b)) diff++; }
        double pct = (100.0 * diff) / (bs * 8);
        total += pct; if (pct < min_pct) min_pct = pct; if (pct > max_pct) max_pct = pct;
        free(pt1); free(pt2); free(ct1); free(ct2);
    }
    results[0] = total / num_tests; results[1] = min_pct; results[2] = max_pct;
}

static double correlation_test(const uint8_t *d1, const uint8_t *d2, int len) {
    double m1=0, m2=0;
    for (int i=0;i<len;i++) { m1+=d1[i]; m2+=d2[i]; }
    m1/=len; m2/=len;
    double cov=0,v1=0,v2=0;
    for (int i=0;i<len;i++) { double a=d1[i]-m1,b=d2[i]-m2; cov+=a*b; v1+=a*a; v2+=b*b; }
    if (v1==0||v2==0) return 0;
    return cov / sqrt(v1 * v2);
}

static void differential_test(WBC1OriginalCipher *cipher, int num_tests, double *results) {
    double total=0, min_pct=100, max_pct=0;
    int bs = cipher->block_size_bytes;
    uint8_t *pt = generate_random_bytes(bs);
    for (int t=0;t<num_tests;t++) {
        uint8_t *ct1=(uint8_t*)malloc((size_t)bs); wbc1_original_encrypt_block(cipher,pt,ct1);
        int fb=rand()%cipher->key_len_bytes, fi=rand()%8;
        cipher->key[fb] ^= (uint8_t)(1<<fi);
        uint8_t *ct2=(uint8_t*)malloc((size_t)bs); wbc1_original_encrypt_block(cipher,pt,ct2);
        cipher->key[fb] ^= (uint8_t)(1<<fi);
        int diff=0;
        for (int i=0;i<bs;i++) { uint8_t x=ct1[i]^ct2[i]; for(int b=0;b<8;b++) if(x&(1<<b)) diff++; }
        double pct=(100.0*diff)/(bs*8);
        total+=pct; if(pct<min_pct) min_pct=pct; if(pct>max_pct) max_pct=pct;
        free(ct1); free(ct2);
    }
    results[0]=total/num_tests; results[1]=min_pct; results[2]=max_pct;
    free(pt);
}

/* ── Print helpers ───────────────────────────────────────────────────────── */
static void print_hex(const uint8_t *data, int len, int max_bytes) {
    for (int i = 0; i < len && i < max_bytes; i++) {
        printf("%02x", data[i]);
        if ((i+1) % 32 == 0) printf("\n");
    }
    if (len > max_bytes) printf("...\n");
    else if (len % 32 != 0) printf("\n");
}

static void print_key_hex(const uint8_t *key, int key_len) {
    printf("\n");
    printf("====================================================================================================\n");
    printf("Generated key (hex) / Сгенерированный ключ (hex)\n");
    printf("====================================================================================================\n");
    for (int i = 0; i < key_len; i++) {
        printf("%02x", key[i]);
        if ((i+1)%32==0) printf("\n"); else if ((i+1)%8==0) printf(" ");
    }
    if (key_len%32!=0) printf("\n");
    printf("====================================================================================================\n\n");
}

static void print_key_operation_mapping(WBC1OriginalCipher *cipher, int show_count) {
    printf("\n====================================================================================================\n");
    printf("Key-to-Operation Mapping (with expand_round_key_byte mixing)\n");
    printf("Format: Key[N]: ASCII Hex → mixed_byte → Operation ID\n");
    printf("====================================================================================================\n");
    if (show_count > cipher->key_len_bytes) show_count = cipher->key_len_bytes;
    for (int i = 0; i < show_count; i++) {
        uint8_t kb = cipher->key[i];
        uint8_t mb = expand_round_key_byte(cipher->key, cipher->key_len_bytes, i);
        int op_id = mb % NUM_OPERATIONS;
        Operation *op = &cipher->operations[op_id];
        char ac = (kb >= 32 && kb <= 126) ? (char)kb : '.';
        printf("Key[%3d]: %c 0x%02X (mixed=0x%02X) → Op %3d: ", i, ac, kb, mb, op_id);
        if (strcmp(op->type, "dynamic") == 0)
            printf("(dynamic,'%s',chain=%d) %s\n", op->param1, op->chain_length, op->desc);
        else
            printf("(%s,'%s','%s') %s\n", op->type, op->param1, op->param2, op->desc);
    }
    printf("====================================================================================================\n\n");
}

static void print_operations_table(WBC1OriginalCipher *cipher) {
    printf("\n==============================================================================\n");
    printf("          WBC0 ORIGINAL - ТАБЛИЦА ОПЕРАЦИЙ / OPERATIONS TABLE\n");
    printf("==============================================================================\n");
    printf("%-7s %-10s %-10s %s\n","Номер","ASCII","Hex","Описание операции");
    printf("%-7s %-10s %-10s %s\n","Number","Char","Code","Operation Description");
    printf("------------------------------------------------------------------------------\n");
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        Operation *op = &cipher->operations[i];
        char asc[12]; if (i>=32&&i<127) snprintf(asc,sizeof(asc),"'%c'",(char)i); else snprintf(asc,sizeof(asc),".");
        char hex[12]; snprintf(hex,sizeof(hex),"0x%02X",i);
        printf("%-7d %-10s %-10s (%s", i, asc, hex, op->type);
        if (strlen(op->param1)>0) printf(",'%s'",op->param1);
        if (strlen(op->param2)>0) printf(",'%s'",op->param2);
        if (op->chain_length>0)   printf(",chain=%d",op->chain_length);
        printf(") %s\n", op->desc);
    }
    printf("==============================================================================\n");
    printf("Total: %d ops | Base: %d\n", NUM_OPERATIONS, cipher->base_ops_count);
    printf("  Face:24  Slice:12  Wide:24  CubeRot:12  Swap:12  Diagflip:3  Dynamic:20\n");
    printf("==============================================================================\n\n");
    printf("Key bit to operation mapping (first 10 bits):\n");
    for (int i = 0; i < 10 && i < cipher->key_len_bits; i++) {
        int kb = get_key_bit(cipher->key, i, cipher->key_len_bytes);
        int op = kb % NUM_OPERATIONS;
        printf("  Bit %3d: value=%d → op %3d\n", i, kb, op);
    }
    if (cipher->key_len_bits > 10)
        printf("  ... (showing first 10 of %d bits)\n", cipher->key_len_bits);
    printf("==============================================================================\n");
}

/* ============================================================
 * main
 * ============================================================ */
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <task> <key_size> <key_source> <block_size_bits>\n"
               "       [mode] [data_size_kb] [seed] [avalanche_tests]\n"
               "       [subblock_size_bytes] [shift_mode]\n\n", argv[0]);
        printf("  task:                0=encrypt/decrypt, 1=statistical tests, 2=operations table\n");
        printf("  key_size:            128, 192, 256\n");
        printf("  key_source:          0=random, 1=sequential\n");
        printf("  block_size_bits:     32, 64, 128, 512, or 0=auto\n");
        printf("  mode:                (task 0) 0=demo text, 1=random data\n");
        printf("  data_size_kb:        data size in KB (default 1)\n");
        printf("  seed:                RNG seed (optional, default=time)\n");
        printf("  avalanche_tests:     number of avalanche iterations (default 300)\n");
        printf("  subblock_size_bytes: 0=auto (cube_d), 1..block_bytes=override\n");
        printf("  shift_mode:          0=baseline, 1=uniform, 2=alpha+beta (default 0)\n\n");
        printf("Examples:\n");
        printf("  %s 0 256 0 128                       # Demo text, 128-bit blocks\n", argv[0]);
        printf("  %s 0 256 0 128 1 10                  # 10 KB random data\n", argv[0]);
        printf("  %s 1 256 0 128 0 100                 # Stats, 100 KB\n", argv[0]);
        printf("  %s 1 256 0 128 0 10 42 100 1         # seed=42, 100 avalanche runs, shift_mode=1\n", argv[0]);
        printf("  %s 2 256 0 128                       # Print operations table\n", argv[0]);
        return 1;
    }

    int task            = atoi(argv[1]);
    int key_size        = atoi(argv[2]);
    int key_source      = atoi(argv[3]);
    int block_size_bits = atoi(argv[4]);
    int mode            = (argc >= 6)  ? atoi(argv[5]) : 0;
    int data_kb         = (argc >= 7)  ? atoi(argv[6]) : 1;
    unsigned int seed   = (argc >= 8)  ? (unsigned int)strtoul(argv[7],NULL,10)
                                       : (unsigned int)time(NULL);
    int avalanche_runs  = (argc >= 9)  ? atoi(argv[8]) : 300;
    int shift_mode      = (argc >= 10) ? atoi(argv[9]) : 0;

    if (data_kb < 1) data_kb = 1;
    if (avalanche_runs < 10)   avalanche_runs = 10;
    if (avalanche_runs > 5000) avalanche_runs = 5000;
    if (shift_mode < 0) shift_mode = 0;
    if (shift_mode > 2) shift_mode = 2;

    srand(seed);

    /* Auto block size */
    if (block_size_bits == 0) {
        if      (data_kb < 10)   block_size_bits = 32;
        else if (data_kb < 100)  block_size_bits = 64;
        else if (data_kb < 1000) block_size_bits = 128;
        else                     block_size_bits = 512;
        printf("\nAuto block size: %d bits (data=%d KB)\n\n", block_size_bits, data_kb);
    }

    /* Key generation */
    int key_len = key_size / 8;
    uint8_t *key = (uint8_t *)malloc((size_t)key_len);
    if (key_source == 0) {
        for (int i = 0; i < key_len; i++) key[i] = (uint8_t)(rand() % 256);
    } else {
        for (int i = 0; i < key_len; i++) key[i] = (uint8_t)(i % 256);
    }

    /* Init cipher */
    WBC1OriginalCipher cipher;
    wbc1_original_init(&cipher, key, key_len, block_size_bits);
    cipher.shift_mode = shift_mode;

    /* Print cipher params */
    if (task != 2) {
        const char *shift_names[] = {"baseline","uniform-key-byte","alpha+beta"};
        printf("\nWBC0 Original (sequential) | key=%d bits | block=%d bits | "
               "cascade-key between blocks | shift_mode=%d (%s)\n\n",
               key_size, block_size_bits, shift_mode, shift_names[shift_mode]);
    }

    /* ── task 0: encrypt / decrypt ───────────────────────────────────────── */
    if (task == 0) {
        uint8_t *plaintext = NULL; int text_len = 0;

        if (mode == 0) {
            const char *demo = "Це тестове повідомлення для демонстрації шифрування оригінальним алгоритмом WBC0.";
            text_len  = (int)strlen(demo);
            plaintext = (uint8_t *)malloc((size_t)text_len);
            memcpy(plaintext, demo, (size_t)text_len);
            printf("========================================\n");
            printf("WBC0 Original - Text Encryption Demo\n");
            printf("========================================\n");
            printf("Original text: %s\n", demo);
        } else {
            text_len  = data_kb * 1024;
            plaintext = generate_random_bytes(text_len);
            printf("========================================\n");
            printf("WBC0 Original - Random Data Encryption\n");
            printf("========================================\n");
            printf("Data size: %d KB (%d bytes)\nFirst 64 bytes:\n", data_kb, text_len);
            print_hex(plaintext, text_len, 64);
        }

        printf("Block: %d bits | Key: %d bits | Cascade key between blocks\n",
               block_size_bits, key_size);

        int cipher_len = 0;
        double t0 = get_time();
        uint8_t *ciphertext = seq_encrypt(&cipher, plaintext, text_len, &cipher_len);
        double enc_time = get_time() - t0;

        printf("\nEncrypted (%d bytes):\n", cipher_len);
        print_hex(ciphertext, cipher_len, 64);

        int dec_len = 0;
        t0 = get_time();
        uint8_t *decrypted = seq_decrypt(&cipher, ciphertext, cipher_len, &dec_len);
        double dec_time = get_time() - t0;

        if (mode == 0) printf("\nDecrypted text: %.*s\n", dec_len, decrypted);
        else { printf("\nDecrypted (%d bytes), first 64:\n", dec_len); print_hex(decrypted, dec_len, 64); }

        printf("\nEncryption time: %.6f s | Decryption time: %.6f s\n", enc_time, dec_time);
        if (text_len > 0) printf("Throughput: %.2f MB/s\n", (text_len/1048576.0)/enc_time);

        if (dec_len == text_len && memcmp(plaintext, decrypted, (size_t)text_len) == 0)
            printf("✓ Success: Decrypted data matches original!\n");
        else
            printf("✗ Error: Decrypted data does NOT match original!\n");

        free(plaintext); free(ciphertext); free(decrypted);

    /* ── task 1: statistical tests ───────────────────────────────────────── */
    } else if (task == 1) {
        printf("========================================\n");
        printf("WBC0 Original - Statistical Analysis\n");
        printf("========================================\n");
        printf("Data: %d KB | Block: %d bits | Key: %d bits | Avalanche runs: %d | Seed: %u\n",
               data_kb, block_size_bits, key_size, avalanche_runs, seed);

        int data_size = data_kb * 1024;
        uint8_t *test_data = generate_random_bytes(data_size);

        int cipher_len = 0;
        printf("Encrypting...\n");
        double t0 = get_time();
        uint8_t *ciphertext = seq_encrypt(&cipher, test_data, data_size, &cipher_len);
        double enc_time = get_time() - t0;
        printf("Encryption: %.3f s | Throughput: %.2f MB/s\n\n",
               enc_time, (data_size/1048576.0)/enc_time);

        printf("Statistical Tests Results:\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        double entropy = shannon_entropy(ciphertext, cipher_len);
        printf("1. Shannon Entropy: %.4f bits/byte (expected ~7.9-8.0)\n", entropy);
        printf("   %s\n\n", entropy >= 7.9 ? "✓ Good" : "⚠ Low entropy");

        double fmean, fstd, fchi;
        frequency_test(ciphertext, cipher_len, &fmean, &fstd, &fchi);
        printf("2. Frequency Test:\n   Mean: %.2f | StdDev: %.2f | Chi²: %.2f\n",
               fmean, fstd, fchi);
        printf("   %s\n\n", fchi < 293.0 ? "✓ Good distribution" : "⚠ May not be uniform");

        double av[3];
        avalanche_test(&cipher, avalanche_runs, av);
        printf("3. Avalanche Effect: avg=%.2f%% min=%.2f%% max=%.2f%% (exp ~50%%)\n",
               av[0], av[1], av[2]);
        printf("   %s\n\n",
               (av[0]>=45.0 && av[0]<=55.0) ? "✓ Good avalanche" : "⚠ Weak avalanche");
        per_block_avalanche(&cipher, test_data, data_size);
        printf("\n");

        int tlen = data_size < cipher_len ? data_size : cipher_len;
        double corr = correlation_test(test_data, ciphertext, tlen);
        printf("4. Correlation: %.6f (exp close to 0)\n", corr);
        printf("   %s\n\n", fabs(corr) < 0.1 ? "✓ Low correlation" : "⚠ High correlation");

        double df[3];
        differential_test(&cipher, 50, df);
        printf("5. Differential Test (key sensitivity): avg=%.2f%% min=%.2f%% max=%.2f%%\n",
               df[0], df[1], df[2]);
        printf("   %s\n",
               (df[0]>=45.0 && df[0]<=55.0) ? "✓ Good key sensitivity" : "⚠ Weak key sensitivity");

        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        free(test_data); free(ciphertext);

    /* ── task 2: operations table ────────────────────────────────────────── */
    } else if (task == 2) {
        print_key_hex(key, key_len);
        print_key_operation_mapping(&cipher, 32);
        print_operations_table(&cipher);
    }

    wbc1_original_free(&cipher);
    free(key);
    return 0;
}
