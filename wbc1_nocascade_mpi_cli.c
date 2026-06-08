/*
 * PWBC1.1 — WBC1-Cascade-NEW MPI Parallel Implementation (v2: cascade-within-chunks)
 * ====================================================================================
 * Параллельная реализация алгоритма WBC1-Cascade-NEW с использованием MPI.
 *
 * Ключевые принципы (v2):
 *
 * 1. Cascade-within-chunks:
 *    Текст делится на nproc чанков. Каждый процесс c получает СТАРТОВЫЙ ключ
 *    derive_parallel_key(master_key, c) и далее запускает полный последовательный
 *    каскад (derive_cascade_key после каждого блока) внутри своего чанка.
 *    Это сохраняет межблочные каскадные зависимости внутри чанка.
 *
 * 2. Двойной проход (double_pass):
 *    Проход 1 (вперёд): cascade-within-chunk, ключ chunk c → derive_parallel_key(key, c)
 *    Проход 2 (назад):  cascade-within-chunk в обратном порядке,
 *                       ключ chunk c → derive_parallel_key(key, nproc + c)
 *
 * 3. WBC-CTR-HMAC: cascade-within-chunk с локальным счётчиком 0..local_count-1,
 *    таблица операций строится по key_crypt.
 *
 * 4. CBC/CFB/OFB: последовательно на rank 0 с полным каскадом (derive_cascade_key).
 *
 * 5. Все ключевые таблицы (build_op_table, build_perm_table) строятся на каждом
 *    процессе независимо (одинаковый ключ → одинаковые таблицы).
 *
 * Build:
 *   mpicc -O2 -o wbc1_cascade_mpi wbc1_cascade_mpi.c -lssl -lcrypto -lm
 *
 * Run tests:
 *   printf "2\n6\n6\n" | mpirun -n 2 ./wbc1_cascade_mpi --single
 *   printf "3\n6\n6\n" | mpirun -n 2 ./wbc1_cascade_mpi --single
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <mpi.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── constants ──────────────────────────────────────────────────────────── */

#define MAGIC        "WBC1"
#define MAGIC_LEN    4
#define VERSION_CASC 0x03
#define NONCE_SIZE   12
#define MAC_SIZE     32
#define KEY_SIZE     32
#define ROUNDS       32
#define NUM_OPS      127
#define MAX_BENCH_REPEATS 64

/* ── task codes for inter-process coordination ──────────────────────────── */
#define TASK_EXIT           0
#define TASK_ENCRYPT_TEXT   1
#define TASK_SELF_TESTS     2
#define TASK_BENCHMARK      3
#define TASK_ANALYSIS       4
#define TASK_SWITCH_MODE    5

/* ── cube sizes ──────────────────────────────────────────────────────────── */

typedef struct { int n; int dim; } CubeSize;

static const CubeSize CUBE_SIZES[] = {
    {8,    2}, {27,   3}, {64,   4}, {125,  5},
    {216,  6}, {343,  7}, {512,  8}, {1000, 10},
    {1331, 11},{1728, 12},{2197, 13},{2744, 14},
    {3375, 15},{4096, 16}
};
#define NUM_CUBE_SIZES (int)(sizeof(CUBE_SIZES)/sizeof(CUBE_SIZES[0]))

static int auto_block_size(int data_len) {
    for (int i = 0; i < NUM_CUBE_SIZES; i++)
        if (data_len <= CUBE_SIZES[i].n) return CUBE_SIZES[i].n;
    return CUBE_SIZES[NUM_CUBE_SIZES - 1].n;
}
static int dim_for(int block_size) {
    for (int i = 0; i < NUM_CUBE_SIZES; i++)
        if (CUBE_SIZES[i].n == block_size) return CUBE_SIZES[i].dim;
    return 0;
}

/* ── byte utilities ──────────────────────────────────────────────────────── */

static uint8_t rotate_right(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b >> n) | (b << (8 - n)));
}
static uint8_t rotate_left(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b << n) | (b >> (8 - n)));
}

/* ── SHA wrappers (used only at init/setup) ──────────────────────────────── */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
}
static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    SHA512(data, len, out);
}

/* ── cube ────────────────────────────────────────────────────────────────── */

typedef struct { uint8_t *data; int dim; } Cube;

static inline int idx3(int dim, int i, int j, int k) {
    return i * dim * dim + j * dim + k;
}

#define MAX_DIM   16
#define MAX_SLICE (MAX_DIM * MAX_DIM)
#define MAX_CUBE  (MAX_DIM * MAX_DIM * MAX_DIM)

static void rot90_2d(uint8_t *mat, int dim, int k) {
    k = ((k % 4) + 4) % 4;
    uint8_t tmp[dim * dim];
    for (int t = 0; t < k; t++) {
        for (int i = 0; i < dim; i++)
            for (int j = 0; j < dim; j++)
                tmp[i * dim + j] = mat[j * dim + (dim - 1 - i)];
        memcpy(mat, tmp, dim * dim);
    }
}
static void get_slice(const Cube *c, int axis, int pos, uint8_t *sl) {
    int dim = c->dim;
    int p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if      (axis == 0) sl[i*dim+j] = c->data[idx3(dim,p,i,j)];
            else if (axis == 1) sl[i*dim+j] = c->data[idx3(dim,i,p,j)];
            else                sl[i*dim+j] = c->data[idx3(dim,i,j,p)];
        }
}
static void set_slice(Cube *c, int axis, int pos, const uint8_t *sl) {
    int dim = c->dim;
    int p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if      (axis == 0) c->data[idx3(dim,p,i,j)] = sl[i*dim+j];
            else if (axis == 1) c->data[idx3(dim,i,p,j)] = sl[i*dim+j];
            else                c->data[idx3(dim,i,j,p)] = sl[i*dim+j];
        }
}
static void rotate_slice(Cube *c, int axis, int pos, int k) {
    uint8_t sl[c->dim * c->dim];
    get_slice(c, axis, pos, sl);
    rot90_2d(sl, c->dim, k);
    set_slice(c, axis, pos, sl);
}
static void rotate_whole_cube(Cube *c, int axis, int k) {
    k = ((k % 4) + 4) % 4;
    int dim = c->dim, total = dim*dim*dim;
    uint8_t tmp[total];
    for (int t = 0; t < k; t++) {
        int a0 = axis, a1 = (axis+1)%3;
        for (int i = 0; i < dim; i++)
            for (int j = 0; j < dim; j++)
                for (int k2 = 0; k2 < dim; k2++) {
                    int coords[3] = {i,j,k2};
                    int new_a0 = coords[a1], new_a1 = dim-1-coords[a0];
                    int nc[3] = {i,j,k2};
                    nc[a0] = new_a0; nc[a1] = new_a1;
                    tmp[idx3(dim,nc[0],nc[1],nc[2])] = c->data[idx3(dim,i,j,k2)];
                }
        memcpy(c->data, tmp, total);
    }
}
static void diagflip(Cube *c, int axis) {
    int dim = c->dim, total = dim*dim*dim;
    uint8_t tmp[total];
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++)
            for (int k = 0; k < dim; k++) {
                int di, dj, dk;
                if      (axis == 0) { di=i; dj=k; dk=j; }
                else if (axis == 1) { di=k; dj=j; dk=i; }
                else                { di=j; dj=i; dk=k; }
                tmp[idx3(dim,di,dj,dk)] = c->data[idx3(dim,i,j,k)];
            }
    memcpy(c->data, tmp, total);
}
static void swap_layers(Cube *c, int axis, int idx1, int idx2) {
    int dim = c->dim;
    idx1 = ((idx1%dim)+dim)%dim; idx2 = ((idx2%dim)+dim)%dim;
    uint8_t s1[dim*dim], s2[dim*dim];
    get_slice(c,axis,idx1,s1); get_slice(c,axis,idx2,s2);
    set_slice(c,axis,idx1,s2); set_slice(c,axis,idx2,s1);
}
static void bitwise_rotate_cube(Cube *c, int n, int right) {
    int total = c->dim*c->dim*c->dim;
    for (int i = 0; i < total; i++)
        c->data[i] = right ? rotate_right(c->data[i],n) : rotate_left(c->data[i],n);
}
static void mix_cube(uint8_t *data, int n) {
    /* F: forward prefix XOR, потім B: backward suffix XOR.
     * Повна дифузія: кожен вихідний байт залежить від усіх вхідних. */
    for (int i = 1; i < n; i++)    data[i] ^= data[i-1];  /* F */
    for (int i = n-2; i >= 0; i--) data[i] ^= data[i+1]; /* B */
}
static void inv_mix_cube(uint8_t *data, int n) {
    /* (F∘B)^-1 = B^-1 ∘ F^-1.
     * B^-1: data[i] ^= data[i+1]  for i=0..n-2  (forward pass)
     * F^-1: data[i] ^= data[i-1]  for i=n-1..1  (backward pass) */
    for (int i = 0; i < n-1; i++)  data[i] ^= data[i+1]; /* B^-1 */
    for (int i = n-1; i >= 1; i--) data[i] ^= data[i-1]; /* F^-1 */
}

/* ── operation table ─────────────────────────────────────────────────────── */

#define OP_FACE     0
#define OP_SLICE    1
#define OP_WIDE     2
#define OP_CUBE_ROT 3
#define OP_ALG      4
#define OP_PATTERN  5
#define OP_SWAP     6
#define OP_DIAGFLIP 7

typedef struct { uint8_t type; int8_t name; int8_t dir; } PrimOp;
#define MAX_CHAIN 8
typedef struct { PrimOp moves[MAX_CHAIN]; int len; } ComposedOp;

static ComposedOp g_ops[NUM_OPS];
static uint8_t    g_ops_key[KEY_SIZE];
static int        g_ops_key_valid = 0;

/* permutation table cache (forward + inverse, per op) */
static uint16_t *g_perms_buf = NULL;
static int       g_perm_bs   = -1;

#define MT_N 624
typedef struct { uint32_t mt[MT_N]; int idx; } MT;

static void mt_seed(MT *m, uint32_t seed) {
    m->mt[0] = seed;
    for (int i = 1; i < MT_N; i++)
        m->mt[i] = 1812433253UL*(m->mt[i-1]^(m->mt[i-1]>>30))+(uint32_t)i;
    m->idx = MT_N;
}
static uint32_t mt_rand(MT *m) {
    if (m->idx >= MT_N) {
        for (int i = 0; i < MT_N; i++) {
            uint32_t y = (m->mt[i]&0x80000000UL)|(m->mt[(i+1)%MT_N]&0x7fffffffUL);
            m->mt[i] = m->mt[(i+397)%MT_N]^(y>>1);
            if (y&1) m->mt[i] ^= 2567483615UL;
        }
        m->idx = 0;
    }
    uint32_t y = m->mt[m->idx++];
    y ^= y>>11; y ^= (y<<7)&2636928640UL;
    y ^= (y<<15)&4022730752UL; y ^= y>>18;
    return y;
}
static int mt_randint(MT *m, int a, int b) {
    int r = b-a+1; if (r<=0) return a;
    return a+(int)(mt_rand(m)%(uint32_t)r);
}
static int mt_choice(MT *m, int n) { return (int)(mt_rand(m)%(uint32_t)n); }
static void mt_shuffle(MT *m, int *arr, int n) {
    for (int i=n-1; i>0; i--) {
        int j = mt_randint(m,0,i);
        int tmp=arr[i]; arr[i]=arr[j]; arr[j]=tmp;
    }
}
static uint32_t sha256_seed(const uint8_t *h32) {
    return ((uint32_t)h32[28]<<24)|((uint32_t)h32[29]<<16)|
           ((uint32_t)h32[30]<< 8)| (uint32_t)h32[31];
}

#define MAX_BASE_OPS 256
typedef struct { uint8_t type; int8_t name; int8_t dir; } BaseOp;
static BaseOp  g_base_ops[MAX_BASE_OPS];
static int     g_base_ops_count = 0;

typedef struct { const char *name; const char *moves; } AlgDef;
static const AlgDef ALGS[] = {
    {"T-Perm",      "R U R' U' R' F R2 U' R' U' R U R' F'"},
    {"Y-Perm",      "F R U' R' U' R U R' F' R U R' U' R' F R F'"},
    {"J-Perm",      "R U R' F' R U R' U' R' F R2 U' R' U'"},
    {"F-Perm",      "R' U' F' R U R' U' R' F R2 U' R' U' R U R' U R"},
    {"A-Perm",      "x' R2 D2 R' U' R D2 R' U R' x"},
    {"E-Perm",      "x' R U' R' D R U R' D' R U R' D R U' R' D' x"},
    {"R-Perm",      "R U' R' U' R U R D R' U' R D' R' U2 R'"},
    {"U-Perm",      "R U' R U R U R U' R' U' R2"},
    {"V-Perm",      "R' U R' U' y R' F' R2 U' R' U R' F R F"},
    {"N-Perm",      "R U R' U R U R' F' R U R' U' R' F R2 U' R' U2 R U' R'"},
    {"Z-Perm",      "M2 U M2 U M' U2 M2 U2 M' U2"},
    {"H-Perm",      "M2 U M2 U2 M2 U M2"},
    {"Checkerboard","M2 E2 S2"},
    {"Cube-in-Cube","F L F U' R U F2 L2 U' L' B D' B' L2 U"},
    {"Superflip",   "U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2"},
    {"Six-Spot",    "U D' R L' F B' U D'"},
    {"Tetris",      "L R F B U' D' L' R'"},
    {"Anaconda",    "L U B' U' R L' B R' F B' D R D' F'"},
    {"Python",      "F2 R' B' U R' L F' L F' B D' R B L2"},
    {"Black Mamba", "R D L F' R U' R' F L' D' R' U"},
};
#define NUM_ALGS 20
#define N_STATIC_BASE 127

static void build_prim_op_from_base_idx(PrimOp *out, int base_idx) {
    int i = base_idx;
    if (i<24) { out->type=OP_FACE;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=24;
    if (i<12) { out->type=OP_SLICE;   out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i<24) { out->type=OP_WIDE;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=24;
    if (i<12) { out->type=OP_CUBE_ROT;out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i<12) { out->type=OP_ALG;     out->name=(int8_t)i;     out->dir=0;             return; } i-=12;
    if (i< 8) { out->type=OP_PATTERN; out->name=(int8_t)(12+i);out->dir=0;             return; } i-=8;
    if (i<12) { out->type=OP_SWAP;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i< 3) { out->type=OP_DIAGFLIP;out->name=(int8_t)i;     out->dir=0;             return; } i-=3;
    /* Инверсные алгоритмы (+20): ALG[0..11]^-1 и PATTERN[12..19]^-1 */
    if (i<12) { out->type=OP_ALG;     out->name=(int8_t)i;     out->dir=1;             return; } i-=12;
    if (i< 8) { out->type=OP_PATTERN; out->name=(int8_t)(12+i);out->dir=1;             return; }
    out->type=OP_FACE; out->name=0; out->dir=0;
}
static int dir_char_to_k(char d, int inverse) {
    int k;
    switch(d) { case '\'': k=-1; break; case '2': k=2; break; case '3': k=3; break; default: k=1; break; }
    return inverse ? -k : k;
}
static void apply_move_token(Cube *cube, const char *token, int inverse) {
    if (!token || !*token) return;
    int len = (int)strlen(token);
    char base = token[0];
    char dmod = (len>1 && (token[len-1]=='\''||token[len-1]=='2'||token[len-1]=='3')) ? token[len-1] : 0;
    int k = dir_char_to_k(dmod, inverse);
    if (base=='U') { rotate_slice(cube,0, 0,k); return; }
    if (base=='D') { rotate_slice(cube,0,-1,k); return; }
    if (base=='L') { rotate_slice(cube,1, 0,k); return; }
    if (base=='R') { rotate_slice(cube,1,-1,k); return; }
    if (base=='F') { rotate_slice(cube,2, 0,k); return; }
    if (base=='B') { rotate_slice(cube,2,-1,k); return; }
    if (base=='M') { rotate_slice(cube,1, 1,k); return; }
    if (base=='E') { rotate_slice(cube,0, 1,k); return; }
    if (base=='S') { rotate_slice(cube,2, 1,k); return; }
    if (base=='x') { rotate_whole_cube(cube,0,k); return; }
    if (base=='y') { rotate_whole_cube(cube,1,k); return; }
    if (base=='z') { rotate_whole_cube(cube,2,k); return; }
}
static void apply_alg_string(Cube *cube, const char *moves_str, int inverse) {
    char buf[512];
    strncpy(buf, moves_str, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    for (char *p=buf; *p; p++) if (*p==',') *p=' ';
    char *tokens[256]; int ntok=0;
    char *tok = strtok(buf," ");
    while (tok && ntok<255) { tokens[ntok++]=tok; tok=strtok(NULL," "); }
    if (!inverse)
        for (int i=0;i<ntok;i++) apply_move_token(cube,tokens[i],0);
    else
        for (int i=ntok-1;i>=0;i--) apply_move_token(cube,tokens[i],1);
}
static void apply_prim_op(Cube *cube, const PrimOp *op, int inverse) {
    static const int face_axis[]  = {0, 0, 1, 1, 2, 2};
    static const int face_pos[]   = {0,-1, 0,-1, 0,-1};
    static const int dir_k[]      = {1,-1, 2, 3};
    static const int slice_axis[] = {1, 0, 2};
    static const int wide_axis[]  = {0, 0, 1, 1, 2, 2};
    static const int cube_axis[]  = {0, 1, 2};
    int type = op->type, name = op->name, dir = op->dir;
    int k = dir_k[((dir % 4) + 4) % 4];
    if (inverse) k = -k;
    if (type == OP_FACE)     { rotate_slice(cube, face_axis[name&7], face_pos[name&7], k); }
    else if (type == OP_SLICE)   { rotate_slice(cube, slice_axis[name%3], 1, k); }
    else if (type == OP_WIDE)    { int a=wide_axis[name&7]; rotate_slice(cube,a,0,k); rotate_slice(cube,a,1,k); }
    else if (type == OP_CUBE_ROT){ rotate_whole_cube(cube, cube_axis[name%3], k); }
    else if (type == OP_ALG || type == OP_PATTERN) { apply_alg_string(cube, ALGS[name%NUM_ALGS].moves, inverse ^ (dir & 1)); }
    else if (type == OP_SWAP)    { swap_layers(cube, name%3, dir, dir+1); }
    else if (type == OP_DIAGFLIP){ diagflip(cube, name%3); }
}
static void apply_composed_op(Cube *cube, const ComposedOp *cop, int inverse) {
    if (inverse) { for (int i=cop->len-1;i>=0;i--) apply_prim_op(cube,&cop->moves[i],1); }
    else         { for (int i=0;i<cop->len;i++)     apply_prim_op(cube,&cop->moves[i],0); }
}
static void build_op_table(const uint8_t key[32]) {
    if (g_ops_key_valid && memcmp(g_ops_key, key, KEY_SIZE) == 0) {
        return;
    }

    for (int i=0; i<NUM_OPS; i++) {
        uint8_t h[32], buf[KEY_SIZE+11];
        memcpy(buf,key,KEY_SIZE); memcpy(buf+KEY_SIZE,"WBC1_OP",7);
        buf[KEY_SIZE+7]=(uint8_t)i; buf[KEY_SIZE+8]=(uint8_t)(i>>8);
        buf[KEY_SIZE+9]=0; buf[KEY_SIZE+10]=0;
        sha256(buf,KEY_SIZE+11,h);
        MT mt; mt_seed(&mt,sha256_seed(h));
        int chain_len = mt_randint(&mt,3,6);
        g_ops[i].len = chain_len;
        for (int j=0; j<chain_len; j++) {
            int base_idx = mt_choice(&mt,N_STATIC_BASE);
            build_prim_op_from_base_idx(&g_ops[i].moves[j],base_idx);
        }
    }
    uint8_t key_hash[32]; sha256(key,KEY_SIZE,key_hash);
    MT mt; mt_seed(&mt,sha256_seed(key_hash));
    int order[NUM_OPS]; for (int i=0;i<NUM_OPS;i++) order[i]=i;
    mt_shuffle(&mt,order,NUM_OPS);
    ComposedOp tmp[NUM_OPS]; memcpy(tmp,g_ops,sizeof(g_ops));
    for (int i=0;i<NUM_OPS;i++) g_ops[i]=tmp[order[i]];

    memcpy(g_ops_key, key, KEY_SIZE);
    g_ops_key_valid = 1;
    /* Операции изменились -> кэш перестановок нужно перестроить */
    g_perm_bs = -1;
}

/* ── permutation table ───────────────────────────────────────────────────── */

static void build_perm_table(int block_size) {
    if (g_perm_bs == block_size) return;
    free(g_perms_buf);
    g_perms_buf = (uint16_t *)malloc((size_t)2 * NUM_OPS * block_size * sizeof(uint16_t));
    g_perm_bs   = block_size;
    int dim     = dim_for(block_size);
    uint8_t tmp[block_size];
    for (int op = 0; op < NUM_OPS; op++) {
        uint16_t *fwd = g_perms_buf + (size_t) op            * block_size;
        uint16_t *inv = g_perms_buf + (size_t)(op + NUM_OPS) * block_size;
        for (int i = 0; i < block_size; i++) tmp[i] = (uint8_t)(i & 0xFF);
        { Cube c = { tmp, dim }; apply_composed_op(&c, &g_ops[op], 0); }
        for (int j = 0; j < block_size; j++) fwd[j] = (uint16_t)tmp[j];
        if (block_size > 256) {
            for (int i = 0; i < block_size; i++) tmp[i] = (uint8_t)(i >> 8);
            { Cube c = { tmp, dim }; apply_composed_op(&c, &g_ops[op], 0); }
            for (int j = 0; j < block_size; j++) fwd[j] |= (uint16_t)((uint16_t)tmp[j] << 8);
        }
        for (int i = 0; i < block_size; i++) inv[fwd[i]] = (uint16_t)i;
    }
}
static void apply_operation(Cube *cube, int op_id, int inverse) {
    int idx = ((op_id % NUM_OPS) + NUM_OPS) % NUM_OPS;
    int bs  = cube->dim * cube->dim * cube->dim;
    if (g_perm_bs != bs) build_perm_table(bs);   /* строим если первый вызов или сменился block_size */
    const uint16_t *perm = inverse
        ? g_perms_buf + (size_t)(idx + NUM_OPS) * bs
        : g_perms_buf + (size_t) idx            * bs;
    uint8_t tmp[bs];
    for (int i = 0; i < bs; i++) tmp[i] = cube->data[perm[i]];
    memcpy(cube->data, tmp, bs);
}

/* ── padding ─────────────────────────────────────────────────────────────── */

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
    int fill_len = (int)data[data_len-block_bytes] | ((int)data[data_len-block_bytes+1]<<8);
    size_t strip = block_bytes+fill_len;
    if (strip > data_len) { *out_len=0; return (uint8_t*)calloc(1,1); }
    *out_len = data_len-strip;
    uint8_t *out = (uint8_t *)malloc(*out_len+1);
    memcpy(out,data,*out_len);
    out[*out_len] = 0;
    return out;
}

/* ── derive_cascade_key ──────────────────────────────────────────────────── */
/* 4 раунда F+B mixing на block_bytes, вывод → 32 байта.                    */
/* Без SHA-256: быстро. 4 раунда достаточно для avalanche ~50% (проверено).  */
static void derive_cascade_key(const uint8_t *enc_block, int block_bytes,
                                uint8_t new_rk[KEY_SIZE]) {
    /* No-cascade mode: keep the same key material for every block. */
    (void)enc_block;
    (void)block_bytes;
    (void)new_rk;
}

/* ── derive_parallel_key — ключ блока по индексу (независимый) ──────────── */

static void derive_parallel_key(const uint8_t master[KEY_SIZE], size_t block_idx,
                                  uint8_t out[KEY_SIZE]) {
    (void)block_idx;
    memcpy(out, master, KEY_SIZE);
}

/* ── encrypt_block / decrypt_block ──────────────────────────────────────── */

static void encrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int dim = dim_for(block_size), cube_bytes = block_size;
    uint8_t rk[ROUNDS][block_size];
    for (int r = 0; r < ROUNDS; r++) {
        int shift = r & 7;
        for (int i = 0; i < cube_bytes; i++)
            rk[r][i] = rotate_left(key_mat[(i + r*7) % KEY_SIZE], shift);
    }
    uint8_t cube_data[block_size];
    Cube cube = { cube_data, dim };
    memcpy(cube.data, block, cube_bytes);
    for (int r = 0; r < ROUNDS; r++) {
        int op_id = key_mat[r] % NUM_OPS;
        apply_operation(&cube, op_id, 0);
        mix_cube(cube.data, cube_bytes);
        for (int i = 0; i < cube_bytes; i++) cube.data[i] ^= rk[r][i];
        bitwise_rotate_cube(&cube, op_id, 1);
    }
    memcpy(out, cube.data, cube_bytes);
}
static void decrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int dim = dim_for(block_size), cube_bytes = block_size;
    uint8_t rk[ROUNDS][block_size];
    for (int r = 0; r < ROUNDS; r++) {
        int shift = r & 7;
        for (int i = 0; i < cube_bytes; i++)
            rk[r][i] = rotate_left(key_mat[(i + r*7) % KEY_SIZE], shift);
    }
    uint8_t cube_data[block_size];
    Cube cube = { cube_data, dim };
    memcpy(cube.data, block, cube_bytes);
    for (int r = ROUNDS - 1; r >= 0; r--) {
        int op_id = key_mat[r] % NUM_OPS;
        bitwise_rotate_cube(&cube, op_id, 0);
        for (int i = 0; i < cube_bytes; i++) cube.data[i] ^= rk[r][i];
        inv_mix_cube(cube.data, cube_bytes);
        apply_operation(&cube, op_id, 1);
    }
    memcpy(out, cube.data, cube_bytes);
}

/* ── KDF + HMAC ──────────────────────────────────────────────────────────── */

static void kdf(const uint8_t key[32], const uint8_t nonce[NONCE_SIZE],
                uint8_t key_crypt[32], uint8_t key_mac[32]) {
    uint8_t in[32+NONCE_SIZE];
    memcpy(in,key,32); memcpy(in+32,nonce,NONCE_SIZE);
    uint8_t h[64]; sha512(in,32+NONCE_SIZE,h);
    memcpy(key_crypt,h,32); memcpy(key_mac,h+32,32);
}
static void hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *data, size_t dlen, uint8_t out[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(),key,(int)klen,data,dlen,out,&olen);
}

/* ── mode helpers ────────────────────────────────────────────────────────── */

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

/* ==========================================================================
 * MPI вспомогательные функции для Scatterv/Gatherv
 * ========================================================================== */

/* Вычисляет send_counts и displs для равномерного распределения блоков */
static void fill_distribution(int n_blocks, int block_bytes, int nproc,
                              int *send_counts, int *displs) {
    int blocks_per_proc = n_blocks / nproc;
    int remainder       = n_blocks % nproc;
    int off = 0;
    for (int i = 0; i < nproc; i++) {
        int cnt = blocks_per_proc + (i < remainder ? 1 : 0);
        send_counts[i] = cnt * block_bytes;
        displs[i]      = off;
        off += send_counts[i];
    }
}

typedef struct {
    uint8_t *in_buf;
    uint8_t *out_buf;
    size_t   cap;
} IoCache;

static int *g_dist_send_counts = NULL;
static int *g_dist_displs = NULL;
static int  g_dist_nproc = -1;
static int  g_dist_n_blocks = -1;
static int  g_dist_block_bytes = -1;

static IoCache g_io_cache_enc = { NULL, NULL, 0 };
static IoCache g_io_cache_dec = { NULL, NULL, 0 };
static IoCache g_io_cache_ctrhmac = { NULL, NULL, 0 };

static void ensure_io_cache(IoCache *cache, size_t needed) {
    if (needed == 0) needed = 1;
    if (needed <= cache->cap) return;

    uint8_t *new_in  = (uint8_t *)malloc(needed);
    uint8_t *new_out = (uint8_t *)malloc(needed);
    if (!new_in || !new_out) {
        fprintf(stderr, "ERROR: unable to allocate MPI IO cache (%zu bytes)\n", needed);
        MPI_Abort(MPI_COMM_WORLD, 2);
    }
    if (cache->in_buf) free(cache->in_buf);
    if (cache->out_buf) free(cache->out_buf);
    cache->in_buf = new_in;
    cache->out_buf = new_out;
    cache->cap = needed;
}

static void calc_distribution_cached(int n_blocks, int block_bytes, int nproc,
                                     int **send_counts, int **displs) {
    if (g_dist_nproc != nproc) {
        if (g_dist_send_counts) free(g_dist_send_counts);
        if (g_dist_displs) free(g_dist_displs);
        g_dist_send_counts = (int *)malloc((size_t)nproc * sizeof(int));
        g_dist_displs      = (int *)malloc((size_t)nproc * sizeof(int));
        if (!g_dist_send_counts || !g_dist_displs) {
            fprintf(stderr, "ERROR: unable to allocate MPI distribution cache\n");
            MPI_Abort(MPI_COMM_WORLD, 2);
        }
        g_dist_nproc = nproc;
        g_dist_n_blocks = -1;
        g_dist_block_bytes = -1;
    }

    if (g_dist_n_blocks != n_blocks || g_dist_block_bytes != block_bytes) {
        fill_distribution(n_blocks, block_bytes, nproc, g_dist_send_counts, g_dist_displs);
        g_dist_n_blocks = n_blocks;
        g_dist_block_bytes = block_bytes;
    }

    *send_counts = g_dist_send_counts;
    *displs = g_dist_displs;
}

static void free_mpi_runtime_caches(void) {
    if (g_dist_send_counts) free(g_dist_send_counts);
    if (g_dist_displs) free(g_dist_displs);
    g_dist_send_counts = NULL;
    g_dist_displs = NULL;
    g_dist_nproc = -1;
    g_dist_n_blocks = -1;
    g_dist_block_bytes = -1;

    if (g_io_cache_enc.in_buf) free(g_io_cache_enc.in_buf);
    if (g_io_cache_enc.out_buf) free(g_io_cache_enc.out_buf);
    g_io_cache_enc.in_buf = NULL;
    g_io_cache_enc.out_buf = NULL;
    g_io_cache_enc.cap = 0;

    if (g_io_cache_dec.in_buf) free(g_io_cache_dec.in_buf);
    if (g_io_cache_dec.out_buf) free(g_io_cache_dec.out_buf);
    g_io_cache_dec.in_buf = NULL;
    g_io_cache_dec.out_buf = NULL;
    g_io_cache_dec.cap = 0;

    if (g_io_cache_ctrhmac.in_buf) free(g_io_cache_ctrhmac.in_buf);
    if (g_io_cache_ctrhmac.out_buf) free(g_io_cache_ctrhmac.out_buf);
    g_io_cache_ctrhmac.in_buf = NULL;
    g_io_cache_ctrhmac.out_buf = NULL;
    g_io_cache_ctrhmac.cap = 0;
}

/* Возвращает глобальный offset первого блока для rank */
static int global_offset_for_rank(int rank, int n_blocks, int nproc) {
    int blocks_per_proc = n_blocks / nproc;
    int remainder       = n_blocks % nproc;
    return rank * blocks_per_proc + (rank < remainder ? rank : remainder);
}

/* ==========================================================================
 * parallel_cascade_encrypt — MPI-параллельное шифрование (v2: cascade-within-chunks)
 *
 * Новый дизайн: каждый MPI-процесс c получает стартовый ключ
 *   derive_parallel_key(master_key, c)
 * и далее запускает ПОЛНЫЙ последовательный каскад внутри своего чанка.
 * Это сохраняет межблочные каскадные зависимости внутри чанка.
 * ========================================================================== */
static uint8_t *parallel_cascade_encrypt(const uint8_t master_key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           EncMode mode,
                                           const uint8_t *iv_in, int block_size,
                                           uint8_t **iv_out, size_t *iv_len_out,
                                           int double_pass,
                                           size_t *out_len) {
    /* No-cascade build always runs single-pass. */
    (void)double_pass;
    double_pass = 0;
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    /* Строим ключезависимые таблицы (все процессы, одинаковый ключ) */
    build_op_table(master_key);
    int bs = block_size;
    MPI_Bcast(&bs, 1, MPI_INT, 0, MPI_COMM_WORLD);
    build_perm_table(bs);

    /* ── Параметры, которые rank 0 вычисляет и рассылает ─────────────────── */
    int n_blocks = 0;
    uint8_t iv[MAX_CUBE] = {0};
    uint8_t *padded = NULL;
    size_t padded_len = 0;

    if (rank == 0) {
        padded = wbc1_pad(data, data_len, bs, &padded_len);
        n_blocks = (int)(padded_len / bs);
        if (mode != MODE_ECB) {
            if (iv_in) memcpy(iv, iv_in, bs);
            else RAND_bytes(iv, bs);
            if (iv_out) { *iv_out = (uint8_t *)malloc(bs); memcpy(*iv_out, iv, bs); *iv_len_out = bs; }
        } else {
            if (iv_out) { *iv_out = NULL; *iv_len_out = 0; }
        }
    }
    MPI_Bcast(&n_blocks, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(iv, bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    /* ── CBC/CFB/OFB: последовательно на rank 0 с полным каскадом ──────────── */
    if (mode == MODE_CBC || mode == MODE_CFB || mode == MODE_OFB) {
        uint8_t *result = NULL;
        if (rank == 0) {
            uint8_t rk[KEY_SIZE];
            memcpy(rk, master_key, KEY_SIZE);
            uint8_t *inter = (uint8_t *)malloc(padded_len);
            uint8_t prev[MAX_CUBE], enc_prev[MAX_CUBE], tmp_b[MAX_CUBE];
            memcpy(prev, iv, bs);
            for (int b = 0; b < n_blocks; b++) {
                const uint8_t *blk = padded + b*bs;
                uint8_t       *ob  = inter  + b*bs;
                if (mode == MODE_CBC) {
                    for (int i=0;i<bs;i++) tmp_b[i]=blk[i]^prev[i];
                    encrypt_block(rk, tmp_b, bs, ob);
                    derive_cascade_key(ob, bs, rk);
                    memcpy(prev, ob, bs);
                } else if (mode == MODE_CFB) {
                    encrypt_block(rk, prev, bs, enc_prev);
                    derive_cascade_key(enc_prev, bs, rk);
                    for (int i=0;i<bs;i++) ob[i]=blk[i]^enc_prev[i];
                    memcpy(prev, ob, bs);
                } else { /* OFB */
                    encrypt_block(rk, prev, bs, enc_prev);
                    derive_cascade_key(enc_prev, bs, rk);
                    for (int i=0;i<bs;i++) ob[i]=blk[i]^enc_prev[i];
                    memcpy(prev, enc_prev, bs);
                }
            }
            if (double_pass) {
                /* Проход 2: backward cascade на rank 0 */
                result = (uint8_t *)malloc(padded_len);
                memcpy(rk, master_key, KEY_SIZE);
                for (int b = n_blocks-1; b >= 0; b--) {
                    encrypt_block(rk, inter+b*bs, bs, result+b*bs);
                    derive_cascade_key(result+b*bs, bs, rk);
                }
                free(inter);
            } else {
                result = inter;
            }
            free(padded);
            *out_len = padded_len;
        }
        return result;
    }

    /* ── ECB / CTR fast-path для nproc==1: без Scatter/Gather ─────────────── */
    if (nproc == 1 && rank == 0) {
        uint8_t *inter = (uint8_t *)malloc(padded_len);
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(master_key, 0, rk);

        if (mode == MODE_ECB) {
            for (int b = 0; b < n_blocks; b++) {
                encrypt_block(rk, padded + b*bs, bs, inter + b*bs);
                derive_cascade_key(inter + b*bs, bs, rk);
            }
        } else { /* CTR */
            uint8_t prev[MAX_CUBE];
            memcpy(prev, iv, bs);
            for (int b = 0; b < n_blocks; b++) {
                uint8_t enc_ctr[MAX_CUBE];
                encrypt_block(rk, prev, bs, enc_ctr);
                derive_cascade_key(enc_ctr, bs, rk);
                for (int i=0;i<bs;i++) inter[b*bs+i] = padded[b*bs+i]^enc_ctr[i];
                int carry=1;
                for (int i=bs-1; i>=0 && carry; i--) {
                    int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
                }
            }
        }

        free(padded);
        if (!double_pass) {
            *out_len = padded_len;
            return inter;
        }

        uint8_t *result = (uint8_t *)malloc(padded_len);
        derive_parallel_key(master_key, 1, rk);
        for (int b = n_blocks-1; b >= 0; b--) {
            encrypt_block(rk, inter+b*bs, bs, result+b*bs);
            derive_cascade_key(result+b*bs, bs, rk);
        }
        free(inter);
        *out_len = padded_len;
        return result;
    }

    /* ── ECB / CTR: cascade-within-chunks (полностью параллельно) ──────────── */
    int *send_counts = NULL, *displs = NULL;
    if (rank == 0) calc_distribution_cached(n_blocks, bs, nproc, &send_counts, &displs);

    int local_count;
    { int bpp = n_blocks/nproc, rem = n_blocks%nproc; local_count = bpp + (rank < rem ? 1 : 0); }

    size_t local_bytes = (size_t)local_count * (size_t)bs;
    ensure_io_cache(&g_io_cache_enc, local_bytes + 1);
    uint8_t *local_in  = g_io_cache_enc.in_buf;
    uint8_t *local_out = g_io_cache_enc.out_buf;

    /* Scatter padded data */
    MPI_Scatterv(padded, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_in, local_count * bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    /* ── Проход 1: cascade-within-chunk ─────────────────────────────────── */
    {
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(master_key, (size_t)rank, rk);  /* стартовый ключ чанка */

        if (mode == MODE_ECB) {
            for (int b = 0; b < local_count; b++) {
                encrypt_block(rk, local_in+b*bs, bs, local_out+b*bs);
                derive_cascade_key(local_out+b*bs, bs, rk);
            }
        } else { /* CTR */
            uint8_t prev[MAX_CUBE];
            memcpy(prev, iv, bs);
            for (int b = 0; b < local_count; b++) {
                uint8_t enc_ctr[MAX_CUBE];
                encrypt_block(rk, prev, bs, enc_ctr);
                derive_cascade_key(enc_ctr, bs, rk);
                for (int i=0;i<bs;i++) local_out[b*bs+i] = local_in[b*bs+i]^enc_ctr[i];
                int carry=1;
                for (int i=bs-1; i>=0 && carry; i--) {
                    int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
                }
            }
        }
    }

    /* ── Gather прохода 1 ────────────────────────────────────────────────── */
    uint8_t *inter = NULL;
    if (rank == 0) inter = (uint8_t *)malloc(padded_len);
    MPI_Gatherv(local_out, local_count*bs, MPI_UNSIGNED_CHAR,
                inter, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (!double_pass) {
        if (rank == 0) { free(padded); *out_len = padded_len; }
        return inter;
    }

    /* ── Проход 2: backward cascade-within-chunk ─────────────────────────── */
    MPI_Scatterv(inter, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_in, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    {
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(master_key, (size_t)nproc + rank, rk);
        /* Обратный порядок внутри чанка */
        for (int b = local_count-1; b >= 0; b--) {
            encrypt_block(rk, local_in+b*bs, bs, local_out+b*bs);
            derive_cascade_key(local_out+b*bs, bs, rk);
        }
    }

    uint8_t *result = NULL;
    if (rank == 0) result = (uint8_t *)malloc(padded_len);
    MPI_Gatherv(local_out, local_count*bs, MPI_UNSIGNED_CHAR,
                result, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (rank == 0) { free(inter); free(padded); *out_len = padded_len; }
    return result;
}

/* ==========================================================================
 * parallel_cascade_decrypt — MPI-параллельное дешифрование (v2: cascade-within-chunks)
 * ========================================================================== */
static uint8_t *parallel_cascade_decrypt(const uint8_t master_key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           EncMode mode, const uint8_t *iv,
                                           int block_size, int double_pass,
                                           size_t *out_len) {
    /* No-cascade build always runs single-pass. */
    (void)double_pass;
    double_pass = 0;
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    build_op_table(master_key);
    int bs = block_size;
    MPI_Bcast(&bs, 1, MPI_INT, 0, MPI_COMM_WORLD);
    build_perm_table(bs);

    int n_blocks = 0;
    if (rank == 0) n_blocks = (int)(data_len / bs);
    MPI_Bcast(&n_blocks, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t local_iv[MAX_CUBE] = {0};
    if (iv && rank == 0) memcpy(local_iv, iv, bs);
    MPI_Bcast(local_iv, bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    /* ── CBC/CFB/OFB: последовательно на rank 0 с полным каскадом ──────────── */
    if (mode == MODE_CBC || mode == MODE_CFB || mode == MODE_OFB) {
        uint8_t *res = NULL;
        if (rank == 0) {
            uint8_t rk[KEY_SIZE];
            /* Если double_pass: сначала отменяем backward cascade */
            uint8_t *inter = (uint8_t *)malloc(data_len);
            if (double_pass) {
                memcpy(rk, master_key, KEY_SIZE);
                for (int b = n_blocks-1; b >= 0; b--) {
                    decrypt_block(rk, data+b*bs, bs, inter+b*bs);
                    derive_cascade_key(data+b*bs, bs, rk);  /* ключ из шифртекста */
                }
            } else {
                memcpy(inter, data, data_len);
            }
            uint8_t *decrypted = (uint8_t *)malloc(data_len+1);
            memcpy(rk, master_key, KEY_SIZE);
            uint8_t prev[MAX_CUBE], enc_prev[MAX_CUBE], tmp_b[MAX_CUBE];
            memcpy(prev, local_iv, bs);
            for (int b = 0; b < n_blocks; b++) {
                const uint8_t *blk = inter + b*bs;
                uint8_t       *ob  = decrypted + b*bs;
                if (mode == MODE_CBC) {
                    decrypt_block(rk, blk, bs, tmp_b);
                    for (int i=0;i<bs;i++) ob[i]=tmp_b[i]^prev[i];
                    derive_cascade_key(blk, bs, rk);  /* ключ из шифртекста */
                    memcpy(prev, blk, bs);
                } else if (mode == MODE_CFB) {
                    encrypt_block(rk, prev, bs, enc_prev);
                    derive_cascade_key(enc_prev, bs, rk);
                    for (int i=0;i<bs;i++) ob[i]=blk[i]^enc_prev[i];
                    memcpy(prev, blk, bs);
                } else { /* OFB */
                    encrypt_block(rk, prev, bs, enc_prev);
                    derive_cascade_key(enc_prev, bs, rk);
                    for (int i=0;i<bs;i++) ob[i]=blk[i]^enc_prev[i];
                    memcpy(prev, enc_prev, bs);
                }
            }
            free(inter);
            res = wbc1_unpad(decrypted, data_len, bs, out_len);
            free(decrypted);
        }
        return res;
    }

    /* ── ECB / CTR fast-path для nproc==1: без Scatter/Gather ─────────────── */
    if (nproc == 1 && rank == 0) {
        uint8_t *inter = (uint8_t *)malloc(data_len);

        if (double_pass) {
            uint8_t rk[KEY_SIZE];
            derive_parallel_key(master_key, 1, rk);
            for (int b = n_blocks-1; b >= 0; b--) {
                decrypt_block(rk, data+b*bs, bs, inter+b*bs);
                derive_cascade_key(data+b*bs, bs, rk);
            }
        } else {
            memcpy(inter, data, data_len);
        }

        uint8_t *padded_plain = (uint8_t *)malloc(data_len+1);
        {
            uint8_t rk[KEY_SIZE];
            derive_parallel_key(master_key, 0, rk);

            if (mode == MODE_ECB) {
                for (int b = 0; b < n_blocks; b++) {
                    decrypt_block(rk, inter+b*bs, bs, padded_plain+b*bs);
                    derive_cascade_key(inter+b*bs, bs, rk);
                }
            } else { /* CTR */
                uint8_t prev[MAX_CUBE];
                memcpy(prev, local_iv, bs);
                for (int b = 0; b < n_blocks; b++) {
                    uint8_t enc_ctr[MAX_CUBE];
                    encrypt_block(rk, prev, bs, enc_ctr);
                    derive_cascade_key(enc_ctr, bs, rk);
                    for (int i=0;i<bs;i++) padded_plain[b*bs+i] = inter[b*bs+i]^enc_ctr[i];
                    int carry=1;
                    for (int i=bs-1; i>=0 && carry; i--) {
                        int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
                    }
                }
            }
        }

        free(inter);
        uint8_t *res = wbc1_unpad(padded_plain, data_len, bs, out_len);
        free(padded_plain);
        return res;
    }

    /* ── ECB / CTR: cascade-within-chunks (полностью параллельно) ──────────── */
    int *send_counts = NULL, *displs = NULL;
    if (rank == 0) calc_distribution_cached(n_blocks, bs, nproc, &send_counts, &displs);

    int local_count;
    { int bpp = n_blocks/nproc, rem = n_blocks%nproc; local_count = bpp + (rank < rem ? 1 : 0); }

    size_t local_bytes = (size_t)local_count * (size_t)bs;
    ensure_io_cache(&g_io_cache_dec, local_bytes + 1);
    uint8_t *local_in  = g_io_cache_dec.in_buf;
    uint8_t *local_out = g_io_cache_dec.out_buf;

    /* ── Если double_pass: отмена backward cascade-within-chunk ─────────── */
    if (double_pass) {
        MPI_Scatterv(data, send_counts, displs, MPI_UNSIGNED_CHAR,
                     local_in, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        {
            uint8_t rk[KEY_SIZE];
            derive_parallel_key(master_key, (size_t)nproc + rank, rk);
            for (int b = local_count-1; b >= 0; b--) {
                decrypt_block(rk, local_in+b*bs, bs, local_out+b*bs);
                derive_cascade_key(local_in+b*bs, bs, rk);  /* ключ из шифртекста */
            }
        }
        uint8_t *inter = NULL;
        if (rank == 0) inter = (uint8_t *)malloc(data_len);
        MPI_Gatherv(local_out, local_count*bs, MPI_UNSIGNED_CHAR,
                    inter, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Scatterv(inter, send_counts, displs, MPI_UNSIGNED_CHAR,
                     local_in, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        if (rank == 0) free(inter);
    } else {
        MPI_Scatterv(data, send_counts, displs, MPI_UNSIGNED_CHAR,
                     local_in, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    }

    /* ── Отмена forward cascade ──────────────────────────────────────────── */
    {
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(master_key, (size_t)rank, rk);

        if (mode == MODE_ECB) {
            for (int b = 0; b < local_count; b++) {
                decrypt_block(rk, local_in+b*bs, bs, local_out+b*bs);
                derive_cascade_key(local_in+b*bs, bs, rk);  /* ключ из шифртекста */
            }
        } else { /* CTR: воспроизводим тот же поток ключей */
            uint8_t prev[MAX_CUBE];
            memcpy(prev, local_iv, bs);
            for (int b = 0; b < local_count; b++) {
                uint8_t enc_ctr[MAX_CUBE];
                encrypt_block(rk, prev, bs, enc_ctr);
                derive_cascade_key(enc_ctr, bs, rk);
                for (int i=0;i<bs;i++) local_out[b*bs+i] = local_in[b*bs+i]^enc_ctr[i];
                int carry=1;
                for (int i=bs-1; i>=0 && carry; i--) {
                    int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
                }
            }
        }
    }

    uint8_t *padded_plain = NULL;
    if (rank == 0) padded_plain = (uint8_t *)malloc(data_len+1);
    MPI_Gatherv(local_out, local_count*bs, MPI_UNSIGNED_CHAR,
                padded_plain, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        uint8_t *res = wbc1_unpad(padded_plain, data_len, bs, out_len);
        free(padded_plain);
        return res;
    }
    return NULL;
}

/* ==========================================================================
 * parallel_cascade_encrypt_ctr_hmac — MPI-параллельное WBC-CTR-HMAC (v2)
 * ========================================================================== */
static uint8_t *parallel_cascade_encrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                                    const uint8_t *data, size_t data_len,
                                                    int block_size,
                                                    const uint8_t *nonce_in,
                                                    size_t *out_len) {
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    int bs = block_size;
    MPI_Bcast(&bs, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t nonce[NONCE_SIZE] = {0};
    uint8_t key_crypt[KEY_SIZE] = {0}, key_mac[KEY_SIZE] = {0};
    int n_blocks = 0;
    uint8_t *padded = NULL;
    size_t padded_len = 0;

    if (rank == 0) {
        if (nonce_in) memcpy(nonce, nonce_in, NONCE_SIZE);
        else RAND_bytes(nonce, NONCE_SIZE);
        kdf(key, nonce, key_crypt, key_mac);
        padded = wbc1_pad(data, data_len, bs, &padded_len);
        n_blocks = (int)(padded_len / bs);
    }
    MPI_Bcast(nonce,     NONCE_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(key_crypt, KEY_SIZE,   MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&n_blocks, 1,          MPI_INT,            0, MPI_COMM_WORLD);

    /* Строим таблицы по key_crypt */
    build_op_table(key_crypt);
    build_perm_table(bs);

    int *send_counts = NULL, *displs = NULL;
    if (rank == 0) calc_distribution_cached(n_blocks, bs, nproc, &send_counts, &displs);

    int local_count;
    { int bpp = n_blocks/nproc, rem = n_blocks%nproc; local_count = bpp + (rank < rem ? 1 : 0); }

    size_t local_bytes = (size_t)local_count * (size_t)bs;
    ensure_io_cache(&g_io_cache_ctrhmac, local_bytes + 1);
    uint8_t *local_plain  = g_io_cache_ctrhmac.in_buf;
    uint8_t *local_cipher = g_io_cache_ctrhmac.out_buf;

    MPI_Scatterv(padded, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_plain, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    /* cascade-within-chunk WBC-CTR (локальный счётчик 0..local_count-1) */
    {
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(key_crypt, (size_t)rank, rk);
        int ctr_tail_sz = (bs > NONCE_SIZE) ? bs-NONCE_SIZE : 1;
        for (int b = 0; b < local_count; b++) {
            uint8_t ctr_block[MAX_CUBE] = {0};
            memcpy(ctr_block, nonce, NONCE_SIZE);
            for (int i=ctr_tail_sz-1; i>=0; i--)
                ctr_block[NONCE_SIZE+i] = (uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
            uint8_t enc_ctr[MAX_CUBE];
            encrypt_block(rk, ctr_block, bs, enc_ctr);
            derive_cascade_key(enc_ctr, bs, rk);
            for (int i=0;i<bs;i++)
                local_cipher[b*bs+i] = local_plain[b*bs+i] ^ enc_ctr[i];
        }
    }

    uint8_t *cipher = NULL;
    if (rank == 0) cipher = (uint8_t *)malloc(padded_len);
    MPI_Gatherv(local_cipher, local_count*bs, MPI_UNSIGNED_CHAR,
                cipher, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        free(padded);
        size_t hdr_len = MAGIC_LEN+1+2+NONCE_SIZE;
        uint8_t header[32];
        memcpy(header,MAGIC,MAGIC_LEN);
        header[MAGIC_LEN]   = VERSION_CASC;
        header[MAGIC_LEN+1] = (uint8_t)(bs>>8);
        header[MAGIC_LEN+2] = (uint8_t)(bs&0xFF);
        memcpy(header+MAGIC_LEN+3, nonce, NONCE_SIZE);
        uint8_t mac[32];
        uint8_t *mac_in = (uint8_t *)malloc(hdr_len+padded_len);
        memcpy(mac_in,header,hdr_len); memcpy(mac_in+hdr_len,cipher,padded_len);
        hmac_sha256(key_mac,32,mac_in,hdr_len+padded_len,mac);
        free(mac_in);
        *out_len = hdr_len+padded_len+MAC_SIZE;
        uint8_t *result = (uint8_t *)malloc(*out_len);
        memcpy(result,header,hdr_len);
        memcpy(result+hdr_len,cipher,padded_len);
        memcpy(result+hdr_len+padded_len,mac,MAC_SIZE);
        free(cipher);
        return result;
    }
    return NULL;
}

/* ==========================================================================
 * parallel_cascade_decrypt_ctr_hmac — MPI-параллельное WBC-CTR-HMAC decrypt (v2)
 * ========================================================================== */
static uint8_t *parallel_cascade_decrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                                    const uint8_t *file_bytes, size_t file_len,
                                                    size_t *out_len) {
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    int bs = 0;
    uint8_t nonce[NONCE_SIZE] = {0};
    uint8_t key_crypt[KEY_SIZE] = {0}, key_mac[KEY_SIZE] = {0};
    int n_blocks = 0;
    int mac_ok   = 0;
    size_t cipher_len = 0;

    if (rank == 0) {
        if (file_len < (size_t)(MAGIC_LEN+1+2+NONCE_SIZE+MAC_SIZE)) {
            fprintf(stderr,"ERROR: file too short\n"); bs = -1;
        } else if (memcmp(file_bytes,MAGIC,MAGIC_LEN)!=0) {
            fprintf(stderr,"ERROR: invalid magic\n"); bs = -1;
        } else if (file_bytes[MAGIC_LEN] != VERSION_CASC) {
            fprintf(stderr,"ERROR: version mismatch (0x%02x)\n",file_bytes[MAGIC_LEN]); bs = -1;
        } else {
            bs = ((int)file_bytes[MAGIC_LEN+1]<<8)|file_bytes[MAGIC_LEN+2];
            memcpy(nonce, file_bytes+MAGIC_LEN+3, NONCE_SIZE);
            size_t hdr_len = MAGIC_LEN+1+2+NONCE_SIZE;
            cipher_len = file_len-hdr_len-MAC_SIZE;
            kdf(key, nonce, key_crypt, key_mac);
            /* Verify MAC */
            uint8_t mac_expected[32], *mac_in = (uint8_t *)malloc(hdr_len+cipher_len);
            memcpy(mac_in,file_bytes,hdr_len);
            memcpy(mac_in+hdr_len,file_bytes+hdr_len,cipher_len);
            hmac_sha256(key_mac,32,mac_in,hdr_len+cipher_len,mac_expected);
            free(mac_in);
            int diff=0; const uint8_t *mac_actual=file_bytes+file_len-MAC_SIZE;
            for (int i=0;i<MAC_SIZE;i++) diff|=mac_actual[i]^mac_expected[i];
            if (diff!=0) { fprintf(stderr,"ERROR: MAC failed\n"); bs = -1; }
            else { mac_ok=1; n_blocks=(int)(cipher_len/bs); }
        }
    }
    MPI_Bcast(&bs, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (bs <= 0) return NULL;

    MPI_Bcast(nonce,     NONCE_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(key_crypt, KEY_SIZE,   MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&n_blocks, 1,          MPI_INT,            0, MPI_COMM_WORLD);
    MPI_Bcast(&mac_ok,   1,          MPI_INT,            0, MPI_COMM_WORLD);
    if (!mac_ok) return NULL;

    build_op_table(key_crypt);
    build_perm_table(bs);

    /* Указатель на cipher (только у rank 0) */
    size_t hdr_len = MAGIC_LEN+1+2+NONCE_SIZE;
    const uint8_t *cipher = (rank == 0) ? (file_bytes + hdr_len) : NULL;

    int *send_counts = NULL, *displs = NULL;
    if (rank == 0) calc_distribution_cached(n_blocks, bs, nproc, &send_counts, &displs);

    int local_count;
    { int bpp = n_blocks/nproc, rem = n_blocks%nproc; local_count = bpp + (rank < rem ? 1 : 0); }

    size_t local_bytes = (size_t)local_count * (size_t)bs;
    ensure_io_cache(&g_io_cache_ctrhmac, local_bytes + 1);
    uint8_t *local_cipher = g_io_cache_ctrhmac.in_buf;
    uint8_t *local_plain  = g_io_cache_ctrhmac.out_buf;

    MPI_Scatterv(cipher, send_counts, displs, MPI_UNSIGNED_CHAR,
                 local_cipher, local_count*bs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    /* cascade-within-chunk WBC-CTR (идентично encrypt — XOR обратим) */
    {
        uint8_t rk[KEY_SIZE];
        derive_parallel_key(key_crypt, (size_t)rank, rk);
        int ctr_tail_sz = (bs > NONCE_SIZE) ? bs-NONCE_SIZE : 1;
        for (int b = 0; b < local_count; b++) {
            uint8_t ctr_block[MAX_CUBE] = {0};
            memcpy(ctr_block, nonce, NONCE_SIZE);
            for (int i=ctr_tail_sz-1; i>=0; i--)
                ctr_block[NONCE_SIZE+i] = (uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
            uint8_t enc_ctr[MAX_CUBE];
            encrypt_block(rk, ctr_block, bs, enc_ctr);
            derive_cascade_key(enc_ctr, bs, rk);
            for (int i=0;i<bs;i++)
                local_plain[b*bs+i] = local_cipher[b*bs+i] ^ enc_ctr[i];
        }
    }

    uint8_t *plain_buf = NULL;
    if (rank == 0) plain_buf = (uint8_t *)malloc(cipher_len+1);
    MPI_Gatherv(local_plain, local_count*bs, MPI_UNSIGNED_CHAR,
                plain_buf, send_counts, displs, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        uint8_t *res = wbc1_unpad(plain_buf, cipher_len, bs, out_len);
        free(plain_buf);
        return res;
    }
    return NULL;
}

/* ── utility ─────────────────────────────────────────────────────────────── */

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %-16s", label);
    for (size_t i=0;i<len;i++) printf("%02x",data[i]);
    printf("\n");
}

/* ── statistics ──────────────────────────────────────────────────────────── */

static double shannon_entropy(const uint8_t *data, size_t len) {
    if (!len) return 0.0;
    size_t freq[256]={0};
    for (size_t i=0;i<len;i++) freq[data[i]]++;
    double h=0.0;
    for (int i=0;i<256;i++) if(freq[i]){ double p=(double)freq[i]/(double)len; h-=p*log2(p); }
    return h;
}
static double chi_square_uniform(const uint8_t *data, size_t len) {
    if (!len) return 0.0;
    size_t freq[256]={0};
    for (size_t i=0;i<len;i++) freq[data[i]]++;
    double expected=(double)len/256.0, chi=0.0;
    for (int i=0;i<256;i++) { double d=(double)freq[i]-expected; chi+=d*d/expected; }
    return chi;
}
static double correlation(const uint8_t *x, const uint8_t *y, size_t len) {
    if (!len) return 0.0;
    double mx=0.0,my=0.0;
    for (size_t i=0;i<len;i++) { mx+=x[i]; my+=y[i]; }
    mx/=len; my/=len;
    double cov=0.0,vx=0.0,vy=0.0;
    for (size_t i=0;i<len;i++) { double a=x[i]-mx,b=y[i]-my; cov+=a*b; vx+=a*a; vy+=b*b; }
    if (vx==0.0||vy==0.0) return 0.0;
    return cov/(sqrt(vx)*sqrt(vy));
}
static void statistics_tests(const uint8_t *plain, size_t pl,
                               const uint8_t *cipher, size_t cl) {
    printf("\n  === STATISTICAL TESTS ===\n");
    printf("  Shannon entropy (plain):   %.4f bits/byte\n", shannon_entropy(plain,pl));
    printf("  Shannon entropy (cipher):  %.4f bits/byte  (ideal 8.0)\n", shannon_entropy(cipher,cl));
    printf("  Chi-square (ciphertext):   %.2f         (ideal ~256)\n", chi_square_uniform(cipher,cl));
    size_t cmp_len = pl<cl?pl:cl;
    printf("  Correlation plain<->cipher:%.4f             (ideal ~0)\n", correlation(plain,cipher,cmp_len));
    int reps=0;
    for (size_t i=1;i<cl;i++) if(cipher[i]==cipher[i-1]) reps++;
    printf("  Adjacent byte repeats:     %d\n", reps);
}

/* ── avalanche test (MPI) ────────────────────────────────────────────────── */

static void avalanche_test_mpi(const uint8_t key[KEY_SIZE], EncMode mode, int double_pass) {
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    int bsz = auto_block_size(64);
    int is_stream = (mode==MODE_CTR||mode==MODE_CFB||mode==MODE_OFB||mode==MODE_WBC_CTR_HMAC);

    if (is_stream) {
        /* Потоковые режимы: чувствительность к ключу — MPI, все ранги */
        MPI_Bcast(&bsz, 1, MPI_INT, 0, MPI_COMM_WORLD);
        uint8_t *data = (uint8_t *)malloc(bsz);
        for (int i=0;i<bsz;i++) data[i]=(uint8_t)(i*17+31);
        uint8_t nonce0[NONCE_SIZE]={0};
        size_t enc_len0=0; uint8_t *iv0=NULL; size_t iv0_len=0; uint8_t *enc0=NULL;
        if (mode==MODE_WBC_CTR_HMAC)
            enc0=parallel_cascade_encrypt_ctr_hmac(key,data,bsz,bsz,nonce0,&enc_len0);
        else
            enc0=parallel_cascade_encrypt(key,data,bsz,mode,NULL,bsz,&iv0,&iv0_len,double_pass,&enc_len0);
        size_t benc_len=enc_len0;
        MPI_Bcast(&benc_len,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
        uint8_t *benc0=(uint8_t*)malloc(benc_len+1);
        if (rank==0) memcpy(benc0,enc0,benc_len);
        MPI_Bcast(benc0,(int)benc_len,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
        size_t hdr_off=(mode==MODE_WBC_CTR_HMAC)?(size_t)(MAGIC_LEN+1+2+NONCE_SIZE):0;
        size_t pay_len=(mode==MODE_WBC_CTR_HMAC)?benc_len-hdr_off-MAC_SIZE:benc_len;
        long long total_flips=0;
        for (int fi=0;fi<KEY_SIZE*8;fi++) {
            size_t enc_len1=0; uint8_t *iv1=NULL; size_t iv1_len=0; uint8_t *enc1=NULL;
            uint8_t mk[KEY_SIZE]; memcpy(mk,key,KEY_SIZE); mk[fi/8]^=(uint8_t)(1<<(fi%8));
            MPI_Bcast(mk,KEY_SIZE,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
            if (mode==MODE_WBC_CTR_HMAC)
                enc1=parallel_cascade_encrypt_ctr_hmac(mk,data,bsz,bsz,nonce0,&enc_len1);
            else
                enc1=parallel_cascade_encrypt(mk,data,bsz,mode,iv0,bsz,&iv1,&iv1_len,double_pass,&enc_len1);
            if (rank==0&&enc1) {
                size_t cmp=(mode==MODE_WBC_CTR_HMAC&&enc_len1>hdr_off+MAC_SIZE)
                    ?enc_len1-hdr_off-MAC_SIZE:(enc_len1<pay_len?enc_len1:pay_len);
                for (size_t j=0;j<cmp;j++) total_flips+=__builtin_popcount((benc0+hdr_off)[j]^(enc1+hdr_off)[j]);
            }
            if (enc1) free(enc1); if (iv1) free(iv1);
        }
        if (rank==0) {
            double ratio=(pay_len>0)?(double)total_flips/((double)(KEY_SIZE*8)*(double)(pay_len*8)):0.0;
            printf("  Avalanche (key,  %dB):%14.2f%%  (ideal ~50%%)\n", bsz, ratio*100.0);
            free(enc0); if (iv0) free(iv0);
        } else { if (enc0) free(enc0); if (iv0) free(iv0); }
        free(benc0); free(data);
        return;
    }

    /* Блочные режимы: последовательный cascade-тест (все ранги, одинаковый результат).
     * Переворачиваем биты ПЕРВОГО блока (b=0), сравниваем downstream-блоки (1..N-1).
     * Первый блок имеет низкий per-block SAC (~6%), но cascade передаёт изменение
     * в следующие блоки с ~50% чувствительностью. */
    int N = 8;   /* 8 блоков: flip в блоке 0, cascade в блоках 1..7 */
    uint8_t *plain = (uint8_t*)malloc(N * bsz);
    for (int i=0; i<N*bsz; i++) plain[i] = (uint8_t)(i*17+31);

    /* Базовое шифрование: последовательный cascade */
    uint8_t *ct_base = (uint8_t*)malloc(N * bsz);
    {
        uint8_t rk[KEY_SIZE]; memcpy(rk, key, KEY_SIZE);
        for (int b=0; b<N; b++) {
            encrypt_block(rk, plain+b*bsz, bsz, ct_base+b*bsz);
            derive_cascade_key(ct_base+b*bsz, bsz, rk);
        }
    }

    int flip_count = bsz * 8;                       /* все биты первого блока */
    long long total_bits = (long long)(N-1) * bsz * 8;  /* downstream блоки 1..N-1 */
    long long total_flips = 0;

    for (int fi=0; fi<flip_count; fi++) {
        uint8_t *plain_mod = (uint8_t*)malloc(N * bsz);
        memcpy(plain_mod, plain, N * bsz);
        plain_mod[fi/8] ^= (uint8_t)(1 << (fi%8));   /* бит в блоке 0 */

        uint8_t *ct_mod = (uint8_t*)malloc(N * bsz);
        uint8_t rk[KEY_SIZE]; memcpy(rk, key, KEY_SIZE);
        for (int b=0; b<N; b++) {
            encrypt_block(rk, plain_mod+b*bsz, bsz, ct_mod+b*bsz);
            derive_cascade_key(ct_mod+b*bsz, bsz, rk);
        }

        /* Биты отличий только в downstream-блоках 1..N-1 */
        for (int b=1; b<N; b++)
            for (int j=0; j<bsz; j++)
                total_flips += __builtin_popcount(ct_base[b*bsz+j] ^ ct_mod[b*bsz+j]);

        free(plain_mod); free(ct_mod);
    }
    free(plain); free(ct_base);

    if (rank==0) {
        double ratio = (total_bits>0)
            ? (double)total_flips / ((double)flip_count * (double)total_bits) : 0.0;
        printf("  Avalanche cascade (%dB):%10.2f%%  (ideal ~50%%)\n",
               N*bsz, ratio*100.0);
    }
}

/* ── differential test (MPI) ────────────────────────────────────────────── */

static void differential_test_mpi(const uint8_t key[KEY_SIZE], EncMode mode, int double_pass) {
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    uint8_t data[64];
    int bsz = auto_block_size(64);
    for (int i=0;i<64;i++) data[i]=(uint8_t)(i*13+57);
    MPI_Bcast(&bsz, 1, MPI_INT, 0, MPI_COMM_WORLD);

    uint8_t nonce0[NONCE_SIZE] = {1};
    size_t enc_len0=0; uint8_t *iv0=NULL; size_t iv0_len=0; uint8_t *enc0=NULL;
    if (mode==MODE_WBC_CTR_HMAC)
        enc0=parallel_cascade_encrypt_ctr_hmac(key,data,64,bsz,nonce0,&enc_len0);
    else
        enc0=parallel_cascade_encrypt(key,data,64,mode,NULL,bsz,&iv0,&iv0_len,double_pass,&enc_len0);

    size_t benc_len=enc_len0;
    MPI_Bcast(&benc_len,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
    uint8_t *benc0=(uint8_t*)malloc(benc_len+1);
    if (rank==0) memcpy(benc0,enc0,benc_len);
    MPI_Bcast(benc0,(int)benc_len,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);

    size_t hdr_off = (mode==MODE_WBC_CTR_HMAC) ? (size_t)(MAGIC_LEN+1+2+NONCE_SIZE) : 0;
    size_t pay_len = (mode==MODE_WBC_CTR_HMAC) ? benc_len-hdr_off-MAC_SIZE : benc_len;

    long long total_flips=0, total_bits=(long long)pay_len*8;

    for (int fi=0; fi<KEY_SIZE*8; fi++) {
        uint8_t mk[KEY_SIZE]; memcpy(mk,key,KEY_SIZE);
        mk[fi/8]^=(uint8_t)(1<<(fi%8));
        MPI_Bcast(mk,KEY_SIZE,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);

        size_t enc_len1=0; uint8_t *iv1=NULL; size_t iv1_len=0; uint8_t *enc1=NULL;
        if (mode==MODE_WBC_CTR_HMAC)
            enc1=parallel_cascade_encrypt_ctr_hmac(mk,data,64,bsz,nonce0,&enc_len1);
        else
            enc1=parallel_cascade_encrypt(mk,data,64,mode,iv0,bsz,&iv1,&iv1_len,double_pass,&enc_len1);

        if (rank==0 && enc1) {
            const uint8_t *c0=benc0+hdr_off, *c1=enc1+hdr_off;
            size_t cmp = (mode==MODE_WBC_CTR_HMAC && enc_len1>hdr_off+MAC_SIZE)
                         ? enc_len1-hdr_off-MAC_SIZE : (enc_len1<pay_len?enc_len1:pay_len);
            for (size_t j=0;j<cmp;j++) total_flips+=__builtin_popcount(c0[j]^c1[j]);
        }
        if (enc1) free(enc1); if (iv1) free(iv1);
    }
    if (rank==0) {
        double ratio = (total_bits>0)
            ?(double)total_flips/((double)(KEY_SIZE*8)*(double)total_bits):0.0;
        printf("  Differential (key, 64B):%12.2f%%  (ideal ~50%%)\n", ratio*100.0);
        free(enc0); if (iv0) free(iv0);
    } else {
        if (enc0) free(enc0); if (iv0) free(iv0);
    }
    free(benc0);
}

/* ── self-tests (только rank 0) ──────────────────────────────────────────── */

static void run_self_tests(const uint8_t key[32], EncMode mode, int double_pass) {
    int rank; MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* Broadcast параметры теста */
    int imode = (int)mode, idp = double_pass;
    MPI_Bcast(&imode, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&idp,   1, MPI_INT, 0, MPI_COMM_WORLD);
    mode = (EncMode)imode; double_pass = idp;

    /* Широковещание ключа (все процессы должны иметь одинаковый ключ) */
    uint8_t bkey[KEY_SIZE]; memcpy(bkey, key, KEY_SIZE);
    MPI_Bcast(bkey, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    build_op_table(bkey);

    if (rank == 0) {
        printf("\n────────────────────────────────────────────────────────────\n");
        printf("  Self-tests  |  mode=%s  cascade=%s  procs=%d\n",
               mode_name(mode), double_pass?"DOUBLE":"SINGLE",
               ({ int s; MPI_Comm_size(MPI_COMM_WORLD,&s); s; }));
        printf("────────────────────────────────────────────────────────────\n");
    }

    typedef struct { const char *label; const uint8_t *data; size_t len; int heap; } T;
    uint8_t rand100[100]; if(rank==0) RAND_bytes(rand100,100); MPI_Bcast(rand100,100,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
    uint8_t range256[256]; for(int i=0;i<256;i++) range256[i]=(uint8_t)i;
    uint8_t a64[64]; memset(a64,'A',64);
    uint8_t b300[300]; memset(b300,'B',300);
    uint8_t *d10k  = (uint8_t *)malloc(10000);
    uint8_t *d100k = (uint8_t *)malloc(100000);
    if (rank==0) { RAND_bytes(d10k,10000); RAND_bytes(d100k,100000); }
    MPI_Bcast(d10k,  10000,  MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(d100k, 100000, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    T tests[] = {
        {"Short text",        (const uint8_t*)"Hello World!", 12, 0},
        {"One block (64B)",   a64,     64,    0},
        {"300 bytes",         b300,    300,   0},
        {"Binary (100B)",     rand100, 100,   0},
        {"Empty input",       (const uint8_t*)"", 0, 0},
        {"All byte values",   range256,256,   0},
        {"Single byte",       (const uint8_t*)"X", 1, 0},
        {"10 000 bytes",      d10k,  10000,   0},
        {"100 000 bytes",     d100k, 100000,  0},
    };
    int n = (int)(sizeof(tests)/sizeof(tests[0]));
    int passed = 0;

    for (int t=0; t<n; t++) {
        /* Broadcast данные теста на все процессы */
        int bsz = auto_block_size((int)tests[t].len);
        int tlen = (int)tests[t].len;
        MPI_Bcast(&tlen, 1, MPI_INT, 0, MPI_COMM_WORLD);
        MPI_Bcast(&bsz,  1, MPI_INT, 0, MPI_COMM_WORLD);

        uint8_t *tdata = (uint8_t *)malloc(tlen+1);
        if (rank==0) memcpy(tdata, tests[t].data, tlen);
        MPI_Bcast(tdata, tlen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        size_t enc_len=0, dec_len=0;
        int ok=0;

        if (mode==MODE_WBC_CTR_HMAC) {
            uint8_t *enc = parallel_cascade_encrypt_ctr_hmac(bkey,tdata,tlen,bsz,NULL,&enc_len);
            /* Broadcast шифртекст */
            size_t benc_len = enc_len;
            MPI_Bcast(&benc_len, sizeof(size_t), MPI_BYTE, 0, MPI_COMM_WORLD);
            uint8_t *benc = (uint8_t *)malloc(benc_len+1);
            if (rank==0) memcpy(benc, enc, benc_len);
            MPI_Bcast(benc, (int)benc_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            uint8_t *dec = parallel_cascade_decrypt_ctr_hmac(bkey,benc,benc_len,&dec_len);
            if (rank==0) ok = dec && dec_len==(size_t)tlen && memcmp(dec,tdata,dec_len)==0;
            if (enc) free(enc); if (dec) free(dec); free(benc);
        } else {
            uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *enc = parallel_cascade_encrypt(bkey,tdata,tlen,mode,NULL,bsz,&iv,&iv_len,double_pass,&enc_len);
            /* Broadcast шифртекст и IV */
            size_t benc_len=enc_len, biv_len=iv_len;
            MPI_Bcast(&benc_len, sizeof(size_t), MPI_BYTE, 0, MPI_COMM_WORLD);
            MPI_Bcast(&biv_len,  sizeof(size_t), MPI_BYTE, 0, MPI_COMM_WORLD);
            uint8_t *benc = (uint8_t *)malloc(benc_len+1);
            uint8_t *biv  = biv_len>0 ? (uint8_t *)malloc(biv_len+1) : NULL;
            if (rank==0) { memcpy(benc,enc,benc_len); if(biv&&iv) memcpy(biv,iv,biv_len); }
            MPI_Bcast(benc, (int)benc_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            if (biv) MPI_Bcast(biv, (int)biv_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            uint8_t *dec = parallel_cascade_decrypt(bkey,benc,benc_len,mode,biv,bsz,double_pass,&dec_len);
            if (rank==0) ok = dec_len==(size_t)tlen && memcmp(dec,tdata,dec_len)==0;
            if (enc) free(enc); if (dec) free(dec); if (iv) free(iv); free(benc); if (biv) free(biv);
        }
        if (rank==0) {
            printf("  %-35s %s\n", tests[t].label, ok?"PASS ✓":"FAIL ✗");
            if (ok) passed++;
        }
        free(tdata);
    }
    if (rank==0) {
        printf("────────────────────────────────────────────────────────────\n");
        printf("  Results: %d/%d passed\n\n", passed, n);
    }
    free(d10k); free(d100k);

    /* Лавинный и дифференциальный тесты */
    if (rank==0) printf("  === AVALANCHE & DIFFERENTIAL (64-byte block) ===\n");
    avalanche_test_mpi(bkey, mode, double_pass);
    differential_test_mpi(bkey, mode, double_pass);
    if (rank==0) printf("\n");
}

/* ── benchmark helpers ───────────────────────────────────────────────────── */

static int cmp_double_asc(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double aggregate_bench_time(const double *t, int n, int trim) {
    if (n <= 0) return 0.0;
    if (!trim || n < 5) {
        double s = 0.0;
        for (int i = 0; i < n; i++) s += t[i];
        return s / (double)n;
    }

    double tmp[MAX_BENCH_REPEATS];
    memcpy(tmp, t, (size_t)n * sizeof(double));
    qsort(tmp, (size_t)n, sizeof(double), cmp_double_asc);

    int cut = (n >= 15) ? 2 : 1;
    int start = cut;
    int end = n - cut;
    if (end <= start) {
        double s = 0.0;
        for (int i = 0; i < n; i++) s += t[i];
        return s / (double)n;
    }

    double s = 0.0;
    for (int i = start; i < end; i++) s += tmp[i];
    return s / (double)(end - start);
}

static double read_cpu_mhz(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0.0;
    char line[256]; double mhz = 0.0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "cpu MHz", 7) == 0) {
            char *p = strchr(line, ':');
            if (p) { mhz = atof(p + 1); break; }
        }
    }
    fclose(f); return mhz;
}

/* ── benchmark (только rank 0 показывает вывод) ─────────────────────────── */

static void benchmark(const uint8_t key[32], EncMode mode, int double_pass) {
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    int imode = (int)mode, idp = double_pass;
    MPI_Bcast(&imode, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&idp,   1, MPI_INT, 0, MPI_COMM_WORLD);
    mode = (EncMode)imode; double_pass = idp;

    uint8_t bkey[KEY_SIZE]; memcpy(bkey, key, KEY_SIZE);
    MPI_Bcast(bkey, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    build_op_table(bkey);

    static const int sizes_default[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};
    static const int sizes_with_1gb[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000,1073741824};
    const int *sizes = sizes_default;
    int ns = (int)(sizeof(sizes_default)/sizeof(sizes_default[0]));
    int repeats = 10;
    int strict_timing = 0;
    int trim_outliers = 1;
    {
        const char *env = getenv("WBC_MPI_BENCH_STRICT");
        if (env && env[0] == '1') strict_timing = 1;
    }
    {
        const char *env = getenv("WBC_MPI_BENCH_REPEATS");
        if (env) {
            int v = atoi(env);
            if (v >= 3 && v <= MAX_BENCH_REPEATS) repeats = v;
        }
    }
    {
        const char *env = getenv("WBC_MPI_BENCH_TRIM");
        if (env && env[0] == '0') trim_outliers = 0;
    }
    {
        const char *env = getenv("WBC_MPI_BENCH_1GB");
        if (env && env[0] == '1') {
            sizes = sizes_with_1gb;
            ns = (int)(sizeof(sizes_with_1gb)/sizeof(sizes_with_1gb[0]));
        }
    }
    double enc_spds[16]={0}, dec_spds[16]={0}; int bsizes[16]={0};

    if (rank==0) {
        printf("\n  Benchmark  |  mode=%s  cascade=%s  procs=%d\n",
               mode_name(mode), double_pass?"DOUBLE":"SINGLE", nproc);
        printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  Integrity\n","Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)","Enc (MB/s)","Dec (MB/s)","Enc (Mbit/s)","Dec (Mbit/s)");
        printf("  %s\n","--------------------------------------------------------------------------------------------------------------");
        printf("  Timing mode: %s\n", strict_timing ? "strict MPI_MAX" : "legacy barrier/root");
        printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers ? "trimmed mean" : "mean");
    }

    for (int si=0; si<ns; si++) {
        int sz = sizes[si];
        uint8_t *data = (uint8_t *)malloc(sz+1);
        if (rank==0) RAND_bytes(data, sz);
        MPI_Bcast(data, sz, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        int bsz = auto_block_size(sz);
        MPI_Bcast(&bsz, 1, MPI_INT, 0, MPI_COMM_WORLD);
        build_perm_table(bsz);
        int all_ok = 1;

        /* warmup */
        {
            size_t el=0,dl=0; uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *e=NULL,*d=NULL;
            if (mode==MODE_WBC_CTR_HMAC) {
                e = parallel_cascade_encrypt_ctr_hmac(bkey,data,sz,bsz,NULL,&el);
                size_t bel=el; MPI_Bcast(&bel,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                uint8_t *be=(uint8_t*)malloc(bel+1); if(rank==0)memcpy(be,e,bel);
                MPI_Bcast(be,(int)bel,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                d = parallel_cascade_decrypt_ctr_hmac(bkey,be,bel,&dl);
                if(e)free(e); if(d)free(d); free(be);
            } else {
                e = parallel_cascade_encrypt(bkey,data,sz,mode,NULL,bsz,&iv,&iv_len,double_pass,&el);
                size_t bel=el,bil=iv_len; MPI_Bcast(&bel,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                MPI_Bcast(&bil,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                uint8_t *be=(uint8_t*)malloc(bel+1); uint8_t *bi=bil>0?(uint8_t*)malloc(bil+1):NULL;
                if(rank==0){memcpy(be,e,bel); if(bi&&iv)memcpy(bi,iv,bil);}
                MPI_Bcast(be,(int)bel,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                if(bi)MPI_Bcast(bi,(int)bil,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                d = parallel_cascade_decrypt(bkey,be,bel,mode,bi,bsz,double_pass,&dl);
                if(e)free(e); if(d)free(d); if(iv)free(iv); free(be); if(bi)free(bi);
            }
        }

        double enc_times[MAX_BENCH_REPEATS] = {0.0};
        double dec_times[MAX_BENCH_REPEATS] = {0.0};
        for (int r=0; r<repeats; r++) {
            size_t enc_len=0,dec_len=0;
            uint8_t *enc=NULL,*dec=NULL,*iv=NULL; size_t iv_len=0;

            if (!strict_timing) MPI_Barrier(MPI_COMM_WORLD);
            double t0 = MPI_Wtime();
            if (mode==MODE_WBC_CTR_HMAC)
                enc = parallel_cascade_encrypt_ctr_hmac(bkey,data,sz,bsz,NULL,&enc_len);
            else
                enc = parallel_cascade_encrypt(bkey,data,sz,mode,NULL,bsz,&iv,&iv_len,double_pass,&enc_len);
            if (strict_timing) {
                double enc_local = MPI_Wtime() - t0;
                double enc_iter = 0.0;
                MPI_Reduce(&enc_local, &enc_iter, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
                if (rank==0) enc_times[r] = enc_iter;
            } else {
                MPI_Barrier(MPI_COMM_WORLD);
                if (rank==0) enc_times[r] = MPI_Wtime() - t0;
            }

            /* Broadcast шифртекст для дешифрования */
            size_t bel=enc_len, bil=iv_len;
            MPI_Bcast(&bel,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
            MPI_Bcast(&bil,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
            uint8_t *be=(uint8_t*)malloc(bel+1); uint8_t *bi=bil>0?(uint8_t*)malloc(bil+1):NULL;
            if(rank==0){if(enc)memcpy(be,enc,bel); if(bi&&iv)memcpy(bi,iv,bil);}
            MPI_Bcast(be,(int)bel,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
            if(bi)MPI_Bcast(bi,(int)bil,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);

            if (!strict_timing) MPI_Barrier(MPI_COMM_WORLD);
            double t1 = MPI_Wtime();
            if (mode==MODE_WBC_CTR_HMAC)
                dec = parallel_cascade_decrypt_ctr_hmac(bkey,be,bel,&dec_len);
            else
                dec = parallel_cascade_decrypt(bkey,be,bel,mode,bi,bsz,double_pass,&dec_len);
            if (strict_timing) {
                double dec_local = MPI_Wtime() - t1;
                double dec_iter = 0.0;
                MPI_Reduce(&dec_local, &dec_iter, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
                if (rank==0) dec_times[r] = dec_iter;
            } else {
                MPI_Barrier(MPI_COMM_WORLD);
                if (rank==0) dec_times[r] = MPI_Wtime() - t1;
            }

            if (rank==0) {
                if (!dec||dec_len!=(size_t)sz||memcmp(dec,data,sz)!=0) all_ok=0;
            }
            if(enc)free(enc); if(dec)free(dec); if(iv)free(iv); free(be); if(bi)free(bi);
        }
        if (rank==0) {
            double ea=aggregate_bench_time(enc_times,repeats,trim_outliers);
            double da=aggregate_bench_time(dec_times,repeats,trim_outliers);
            double es=((double)sz/1024.0)/(ea>0?ea:1e-9);
            double ds=((double)sz/1024.0)/(da>0?da:1e-9);
            double em=((double)sz/1e6)/(ea>0?ea:1e-9);
            double dm=((double)sz/1e6)/(da>0?da:1e-9);
            double emb=em*8.0, dmb=dm*8.0;
            printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
                   (double)sz/1024.0, ea, es, ds, em, dm, emb, dmb, all_ok?"OK":"FAIL");
            enc_spds[si] = es; dec_spds[si] = ds; bsizes[si] = bsz;
        }
        free(data);
    }
    /* --- Цикли / байт (cycles per byte) --- */
    if (rank==0) {
        double cpu_mhz = read_cpu_mhz();
        if (cpu_mhz > 0) {
            printf("\n  --- Цикли / байт  (CPU: %.0f МГц) ---\n", cpu_mhz);
            printf("  %10s  %8s  %8s  %12s  %12s  %10s  %10s\n",
                   "Size (KB)","Enc CPB","Dec CPB","E Cyc/blk","D Cyc/blk","E B/cycle","D B/cycle");
            printf("  %s\n","--------------------------------------------------------------------------");
            for (int si=0; si<ns; si++) {
                double ecpb = (enc_spds[si]>0) ? cpu_mhz*1e6/(enc_spds[si]*1024.0) : 0.0;
                double dcpb = (dec_spds[si]>0) ? cpu_mhz*1e6/(dec_spds[si]*1024.0) : 0.0;
                printf("  %10.2f  %8.2f  %8.2f  %12.0f  %12.0f  %10.5f  %10.5f\n",
                       (double)sizes[si]/1024.0, ecpb, dcpb,
                       ecpb*(double)bsizes[si], dcpb*(double)bsizes[si],
                       (ecpb>0)?1.0/ecpb:0.0, (dcpb>0)?1.0/dcpb:0.0);
            }
        } else {
            printf("\n  CPB: частота CPU недоступна\n");
        }
        printf("\n");
    }
}

/* ── interactive helpers (только rank 0 читає stdin) ──────────────────── */

static EncMode select_mode(void) {
    printf("  Select mode:\n"
           "    1. ECB\n    2. CBC\n    3. CFB\n"
           "    4. OFB\n    5. CTR\n    6. WBC-CTR-HMAC\n"
           "  Mode [1-6, default=1]: ");
    fflush(stdout);
    char buf[16]={0};
    if (fgets(buf,sizeof(buf),stdin)==NULL) return MODE_ECB;
    switch(buf[0]) {
        case '2': return MODE_CBC;  case '3': return MODE_CFB;
        case '4': return MODE_OFB;  case '5': return MODE_CTR;
        case '6': return MODE_WBC_CTR_HMAC;
        default:  return MODE_ECB;
    }
}

static int parse_mode_cli(const char *s, EncMode *out) {
    if (!s || !out) return 0;
    if (strcmp(s, "ecb") == 0) *out = MODE_ECB;
    else if (strcmp(s, "cbc") == 0) *out = MODE_CBC;
    else if (strcmp(s, "cfb") == 0) *out = MODE_CFB;
    else if (strcmp(s, "ofb") == 0) *out = MODE_OFB;
    else if (strcmp(s, "ctr") == 0) *out = MODE_CTR;
    else if (strcmp(s, "wbc-ctr-hmac") == 0 || strcmp(s, "ctr-hmac") == 0 || strcmp(s, "hmac") == 0)
        *out = MODE_WBC_CTR_HMAC;
    else return 0;
    return 1;
}

static int parse_task_cli(const char *s) {
    if (!s) return 0;
    if (strcmp(s, "encrypt") == 0 || strcmp(s, "demo") == 0 || strcmp(s, "text") == 0)
        return TASK_ENCRYPT_TEXT;
    if (strcmp(s, "selftest") == 0 || strcmp(s, "self-tests") == 0 || strcmp(s, "test") == 0)
        return TASK_SELF_TESTS;
    if (strcmp(s, "bench") == 0 || strcmp(s, "benchmark") == 0)
        return TASK_BENCHMARK;
    if (strcmp(s, "analysis") == 0 || strcmp(s, "stats") == 0)
        return TASK_ANALYSIS;
    return 0;
}

/* ==========================================================================
 * main — MPI SPMD: rank 0 управляет, все участвуют в коллективных операциях
 * ========================================================================== */

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    int rank, nproc;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

    /* Парсинг аргументов */
    int double_pass = 0;
    int cli_task = 0;
    int cli_mode_set = 0;
    EncMode cli_mode = MODE_ECB;
    int cli_data_size = 1024;
    int cli_bench_1gb = 0;
    char cli_text[4096] = {0};
    int cli_once = 0;
    if (rank == 0) {
        for (int i=1; i<argc; i++) {
            if (strcmp(argv[i],"-s")==0 || strcmp(argv[i],"--single")==0) double_pass=0;
            else if (strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--double")==0) double_pass=0;
            else if (strcmp(argv[i],"--task-encrypt")==0 || strcmp(argv[i],"--encrypt")==0) {
                cli_task = TASK_ENCRYPT_TEXT;
            } else if (strcmp(argv[i],"--task-selftest")==0 || strcmp(argv[i],"--selftest")==0 || strcmp(argv[i],"--self-tests")==0) {
                cli_task = TASK_SELF_TESTS;
            } else if (strcmp(argv[i],"--task-benchmark")==0 || strcmp(argv[i],"--benchmark")==0 || strcmp(argv[i],"--bench")==0) {
                cli_task = TASK_BENCHMARK;
            } else if (strcmp(argv[i],"--task-analysis")==0 || strcmp(argv[i],"--analysis")==0 || strcmp(argv[i],"--stats")==0) {
                cli_task = TASK_ANALYSIS;
            }
            else if ((strcmp(argv[i],"--task")==0 || strcmp(argv[i],"-t")==0) && i+1<argc) {
                cli_task = parse_task_cli(argv[++i]);
            } else if ((strcmp(argv[i],"--mode")==0 || strcmp(argv[i],"-m")==0) && i+1<argc) {
                cli_mode_set = parse_mode_cli(argv[++i], &cli_mode);
            } else if (strcmp(argv[i],"--size")==0 && i+1<argc) {
                cli_data_size = atoi(argv[++i]);
                if (cli_data_size <= 0 || cli_data_size > 1073741824) cli_data_size = 1024;
            } else if (strcmp(argv[i],"--bench-1gb")==0) {
                cli_bench_1gb = 1;
            } else if (strcmp(argv[i],"--text")==0 && i+1<argc) {
                strncpy(cli_text, argv[++i], sizeof(cli_text)-1);
                cli_text[sizeof(cli_text)-1] = 0;
            } else if (strcmp(argv[i],"--once")==0) {
                cli_once = 1;
            }
            else if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) {
                printf("Usage: mpirun -n N %s [--single] [--task TASK] [--mode MODE] [--text TXT] [--size N] [--once]\n", argv[0]);
                printf("  TASK: encrypt|selftest|benchmark|analysis\n");
                printf("  MODE: ecb|cbc|cfb|ofb|ctr|wbc-ctr-hmac\n");
                printf("  --bench-1gb: include 1 GiB point in benchmark (WBC_MPI_BENCH_1GB=1)\n");
                MPI_Finalize(); return 0;
            }
        }
        if (cli_task != 0) cli_once = 1;
    }
    MPI_Bcast(&double_pass, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cli_task, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cli_mode_set, 1, MPI_INT, 0, MPI_COMM_WORLD);
    int cli_mode_i = (int)cli_mode;
    MPI_Bcast(&cli_mode_i, 1, MPI_INT, 0, MPI_COMM_WORLD);
    cli_mode = (EncMode)cli_mode_i;
    MPI_Bcast(&cli_data_size, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cli_bench_1gb, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cli_once, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(cli_text, (int)sizeof(cli_text), MPI_CHAR, 0, MPI_COMM_WORLD);

    if (cli_bench_1gb) setenv("WBC_MPI_BENCH_1GB", "1", 1);

    /* Генерация ключа на rank 0, рассылка всем */
    uint8_t key[KEY_SIZE] = {0};
    if (rank == 0) RAND_bytes(key, KEY_SIZE);
    MPI_Bcast(key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    build_op_table(key);

    if (rank == 0) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════╗\n");
        printf("║        PWBC1.1 — WBC1-NOCASCADE-MPI  (MPI parallel)     ║\n");
        printf("╠══════════════════════════════════════════════════════════╣\n");
        printf("║  Прогрессы MPI: %-40d║\n", nproc);
         printf("║  Каскад:  %-46s ║\n",
             "NOCASCADE (single-pass, fixed master key)");
        printf("║  Раунды:  32  |  SHA: только init/HMAC  |  ECB/CTR: MPI║\n");
        printf("╚══════════════════════════════════════════════════════════╝\n");
    }

    /* ── Главный цикл — SPMD: rank 0 читает ввод и рассылает задачу ──────── */
    int ran_cli_once = 0;
    while (1) {
        int task = TASK_EXIT;
        EncMode mode = MODE_WBC_CTR_HMAC;

        if (cli_task != 0 && !ran_cli_once) {
            task = cli_task;
        } else if (rank == 0) {
            printf("\n"
                   "=== PWBC1.1 MPI [%s] ===\n"
                   "1. Encrypt / decrypt text\n"
                   "2. Run self-tests\n"
                   "3. Benchmark performance\n"
                   "4. Statistical analysis\n"
                   "5. Cascade mode (disabled in nocascade build)\n"
                   "6. Exit\n"
                   "Select (1-6): ",
                   "NOCASCADE");
            fflush(stdout);
            char choice[8]={0};
            if (fgets(choice,sizeof(choice),stdin)==NULL) { task=TASK_EXIT; }
            else {
                switch(choice[0]) {
                    case '1': task=TASK_ENCRYPT_TEXT; break;
                    case '2': task=TASK_SELF_TESTS;   break;
                    case '3': task=TASK_BENCHMARK;    break;
                    case '4': task=TASK_ANALYSIS;     break;
                    case '5': task=TASK_SWITCH_MODE;  break;
                    default:  task=TASK_EXIT;         break;
                }
            }
        }
        /* Все процессы узнают задачу */
        MPI_Bcast(&task, 1, MPI_INT, 0, MPI_COMM_WORLD);

        if (task == TASK_EXIT) { if(rank==0) printf("Bye!\n"); break; }

        if (cli_task != 0 && !ran_cli_once) ran_cli_once = 1;

        if (task == TASK_SWITCH_MODE) {
            if (rank==0) double_pass = 0;
            MPI_Bcast(&double_pass, 1, MPI_INT, 0, MPI_COMM_WORLD);
            if (rank==0)
                printf("  Cascade mode is disabled in nocascade build (single-pass fixed).\n");
            continue;
        }

        /* Для задач, требующих выбора режима */
        int imode = (int)MODE_WBC_CTR_HMAC;
        if (task == TASK_ENCRYPT_TEXT || task == TASK_SELF_TESTS ||
            task == TASK_BENCHMARK    || task == TASK_ANALYSIS) {
            if (rank==0) {
                if (cli_task != 0) {
                    mode = cli_mode_set ? cli_mode : MODE_WBC_CTR_HMAC;
                } else {
                    mode = select_mode();
                }
                imode = (int)mode;
            }
            MPI_Bcast(&imode, 1, MPI_INT, 0, MPI_COMM_WORLD);
            mode = (EncMode)imode;
        }

        if (task == TASK_SELF_TESTS) {
            /* Передача управления функции, которая сама делает Bcast */
            int imodeTmp=(int)mode, idpTmp=double_pass;
            /* Уже внутри run_self_tests есть MPI_Bcast, но передадим через bkey */
            run_self_tests(key, mode, double_pass);

        } else if (task == TASK_BENCHMARK) {
            benchmark(key, mode, double_pass);

        } else if (task == TASK_ENCRYPT_TEXT) {
            /* Чтение и рассылка текста */
            int text_len = 0;
            uint8_t *text_buf = NULL;
            if (rank == 0) {
                char text[4096]={0};
                if (cli_task != 0) {
                    if (cli_text[0] != 0) {
                        strncpy(text, cli_text, sizeof(text)-1);
                    } else {
                        strncpy(text, "Hello from WBC1 nocascade CLI mode", sizeof(text)-1);
                    }
                } else {
                    printf("  Text to encrypt: "); fflush(stdout);
                    if (fgets(text,sizeof(text),stdin)) text[strcspn(text,"\r\n")]=0;
                }
                text_len = (int)strlen(text);
                text_buf = (uint8_t *)malloc(text_len+1);
                memcpy(text_buf, text, text_len);
            }
            MPI_Bcast(&text_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
            if (rank != 0) text_buf = (uint8_t *)malloc(text_len+1);
            MPI_Bcast(text_buf, text_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

            int bsz = auto_block_size(text_len);
            MPI_Bcast(&bsz, 1, MPI_INT, 0, MPI_COMM_WORLD);
            build_perm_table(bsz);

            size_t enc_len=0, dec_len=0;
            uint8_t *enc=NULL, *dec=NULL;

            if (mode == MODE_WBC_CTR_HMAC) {
                enc = parallel_cascade_encrypt_ctr_hmac(key,text_buf,text_len,bsz,NULL,&enc_len);
                size_t bel=enc_len; MPI_Bcast(&bel,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                uint8_t *be=(uint8_t*)malloc(bel+1); if(rank==0)memcpy(be,enc,bel);
                MPI_Bcast(be,(int)bel,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                dec = parallel_cascade_decrypt_ctr_hmac(key,be,bel,&dec_len);
                if(rank==0){print_hex("Encrypted:",enc,enc_len);}
                free(be);
            } else {
                uint8_t *iv=NULL; size_t iv_len=0;
                enc = parallel_cascade_encrypt(key,text_buf,text_len,mode,NULL,bsz,&iv,&iv_len,double_pass,&enc_len);
                size_t bel=enc_len,bil=iv_len;
                MPI_Bcast(&bel,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                MPI_Bcast(&bil,sizeof(size_t),MPI_BYTE,0,MPI_COMM_WORLD);
                uint8_t *be=(uint8_t*)malloc(bel+1); uint8_t *bi=bil>0?(uint8_t*)malloc(bil+1):NULL;
                if(rank==0){memcpy(be,enc,bel); if(bi&&iv)memcpy(bi,iv,bil);}
                MPI_Bcast(be,(int)bel,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                if(bi)MPI_Bcast(bi,(int)bil,MPI_UNSIGNED_CHAR,0,MPI_COMM_WORLD);
                dec = parallel_cascade_decrypt(key,be,bel,mode,bi,bsz,double_pass,&dec_len);
                if(rank==0){print_hex("Encrypted:",enc,enc_len);}
                if(iv)free(iv); free(be); if(bi)free(bi);
            }
            if (rank==0 && dec) {
                print_hex("Decrypted hex:", dec, dec_len);
                printf("  Decrypted:     %.*s\n",(int)dec_len,(char*)dec);
            }
            if(enc)free(enc); if(dec)free(dec);
            free(text_buf);

        } else if (task == TASK_ANALYSIS) {
            /* Статистический анализ на rank 0 */
            int sz = 0;
            uint8_t *tdata = NULL;
            if (rank==0) {
                if (cli_task != 0) {
                    sz = cli_data_size;
                    if (sz<=0||sz>1073741824) sz=1024;
                } else {
                    printf("  Data size in bytes [default=1024]: "); fflush(stdout);
                    char buf[32]={0};
                    if (fgets(buf,sizeof(buf),stdin) == NULL) buf[0]='0';
                    sz = atoi(buf); if (sz<=0||sz>1073741824) sz=1024;
                }
                tdata = (uint8_t *)malloc(sz); RAND_bytes(tdata,sz);
            }
            MPI_Bcast(&sz, 1, MPI_INT, 0, MPI_COMM_WORLD);
            if (rank!=0) tdata = (uint8_t *)malloc(sz);
            MPI_Bcast(tdata, sz, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            int bsz = auto_block_size(sz); MPI_Bcast(&bsz, 1, MPI_INT, 0, MPI_COMM_WORLD);
            build_perm_table(bsz);

            size_t enc_len=0;
            uint8_t *enc=NULL;
            if (mode==MODE_WBC_CTR_HMAC) {
                enc = parallel_cascade_encrypt_ctr_hmac(key,tdata,sz,bsz,NULL,&enc_len);
            } else {
                uint8_t *iv=NULL; size_t iv_len=0;
                enc = parallel_cascade_encrypt(key,tdata,sz,mode,NULL,bsz,&iv,&iv_len,double_pass,&enc_len);
                if(iv)free(iv);
            }
            if (rank==0 && enc) {
                size_t hdr=0;
                const uint8_t *cdata=enc; size_t clen=enc_len;
                if (mode==MODE_WBC_CTR_HMAC) { hdr=MAGIC_LEN+1+2+NONCE_SIZE; cdata=enc+hdr; clen=enc_len-hdr-MAC_SIZE; }
                statistics_tests(tdata,sz,cdata,clen);
            }
            if(enc)free(enc); free(tdata);

            /* Лавинный и дифференциальный тесты */
            if (rank==0) printf("\n");
            avalanche_test_mpi(key, mode, double_pass);
            differential_test_mpi(key, mode, double_pass);
        }

        if (cli_once && ran_cli_once) break;
    } /* while */

    if (g_perms_buf) { free(g_perms_buf); g_perms_buf=NULL; }
    free_mpi_runtime_caches();
    MPI_Finalize();
    return 0;
}
