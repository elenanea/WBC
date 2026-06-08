/*
 * WBC1-Cascade-NEW -- C implementation
 * ======================================
 * Ключевые изменения относительно wbc1_fixed_cascade.c:
 *
 * 1. Нет SHA в горячем пути (per-block).
 *    get_round_key() удалён. Раундовый ключ выводится прямо из каскадного ключа:
 *      RK_r[i] = ROL8(cascade_key[(i + r*7) % 32], r & 7)
 *
 * 2. Число раундов = длина ключа в байтах = 32 (было 16).
 *    Каждый раунд r использует cascade_key[r] для выбора операции.
 *
 * 3. Новая derive_cascade_key — два прохода с модульным сложением (нелинейность):
 *    Шаг 1: XOR-свёртка блока → 32 байта F
 *    Шаг 2: прямой проход  c = (F[i] + ROL8(c,5) + 29i) mod 256  — ADD нелинейен
 *    Шаг 3: обратный проход c = F[i] XOR ROR8(c,3)               — полная диффузия
 *
 * 4. Командная строка:
 *    -s / --single   одиночный каскад (1 проход вперёд)
 *    -d / --double   двойной каскад  (2 прохода: вперёд + назад) [по умолчанию]
 *
 * SHA остаётся только в:
 *   - build_op_table()  — один раз при инициализации
 *   - kdf()             — один раз на сообщение (разделение ключей)
 *   - hmac_sha256()     — один раз на сообщение (аутентификация)
 *
 * Build:
 *   gcc -O2 -o wbc1_cascade_new wbc1_cascade_new.c -lssl -lcrypto -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <omp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── constants ──────────────────────────────────────────────────────────── */

#define MAGIC        "WBC1"
#define MAGIC_LEN    4
#define VERSION      0x01
#define VERSION_CASC 0x03   /* new version tag to distinguish from old files */
#define NONCE_SIZE   12
#define MAC_SIZE     32
#define PAD_HDR      2
#define KEY_SIZE     32
#define ROUNDS       32     /* = KEY_SIZE: один раунд на каждый байт ключа */
#define NUM_OPS      127

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

/* ── SHA-256/512 wrappers (used only at init/setup, NOT per-block) ────────── */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
}
static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    SHA512(data, len, out);
}

/* ── cube data structure ─────────────────────────────────────────────────── */

typedef struct { uint8_t *data; int dim; } Cube;

static Cube cube_alloc(int dim) {
    Cube c; c.dim = dim;
    c.data = (uint8_t *)calloc(dim * dim * dim, 1);
    return c;
}
static void cube_free(Cube *c) { free(c->data); c->data = NULL; }

static inline int idx3(int dim, int i, int j, int k) {
    return i * dim * dim + j * dim + k;
}

#define MAX_DIM   16
#define MAX_SLICE (MAX_DIM * MAX_DIM)   /* 256 байт — макс. срез */
#define MAX_CUBE  (MAX_DIM * MAX_DIM * MAX_DIM) /* 4096 байт — макс. куб */

static void rot90_2d(uint8_t *mat, int dim, int k) {
    k = ((k % 4) + 4) % 4;
    uint8_t tmp[dim * dim];  /* VLA — точный размер среза */
    for (int t = 0; t < k; t++) {
        for (int i = 0; i < dim; i++)
            for (int j = 0; j < dim; j++)
                tmp[i * dim + j] = mat[j * dim + (dim - 1 - i)];
        memcpy(mat, tmp, dim * dim);
    }
}

static void get_slice(const Cube *c, int axis, int pos, uint8_t sl[MAX_SLICE]) {
    int dim = c->dim;
    int p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if (axis == 0)      sl[i*dim+j] = c->data[idx3(dim,p,i,j)];
            else if (axis == 1) sl[i*dim+j] = c->data[idx3(dim,i,p,j)];
            else                sl[i*dim+j] = c->data[idx3(dim,i,j,p)];
        }
}

static void set_slice(Cube *c, int axis, int pos, const uint8_t *sl) {
    int dim = c->dim;
    int p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if (axis == 0)      c->data[idx3(dim,p,i,j)] = sl[i*dim+j];
            else if (axis == 1) c->data[idx3(dim,i,p,j)] = sl[i*dim+j];
            else                c->data[idx3(dim,i,j,p)] = sl[i*dim+j];
        }
}

static void rotate_slice(Cube *c, int axis, int pos, int k) {
    uint8_t sl[c->dim * c->dim];  /* VLA — точный размер среза */
    get_slice(c, axis, pos, sl);
    rot90_2d(sl, c->dim, k);
    set_slice(c, axis, pos, sl);
}

static void rotate_whole_cube(Cube *c, int axis, int k) {
    k = ((k % 4) + 4) % 4;
    int dim = c->dim, total = dim*dim*dim;
    uint8_t tmp[total];  /* VLA — точный размер куба */
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
    uint8_t tmp[total];  /* VLA — точный размер куба */
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
    idx1 = ((idx1%dim)+dim)%dim;
    idx2 = ((idx2%dim)+dim)%dim;
    uint8_t s1[dim * dim], s2[dim * dim];  /* VLA */
    get_slice(c,axis,idx1,s1); get_slice(c,axis,idx2,s2);
    set_slice(c,axis,idx1,s2); set_slice(c,axis,idx2,s1);
}

static void bitwise_rotate_cube(Cube *c, int n, int right) {
    int total = c->dim*c->dim*c->dim;
    for (int i = 0; i < total; i++)
        c->data[i] = right ? rotate_right(c->data[i],n) : rotate_left(c->data[i],n);
}

static void mix_cube(uint8_t *data, int n) {
    for (int i = 1; i < n; i++) data[i] ^= data[i-1];
}
static void inv_mix_cube(uint8_t *data, int n) {
    for (int i = n-1; i >= 1; i--) data[i] ^= data[i-1];
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

typedef struct { uint8_t type; int8_t name; int8_t dir; } BaseOp;
#define MAX_BASE_OPS 256
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
#define N_STATIC_BASE 107

static void build_prim_op_from_base_idx(PrimOp *out, int base_idx) {
    int i = base_idx;
    if (i<24) { out->type=OP_FACE;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=24;
    if (i<12) { out->type=OP_SLICE;   out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i<24) { out->type=OP_WIDE;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=24;
    if (i<12) { out->type=OP_CUBE_ROT;out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i<12) { out->type=OP_ALG;     out->name=(int8_t)i;     out->dir=0;             return; } i-=12;
    if (i< 8) { out->type=OP_PATTERN; out->name=(int8_t)(12+i);out->dir=0;             return; } i-=8;
    if (i<12) { out->type=OP_SWAP;    out->name=(int8_t)(i/4); out->dir=(int8_t)(i%4); return; } i-=12;
    if (i< 3) { out->type=OP_DIAGFLIP;out->name=(int8_t)i;     out->dir=0;             return; }
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
    strncpy(buf, moves_str, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
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

    if (type == OP_FACE) {
        rotate_slice(cube, face_axis[name & 7], face_pos[name & 7], k);
    } else if (type == OP_SLICE) {
        rotate_slice(cube, slice_axis[name % 3], 1, k);
    } else if (type == OP_WIDE) {
        int axis = wide_axis[name & 7];
        rotate_slice(cube, axis, 0, k);
        rotate_slice(cube, axis, 1, k);
    } else if (type == OP_CUBE_ROT) {
        rotate_whole_cube(cube, cube_axis[name % 3], k);
    } else if (type == OP_ALG || type == OP_PATTERN) {
        apply_alg_string(cube, ALGS[name % NUM_ALGS].moves, inverse);
    } else if (type == OP_SWAP) {
        int offset = dir;
        swap_layers(cube, name % 3, offset, offset + 1);
    } else if (type == OP_DIAGFLIP) {
        diagflip(cube, name % 3);
    }
}

static void apply_composed_op(Cube *cube, const ComposedOp *cop, int inverse) {
    if (inverse) {
        for (int i = cop->len - 1; i >= 0; i--)
            apply_prim_op(cube, &cop->moves[i], 1);
    } else {
        for (int i = 0; i < cop->len; i++)
            apply_prim_op(cube, &cop->moves[i], 0);
    }
}

static void build_op_table(const uint8_t key[32]) {
    for (int i=0; i<NUM_OPS; i++) {
        uint8_t h[32], buf[KEY_SIZE+7+4];
        memcpy(buf,key,KEY_SIZE);
        memcpy(buf+KEY_SIZE,"WBC1_OP",7);
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
    uint8_t key_hash[32];
    sha256(key,KEY_SIZE,key_hash);
    MT mt; mt_seed(&mt,sha256_seed(key_hash));
    int order[NUM_OPS];
    for (int i=0;i<NUM_OPS;i++) order[i]=i;
    mt_shuffle(&mt,order,NUM_OPS);
    ComposedOp tmp[NUM_OPS];
    memcpy(tmp,g_ops,sizeof(g_ops));
    for (int i=0;i<NUM_OPS;i++) g_ops[i]=tmp[order[i]];
}

/* ==========================================================================
 * ТАБЛИЦА ПЕРЕСТАНОВОК — ускорение ×30-100
 *
 * Каждая из 127 составных операций куба — это перестановка N байт.
 * Вместо ~13 000 обращений через поворот срезов, apply_operation делает
 * всего N table-lookup'ов (обычно 27 для куба 3×3×3).
 *
 * perm_fwd[op*bs + i] = j : на выходе в позиции i стоит байт из позиции j
 * perm_inv[op*bs + i] = j : обратная операция
 *
 * Таблица строится ОДИН РАЗ при первом вызове cascade_encrypt/decrypt
 * с данным block_size.  При смене block_size — перестраивается.
 * ========================================================================== */
static uint16_t *g_perms_buf = NULL;   /* размер: 2 * NUM_OPS * g_perm_bs элементов uint16_t */
static int      g_perm_bs   = -1;

static void build_perm_table(int block_size) {
    if (g_perm_bs == block_size) return;
    free(g_perms_buf);
    g_perms_buf = (uint16_t *)malloc((size_t)2 * NUM_OPS * block_size * sizeof(uint16_t));
    g_perm_bs   = block_size;
    int dim     = dim_for(block_size);
    uint8_t tmp[block_size];   /* VLA рабочий буфер */

    for (int op = 0; op < NUM_OPS; op++) {
        uint16_t *fwd = g_perms_buf + (size_t) op            * block_size;
        uint16_t *inv = g_perms_buf + (size_t)(op + NUM_OPS) * block_size;

        /* Проход 1: tmp[i] = i & 0xFF  →  после перестановки: tmp[j] = source_j & 0xFF */
        for (int i = 0; i < block_size; i++) tmp[i] = (uint8_t)(i & 0xFF);
        { Cube c = { tmp, dim }; apply_composed_op(&c, &g_ops[op], 0); }
        for (int j = 0; j < block_size; j++) fwd[j] = (uint16_t)tmp[j];  /* младший байт */

        /* Проход 2 (только если block_size > 256): добавляем старший байт */
        if (block_size > 256) {
            for (int i = 0; i < block_size; i++) tmp[i] = (uint8_t)(i >> 8);
            { Cube c = { tmp, dim }; apply_composed_op(&c, &g_ops[op], 0); }
            for (int j = 0; j < block_size; j++) fwd[j] |= (uint16_t)((uint16_t)tmp[j] << 8);
        }

        /* Строим обратную перестановку */
        for (int i = 0; i < block_size; i++) inv[fwd[i]] = (uint16_t)i;
    }
}

static void apply_operation(Cube *cube, int op_id, int inverse) {
    int idx = ((op_id % NUM_OPS) + NUM_OPS) % NUM_OPS;
    int bs  = cube->dim * cube->dim * cube->dim;
    const uint16_t *perm = inverse
        ? g_perms_buf + (size_t)(idx + NUM_OPS) * bs
        : g_perms_buf + (size_t) idx            * bs;
    uint8_t tmp[bs];    /* VLA */
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
    int fill_len = (int)data[data_len-block_bytes] |
                   ((int)data[data_len-block_bytes+1]<<8);
    size_t strip = block_bytes+fill_len;
    if (strip > data_len) { *out_len=0; return (uint8_t*)calloc(1,1); }
    *out_len = data_len-strip;
    uint8_t *out = (uint8_t *)malloc(*out_len+1);
    memcpy(out,data,*out_len);
    out[*out_len] = 0;
    return out;
}

/* ==========================================================================
 * НОВАЯ derive_cascade_key — без SHA, нелинейная, полный лавинный эффект
 * ==========================================================================
 *
 * 4 раунда F+B mixing на block_bytes, вывод → 32 байта.
 * Без SHA-256: быстро. 4 раунда достаточно для avalanche ~50% (проверено).
 * ========================================================================== */
static void derive_cascade_key(const uint8_t *enc_block, int block_bytes,
                                uint8_t new_rk[KEY_SIZE]) {
    /* Шаг 1: копируем/сворачиваем в 64-байтовое состояние S */
    uint8_t S[64] = {0};
    for (int j = 0; j < block_bytes; j++)
        S[j & 63] ^= enc_block[j];

    /* Шаг 2: 4 раунда F+B mixing с modular add (нелинейность через carry). */
    for (int r = 0; r < 4; r++) {
        uint8_t c = (uint8_t)(S[63] ^ r);
        for (int i = 0; i < 64; i++) {
            c = (uint8_t)(S[i] + rotate_left(c, 5) + (uint8_t)(67*i + 29*r));
            S[i] = c;
        }
        c = (uint8_t)(S[0] ^ (uint8_t)(r * 37));
        for (int i = 63; i >= 0; i--) {
            c = S[i] ^ rotate_right(c, 3);
            S[i] = c;
        }
    }

    /* Шаг 3: берём первые KEY_SIZE байт */
    memcpy(new_rk, S, KEY_SIZE);
}

/* ==========================================================================
 * derive_parallel_key — детерминированный ключ блока для PWBC1.1
 *
 * Принимает master_key и номер блока (block_idx), а НЕ шифртекст.
 * Это делает ключ каждого блока независимым → можно шифровать параллельно.
 *
 * Структура идентична derive_cascade_key, но источник "блока" —
 * 8-байтовый little-endian block_idx, растянутый до KEY_SIZE байт через XOR.
 * ========================================================================== */
static void derive_parallel_key(const uint8_t master[KEY_SIZE], size_t block_idx,
                                 uint8_t out[KEY_SIZE]) {
    /* Шаг 1: XOR master_key с индексом блока */
    uint8_t F[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++)
        F[i] = master[i] ^ (uint8_t)(block_idx >> ((i % 8) * 8));

    /* Шаг 2: прямой проход (нелинейность, идентично derive_cascade_key) */
    uint8_t c = F[KEY_SIZE - 1];
    for (int i = 0; i < KEY_SIZE; i++) {
        c = (uint8_t)(F[i] + rotate_left(c, 5) + (uint8_t)(29 * i));
        F[i] = c;
    }

    /* Шаг 3: обратный проход (полная диффузия) */
    c = F[0];
    for (int i = KEY_SIZE - 1; i >= 0; i--) {
        c = F[i] ^ rotate_right(c, 3);
        out[i] = c;
    }
}

/* ==========================================================================
 * НОВЫЕ encrypt_block / decrypt_block — без SHA, 32 раунда
 * ==========================================================================
 *
 * Раундовый ключ выводится прямо из cascade key без SHA:
 *   op_id    = key_mat[r] % 127
 *   RK_r[i]  = ROL8(key_mat[(i + r*7) % 32], r & 7)
 *
 * r*7: шаг 7 взаимно прост с 32 → за 32 шага каждый байт ключа используется
 * ровно один раз в каждой позиции блока (cyclic cover).
 * r & 7: разная ротация в каждом раунде → корреляция между раундами мала.
 * ========================================================================== */

static void encrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int dim        = dim_for(block_size);
    int cube_bytes = block_size;

    /* Предвычисляем таблицу раундовых ключей: ROUNDS×block_size байт (<=32×343=10976 B, влезает в L1d) */
    uint8_t rk[ROUNDS][block_size];
    for (int r = 0; r < ROUNDS; r++) {
        int shift = r & 7;
        for (int i = 0; i < cube_bytes; i++)
            rk[r][i] = rotate_left(key_mat[(i + r * 7) % KEY_SIZE], shift);
    }

    uint8_t cube_data[block_size];  /* VLA — нет calloc */
    Cube cube = { cube_data, dim };
    memcpy(cube.data, block, cube_bytes);

    for (int r = 0; r < ROUNDS; r++) {
        int op_id = key_mat[r] % NUM_OPS;
        apply_operation(&cube, op_id, 0);
        mix_cube(cube.data, cube_bytes);
        /* XOR с раундовым ключом — только чтение из rk (нет mod/ROL в горячем пути) */
        for (int i = 0; i < cube_bytes; i++)
            cube.data[i] ^= rk[r][i];
        bitwise_rotate_cube(&cube, op_id, 1 /* right */);
    }
    memcpy(out, cube.data, cube_bytes);
}

static void decrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int dim        = dim_for(block_size);
    int cube_bytes = block_size;

    /* Предвычисляем таблицу раундовых ключей (та же, что при шифровании) */
    uint8_t rk[ROUNDS][block_size];
    for (int r = 0; r < ROUNDS; r++) {
        int shift = r & 7;
        for (int i = 0; i < cube_bytes; i++)
            rk[r][i] = rotate_left(key_mat[(i + r * 7) % KEY_SIZE], shift);
    }

    uint8_t cube_data[block_size];  /* VLA — нет calloc */
    Cube cube = { cube_data, dim };
    memcpy(cube.data, block, cube_bytes);

    for (int r = ROUNDS - 1; r >= 0; r--) {
        int op_id = key_mat[r] % NUM_OPS;
        bitwise_rotate_cube(&cube, op_id, 0 /* left */);
        for (int i = 0; i < cube_bytes; i++)
            cube.data[i] ^= rk[r][i];
        inv_mix_cube(cube.data, cube_bytes);
        apply_operation(&cube, op_id, 1 /* inverse */);
    }
    memcpy(out, cube.data, cube_bytes);
}

/* ── KDF + HMAC (used once per message, not per block) ──────────────────── */

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
 * cascade_encrypt / cascade_decrypt
 *
 * Параметр double_pass:
 *   0 = одиночный каскад (только проход 1, вперёд)
 *   1 = двойной каскад  (проход 1 вперёд + проход 2 назад)
 * ========================================================================== */

static uint8_t *cascade_encrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode,
                                  const uint8_t *iv_in, int block_size,
                                  uint8_t **iv_out, size_t *iv_len_out,
                                  int double_pass,
                                  size_t *out_len) {
    int block_bytes = block_size;
    build_op_table(master_key);
    g_perm_bs = -1;
    build_perm_table(block_bytes);
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
            memcpy(*iv_out, iv, block_bytes);
            *iv_len_out = block_bytes;
        }
    } else {
        if (iv_out) { *iv_out = NULL; *iv_len_out = 0; }
    }

    uint8_t rk[KEY_SIZE];
    memcpy(rk, master_key, KEY_SIZE);

    uint8_t prev[4096], tmp_block[4096], enc_prev[4096];
    memcpy(prev, iv, block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = padded + b * block_bytes;
        uint8_t       *out_b = inter  + b * block_bytes;

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
            for (int i=block_bytes-1; i>=0 && carry; i--) {
                int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
            }
        }
    }

    free(padded);

    if (!double_pass) {
        *out_len = padded_len;
        return inter;
    }

    uint8_t rk_bwd[KEY_SIZE];
    derive_cascade_key(master_key, KEY_SIZE, rk_bwd);

    for (int b = (int)n_blocks - 1; b >= 0; b--) {
        encrypt_block(rk_bwd, inter + b * block_bytes, block_size,
                      result + b * block_bytes);
        derive_cascade_key(result + b * block_bytes, block_bytes, rk_bwd);
    }

    *out_len = padded_len;
    free(inter);
    return result;
}

static uint8_t *cascade_decrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode, const uint8_t *iv,
                                  int block_size, int double_pass,
                                  size_t *out_len) {
    int block_bytes = block_size;
    build_op_table(master_key);
    g_perm_bs = -1;
    build_perm_table(block_bytes);
    size_t n_blocks = data_len / block_bytes;

    uint8_t *inter     = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len + 1);

    if (double_pass) {
        uint8_t rk_bwd[KEY_SIZE];
        derive_cascade_key(master_key, KEY_SIZE, rk_bwd);

        for (int b = (int)n_blocks - 1; b >= 0; b--) {
            decrypt_block(rk_bwd, data + b * block_bytes, block_size,
                          inter + b * block_bytes);
            derive_cascade_key(data + b * block_bytes, block_bytes, rk_bwd);
        }
    } else {
        memcpy(inter, data, data_len);
    }

    uint8_t rk[KEY_SIZE];
    memcpy(rk, master_key, KEY_SIZE);

    uint8_t prev[4096], enc_prev[4096], tmp[4096];
    if (iv) memcpy(prev, iv, block_bytes);
    else    memset(prev, 0,  block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = inter + b * block_bytes;
        uint8_t       *out_b = decrypted + b * block_bytes;

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
            for (int i=block_bytes-1; i>=0 && carry; i--) {
                int v=prev[i]+carry; prev[i]=(uint8_t)(v&0xFF); carry=v>>8;
            }
        }
    }

    uint8_t *res = wbc1_unpad(decrypted, data_len, block_bytes, out_len);
    free(inter); free(decrypted);
    return res;
}

/* ── WBC-CTR-HMAC (одиночный каскад, CTR — всегда) ──────────────────────── */

static uint8_t *cascade_encrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           int block_size,
                                           const uint8_t *nonce_in,
                                           size_t *out_len) {
    int block_bytes = block_size;
    build_perm_table(block_bytes);   /* строим таблицу перестановок один раз */
    uint8_t nonce[NONCE_SIZE];
    if (nonce_in) memcpy(nonce,nonce_in,NONCE_SIZE);
    else RAND_bytes(nonce,NONCE_SIZE);

    uint8_t key_crypt[32], key_mac[32];
    kdf(key, nonce, key_crypt, key_mac);

    size_t padded_len;
    uint8_t *padded  = wbc1_pad(data, data_len, block_bytes, &padded_len);
    size_t n_blocks  = padded_len / block_bytes;
    uint8_t *cipher  = (uint8_t *)malloc(padded_len);

    /* ── Параллельное CTR шифрование ────────────────────────────────────── */
    int ctr_tail_sz = (block_bytes > NONCE_SIZE) ? block_bytes-NONCE_SIZE : 1;
    #pragma omp parallel for schedule(dynamic)
    for (size_t b = 0; b < n_blocks; b++) {
        uint8_t bk[KEY_SIZE];
        derive_parallel_key(key_crypt, b, bk);
        uint8_t ctr_block[4096] = {0};
        memcpy(ctr_block, nonce, NONCE_SIZE);
        for (int i=ctr_tail_sz-1; i>=0; i--)
            ctr_block[NONCE_SIZE+i] = (uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(bk, ctr_block, block_size, enc_ctr);
        for (int i=0; i<block_bytes; i++)
            cipher[b*block_bytes+i] = padded[b*block_bytes+i] ^ enc_ctr[i];
    }
    free(padded);

    size_t hdr_len = MAGIC_LEN+1+2+NONCE_SIZE;
    uint8_t header[32];
    memcpy(header,MAGIC,MAGIC_LEN);
    header[MAGIC_LEN]   = VERSION_CASC;
    header[MAGIC_LEN+1] = (uint8_t)(block_size>>8);
    header[MAGIC_LEN+2] = (uint8_t)(block_size&0xFF);
    memcpy(header+MAGIC_LEN+3, nonce, NONCE_SIZE);

    uint8_t mac[32];
    uint8_t *mac_in = (uint8_t *)malloc(hdr_len+padded_len);
    memcpy(mac_in,header,hdr_len);
    memcpy(mac_in+hdr_len,cipher,padded_len);
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
    int block_size = ((int)file_bytes[MAGIC_LEN+1]<<8)|file_bytes[MAGIC_LEN+2];
    build_perm_table(block_size);   /* строим таблицу перестановок один раз */
    const uint8_t *nonce = file_bytes+MAGIC_LEN+3;
    size_t hdr_len       = MAGIC_LEN+1+2+NONCE_SIZE;
    const uint8_t *mac_actual = file_bytes+file_len-MAC_SIZE;
    const uint8_t *cipher     = file_bytes+hdr_len;
    size_t cipher_len         = file_len-hdr_len-MAC_SIZE;

    uint8_t key_crypt[32], key_mac[32];
    kdf(key, nonce, key_crypt, key_mac);

    uint8_t mac_expected[32];
    uint8_t *mac_in = (uint8_t *)malloc(hdr_len+cipher_len);
    memcpy(mac_in,file_bytes,hdr_len);
    memcpy(mac_in+hdr_len,cipher,cipher_len);
    hmac_sha256(key_mac,32,mac_in,hdr_len+cipher_len,mac_expected);
    free(mac_in);

    int diff = 0;
    for (int i=0;i<MAC_SIZE;i++) diff |= mac_actual[i]^mac_expected[i];
    if (diff!=0) { fprintf(stderr,"ERROR: MAC failed\n"); return NULL; }

    int block_bytes = block_size;
    size_t n_blocks = cipher_len/block_bytes;
    uint8_t *plain  = (uint8_t *)malloc(cipher_len+1);
    int ctr_tail_sz = (block_bytes>NONCE_SIZE) ? block_bytes-NONCE_SIZE : 1;

    /* ── Параллельное CTR дешифрование ───────────────────────────────────── */
    #pragma omp parallel for schedule(dynamic)
    for (size_t b=0; b<n_blocks; b++) {
        uint8_t bk[KEY_SIZE];
        derive_parallel_key(key_crypt, b, bk);
        uint8_t ctr_block[4096]={0};
        memcpy(ctr_block,nonce,NONCE_SIZE);
        for (int i=ctr_tail_sz-1;i>=0;i--)
            ctr_block[NONCE_SIZE+i]=(uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(bk, ctr_block, block_size, enc_ctr);
        for (int i=0;i<block_bytes;i++)
            plain[b*block_bytes+i] = cipher[b*block_bytes+i] ^ enc_ctr[i];
    }
    uint8_t *result = wbc1_unpad(plain, cipher_len, block_bytes, out_len);
    free(plain);
    return result;
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
    for (int i=0;i<256;i++) if (freq[i]) { double p=(double)freq[i]/(double)len; h-=p*log2(p); }
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

static void statistics_tests(const uint8_t *plain, size_t plain_len,
                               const uint8_t *cipher, size_t cipher_len) {
    printf("\n  === STATISTICAL TESTS ===\n");
    printf("  Shannon entropy (plain):   %.4f bits/byte\n", shannon_entropy(plain,plain_len));
    printf("  Shannon entropy (cipher):  %.4f bits/byte  (ideal 8.0)\n", shannon_entropy(cipher,cipher_len));
    printf("  Chi-square (ciphertext):   %.2f         (ideal ~256)\n", chi_square_uniform(cipher,cipher_len));
    size_t cmp_len = plain_len < cipher_len ? plain_len : cipher_len;
    printf("  Correlation plain<->cipher:%.4f             (ideal ~0)\n", correlation(plain,cipher,cmp_len));
    int reps=0;
    for (size_t i=1;i<cipher_len;i++) if (cipher[i]==cipher[i-1]) reps++;
    printf("  Adjacent byte repeats:     %d\n", reps);
}

/* ── NIST helpers ────────────────────────────────────────────────────────── */

static inline int nist_get_bit(const uint8_t *data, size_t i) {
    return (data[i/8]>>(7-(i%8)))&1;
}
static double normal_cdf(double x) { return 0.5*erfc(-x/sqrt(2.0)); }
static double chi2_pvalue_approx(double chi2, double df) {
    if (df<=0.0) return 0.0; if (chi2<=0.0) return 1.0;
    double a=pow(chi2/df,1.0/3.0), mu=1.0-2.0/(9.0*df), sigma=sqrt(2.0/(9.0*df));
    return 1.0-normal_cdf((a-mu)/sigma);
}
static void nist_print_result(const char *name, double p) {
    printf("  %-34s p=%.6f  %s\n", name, p, (p>=0.01?"PASS ✓":"FAIL ✗"));
}
static void nist_print_skip(const char *name, const char *why) {
    printf("  %-34s %-8s (%s)\n", name, "SKIP", why);
}

static void nist_sts_quick_tests(const uint8_t *cipher, size_t cipher_len) {
    size_t n = cipher_len*8;
    printf("\n  === NIST STS QUICK ===\n");
    if (n < 1024) { printf("  NOTE: too few bits (%zu). Need >= 1024.\n", n); return; }

    /* 1) Frequency */
    long s=0;
    for (size_t i=0;i<n;i++) s += nist_get_bit(cipher,i)?1:-1;
    nist_print_result("Frequency (Monobit)", erfc(fabs((double)s)/sqrt(2.0*(double)n)));

    /* 2) Block Frequency */
    { const int M=128; size_t N=n/M;
      if (N>0) {
          double chi2=0.0;
          for (size_t b=0;b<N;b++) {
              int ones=0;
              for (int j=0;j<M;j++) ones+=nist_get_bit(cipher,b*M+(size_t)j);
              double pi=(double)ones/(double)M; chi2+=(pi-0.5)*(pi-0.5);
          }
          nist_print_result("Block Frequency (M=128)", chi2_pvalue_approx(chi2*4.0*M,(double)N));
      }
    }

    /* 3) Runs */
    { long ones=0;
      for (size_t i=0;i<n;i++) ones+=nist_get_bit(cipher,i);
      double pi=(double)ones/(double)n;
      if (fabs(pi-0.5)>=2.0/sqrt((double)n)) { nist_print_result("Runs",0.0); }
      else {
          long vn=1;
          for (size_t i=1;i<n;i++) if (nist_get_bit(cipher,i)!=nist_get_bit(cipher,i-1)) vn++;
          double num=fabs((double)vn-2.0*(double)n*pi*(1.0-pi));
          double den=2.0*sqrt(2.0*(double)n)*pi*(1.0-pi);
          nist_print_result("Runs", erfc(num/den));
      }
    }

    /* 4) Cumulative Sums */
    { long zf=0,sf=0;
      for (size_t i=0;i<n;i++) { sf+=nist_get_bit(cipher,i)?1:-1; long a=labs(sf); if(a>zf)zf=a; }
      if (zf==0) { nist_print_result("Cumulative Sums (forward)",1.0); }
      else {
          double sum1=0.0,sum2=0.0;
          int kmin=(int)(-(double)n/zf+1.0)/4, kmax=(int)(((double)n/zf-1.0)/4.0);
          for (int k=kmin;k<=kmax;k++) {
              sum1+=normal_cdf((4.0*k+1.0)*zf/sqrt((double)n))-normal_cdf((4.0*k-1.0)*zf/sqrt((double)n));
              sum2+=normal_cdf((4.0*k+3.0)*zf/sqrt((double)n))-normal_cdf((4.0*k+1.0)*zf/sqrt((double)n));
          }
          nist_print_result("Cumulative Sums (forward)", 1.0-sum1+sum2);
      }
    }

    /* 5) Approximate Entropy */
    if (n<100000) { nist_print_skip("Approximate Entropy (m=8)","need >=100000 bits"); }
    else {
        int m=8; size_t cnt_m=(size_t)1<<m, cnt_m1=(size_t)1<<(m+1);
        size_t *f0=(size_t*)calloc(cnt_m,sizeof(size_t));
        size_t *f1=(size_t*)calloc(cnt_m1,sizeof(size_t));
        if (f0&&f1) {
            for (size_t i=0;i<n;i++) {
                unsigned p0=0,p1=0;
                for (int j=0;j<m;j++) p0=(p0<<1)|(unsigned)nist_get_bit(cipher,(i+(size_t)j)%n);
                for (int j=0;j<m+1;j++) p1=(p1<<1)|(unsigned)nist_get_bit(cipher,(i+(size_t)j)%n);
                f0[p0]++; f1[p1]++;
            }
            double phi_m=0.0,phi_m1=0.0;
            for (size_t i=0;i<cnt_m;i++) if(f0[i]){double p=(double)f0[i]/(double)n;phi_m+=p*log(p);}
            for (size_t i=0;i<cnt_m1;i++) if(f1[i]){double p=(double)f1[i]/(double)n;phi_m1+=p*log(p);}
            double apen=phi_m-phi_m1;
            double chi2=2.0*(double)n*(log(2.0)-apen);
            nist_print_result("Approximate Entropy (m=8)",chi2_pvalue_approx(chi2,(double)(1<<(m-1))));
        }
        if(f0)free(f0); if(f1)free(f1);
    }
}

/* ── self-tests ──────────────────────────────────────────────────────────── */

static void run_self_tests(const uint8_t key[32], EncMode mode, int double_pass) {
    printf("\n%s\n","────────────────────────────────────────────────────────────");
    printf("  Self-tests  |  mode=%s  cascade=%s\n",
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
    int n = (int)(sizeof(tests)/sizeof(tests[0]));
    int passed = 0;

    for (int t=0; t<n; t++) {
        int block_size = auto_block_size((int)tests[t].len);
        size_t enc_len=0, dec_len=0;
        int ok=0;

        if (mode==MODE_WBC_CTR_HMAC) {
            uint8_t *enc = cascade_encrypt_ctr_hmac(key, tests[t].data, tests[t].len,
                                                    block_size, NULL, &enc_len);
            uint8_t *dec = cascade_decrypt_ctr_hmac(key, enc, enc_len, &dec_len);
            ok = dec && dec_len==tests[t].len && memcmp(dec,tests[t].data,dec_len)==0;
            free(enc); if (dec) free(dec);
        } else {
            uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *enc = cascade_encrypt(key, tests[t].data, tests[t].len,
                                           mode, NULL, block_size, &iv, &iv_len,
                                           double_pass, &enc_len);
            uint8_t *dec = cascade_decrypt(key, enc, enc_len, mode, iv,
                                           block_size, double_pass, &dec_len);
            ok = dec_len==tests[t].len && memcmp(dec,tests[t].data,dec_len)==0;
            free(enc); free(dec); if (iv) free(iv);
        }
        printf("  %-35s %s\n", tests[t].label, ok?"PASS ✓":"FAIL ✗");
        if (ok) passed++;
    }
    printf("%s\n","────────────────────────────────────────────────────────────");
    printf("  Results: %d/%d passed\n\n", passed, n);
    free(d10k); free(d100k);
}

/* ── benchmark ───────────────────────────────────────────────────────────── */

static void benchmark(const uint8_t key[32], EncMode mode, int double_pass) {
    static const int sizes[] = {1,10,100,1000,10000,100000,1000000,10000000};
    int ns = (int)(sizeof(sizes)/sizeof(sizes[0]));
    int repeats = 3;

    printf("\n  Benchmark  |  mode=%s  cascade=%s\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE");
    printf("  %10s  %10s  %14s  %14s  Integrity\n","Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)");
    printf("  %s\n","----------------------------------------------------------------");

    for (int si=0; si<ns; si++) {
        int sz = sizes[si];
        uint8_t *data = (uint8_t*)malloc(sz);
        RAND_bytes(data, sz);
        int block_size = auto_block_size(sz);
        int all_ok = 1;

        /* warmup: build perm table + first enc/dec, not timed */
        {
            size_t el=0, dl=0; uint8_t *iv=NULL; size_t iv_len=0;
            uint8_t *e=NULL, *d=NULL;
            if (mode==MODE_WBC_CTR_HMAC) {
                e = cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&el);
                d = cascade_decrypt_ctr_hmac(key,e,el,&dl);
            } else {
                e = cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&el);
                d = cascade_decrypt(key,e,el,mode,iv,block_size,double_pass,&dl);
                if (iv) free(iv);
            }
            free(e); if (d) free(d);
        }

        double enc_total=0.0, dec_total=0.0;
        for (int r=0; r<repeats; r++) {
            struct timespec t0,t1;
            size_t enc_len=0, dec_len=0;
            uint8_t *enc=NULL, *dec=NULL;
            uint8_t *iv=NULL; size_t iv_len=0;

            /* time encrypt only */
            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC)
                enc = cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&enc_len);
            else
                enc = cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            enc_total += (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            /* time decrypt only */
            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC)
                dec = cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            else
                dec = cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            dec_total += (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            if (!dec||dec_len!=(size_t)sz||memcmp(dec,data,sz)!=0) all_ok=0;
            if (iv) free(iv);
            free(enc); if (dec) free(dec);
        }
        double enc_avg = enc_total/repeats;
        double dec_avg = dec_total/repeats;
        double enc_spd = ((double)sz/1024.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_spd = ((double)sz/1024.0)/(dec_avg>0?dec_avg:1e-9);
        printf("  %10.2f  %10.5f  %14.2f  %14.2f  %s\n",
               (double)sz/1024.0, enc_avg, enc_spd, dec_spd, all_ok?"OK":"FAIL");
        free(data);
    }
    printf("\n");
}

/* ── per-block cascade avalanche ─────────────────────────────────────────────── */
/* K^(src->tgt) = (1/n)*sum_j [ct_ref[tgt]_j xor ct_mod[tgt]_j]                */
/* diagonal ~6% (local), above diagonal ~50% (cascade key changed), ideal 50%   */

static void per_block_avalanche(const uint8_t key[KEY_SIZE], const uint8_t *data,
                                 size_t data_len) {
    if (data_len==0) { printf("  Per-block avalanche: N/A\n"); return; }
    int fixed_bs = 64;
    build_op_table(key);
    g_perm_bs = -1;
    build_perm_table(fixed_bs);
    size_t padded_len;
    uint8_t *padded = wbc1_pad(data, data_len, fixed_bs, &padded_len);
    size_t N = padded_len / fixed_bs;
    int n_bits = fixed_bs * 8;
    if (N == 0) { free(padded); return; }

    /* Pre-compute reference cascade: ct_ref[b] with real cascade keys */
    uint8_t **ct_ref = malloc(N * sizeof(uint8_t *));
    uint8_t **rk_arr = malloc(N * sizeof(uint8_t *));
    double   *col_sum = calloc(N, sizeof(double));
    int      *col_cnt = calloc(N, sizeof(int));
    for (size_t i = 0; i < N; i++) {
        ct_ref[i] = malloc(fixed_bs);
        rk_arr[i] = malloc(KEY_SIZE);
    }
    memcpy(rk_arr[0], key, KEY_SIZE);
    for (size_t b = 0; b < N; b++) {
        encrypt_block(rk_arr[b], padded + b * fixed_bs, fixed_bs, ct_ref[b]);
        if (b + 1 < N)
            derive_cascade_key(ct_ref[b], fixed_bs, rk_arr[b + 1]);
    }

    int wide = (N > 8);
    printf("  Cascade K^(src->tgt): %zu block(s), %d bits/block:\n", N, n_bits);

    uint8_t *ct_mod  = malloc(fixed_bs);
    uint8_t *rk_cur  = malloc(KEY_SIZE);
    uint8_t *blk_mod = malloc(fixed_bs);
    double grand_total = 0.0;
    int    grand_count = 0;

    for (size_t src = 0; src < N; src++) {
        int N_SAMPLE = (n_bits > 64) ? 64 : n_bits;
        int step     = n_bits / N_SAMPLE;
        long long *diff = calloc(N, sizeof(long long));

        for (int bit = 0; bit < n_bits; bit += step) {
            memcpy(blk_mod, padded + src * fixed_bs, fixed_bs);
            blk_mod[bit/8] ^= (uint8_t)(1u << (bit%8));
            memcpy(rk_cur, rk_arr[src], KEY_SIZE);
            encrypt_block(rk_cur, blk_mod, fixed_bs, ct_mod);
            for (int j = 0; j < fixed_bs; j++)
                diff[src] += __builtin_popcount(ct_ref[src][j] ^ ct_mod[j]);
            uint8_t rk_next[KEY_SIZE];
            derive_cascade_key(ct_mod, fixed_bs, rk_next);
            uint8_t ct_tmp[fixed_bs];
            for (size_t tgt = src+1; tgt < N; tgt++) {
                encrypt_block(rk_next, padded + tgt*fixed_bs, fixed_bs, ct_tmp);
                for (int j = 0; j < fixed_bs; j++)
                    diff[tgt] += __builtin_popcount(ct_ref[tgt][j] ^ ct_tmp[j]);
                derive_cascade_key(ct_tmp, fixed_bs, rk_next);
            }
        }

        int samples = n_bits / step;
        for (size_t tgt = src; tgt < N; tgt++) {
            double pct = 100.0*(double)diff[tgt]/((double)samples*n_bits);
            grand_total += pct; grand_count++;
            col_sum[tgt] += pct; col_cnt[tgt]++;
        }
        free(diff);
    }

    /* Column averages */
    printf("  col_avg: |");
    double col_grand = 0.0;
    for (size_t t = 0; t < N; t++) {
        double ca = col_cnt[t]>0 ? col_sum[t]/col_cnt[t] : 0.0;
        if (wide) printf("%5.1f%%|", ca);
        else      printf("  %5.1f%% |", ca);
        col_grand += ca;
    }
    printf(" %6.1f%%\n", N>0 ? col_grand/N : 0.0);
    printf("  Overall K^ = %.1f%%  (diagonal~6%%, cascade~50%%, ideal 50%%)\n\n",
           grand_count>0 ? grand_total/grand_count : 0.0);

    free(ct_mod); free(rk_cur); free(blk_mod);
    free(col_sum); free(col_cnt);
    for (size_t i = 0; i < N; i++) { free(ct_ref[i]); free(rk_arr[i]); }
    free(ct_ref); free(rk_arr); free(padded);
}

/* ── avalanche test (повний шифртекст, SAC формула (3)) ──────────────────────── */

static void avalanche_test(const uint8_t key[KEY_SIZE], const uint8_t *data,
                            size_t data_len, EncMode mode, int double_pass) {
    if (data_len==0) { printf("  Avalanche effect: N/A\n"); return; }
    int is_stream = (mode==MODE_CTR||mode==MODE_WBC_CTR_HMAC);
    int block_size = auto_block_size((int)data_len);
    size_t enc_len0=0;
    uint8_t *iv0=NULL; size_t iv0_len=0;
    uint8_t *enc0;
    const uint8_t *ref; size_t ref_len;
    const uint8_t *nonce0=NULL;

    if (mode==MODE_WBC_CTR_HMAC) {
        enc0 = cascade_encrypt_ctr_hmac(key,data,data_len,block_size,NULL,&enc_len0);
        size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
        ref=enc0+hdr; ref_len=enc_len0-hdr-MAC_SIZE; nonce0=enc0+MAGIC_LEN+3;
    } else {
        enc0 = cascade_encrypt(key,data,data_len,mode,NULL,block_size,&iv0,&iv0_len,double_pass,&enc_len0);
        ref=enc0; ref_len=enc_len0;
    }

    long long total_flips=0, total_bits=(long long)ref_len*8;
    size_t flip_count = is_stream ? (size_t)(KEY_SIZE*8) : data_len*8;

    for (size_t i=0; i<flip_count; i++) {
        size_t enc_len1=0;
        uint8_t *enc1;
        if (is_stream) {
            uint8_t mod_key[KEY_SIZE]; memcpy(mod_key,key,KEY_SIZE);
            mod_key[i/8] ^= (uint8_t)(1<<(i%8));
            if (mode==MODE_WBC_CTR_HMAC) {
                enc1=cascade_encrypt_ctr_hmac(mod_key,data,data_len,block_size,nonce0,&enc_len1);
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
                const uint8_t *cmp=enc1+hdr; size_t cmp_len=enc_len1-hdr-MAC_SIZE;
                if (cmp_len==ref_len) for (size_t j=0;j<cmp_len;j++) total_flips+=__builtin_popcount(ref[j]^cmp[j]);
            } else {
                uint8_t *iv1=NULL; size_t iv1_len=0;
                enc1=cascade_encrypt(mod_key,data,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
                if (enc_len1==ref_len) for (size_t j=0;j<enc_len1;j++) total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
                if (iv1) free(iv1);
            }
        } else {
            uint8_t *mod=(uint8_t*)malloc(data_len); memcpy(mod,data,data_len);
            mod[i/8] ^= (uint8_t)(1<<(i%8));
            uint8_t *iv1=NULL; size_t iv1_len=0;
            enc1=cascade_encrypt(key,mod,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
            if (enc_len1==ref_len) for (size_t j=0;j<enc_len1;j++) total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
            if (iv1) free(iv1); free(mod);
        }
        free(enc1);
    }
        double ratio=(double)total_flips/((double)flip_count*(double)total_bits);
        printf("  Avalanche effect %s: %.2f%%  (ideal ~50%%)\n",
            is_stream?"(key)":"(plaintext)", ratio*100.0);
    free(enc0); if (iv0) free(iv0);
}

/* ── differential test ───────────────────────────────────────────────────── */

static void differential_test(const uint8_t key[KEY_SIZE], const uint8_t *data,
                                size_t data_len, EncMode mode, int double_pass) {
    int block_size = auto_block_size((int)data_len);
    size_t enc_len0=0;
    uint8_t *iv0=NULL; size_t iv0_len=0;
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

    for (int i=0; i<KEY_SIZE*8; i++) {
        uint8_t mod_key[32]; memcpy(mod_key,key,32);
        mod_key[i/8] ^= (uint8_t)(1<<(i%8));
        build_op_table(mod_key);

        size_t enc_len1=0;
        uint8_t *enc1;
        if (mode==MODE_WBC_CTR_HMAC) {
            enc1=cascade_encrypt_ctr_hmac(mod_key,data,data_len,block_size,nonce0,&enc_len1);
            size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
            const uint8_t *cmp=enc1+hdr; size_t cmp_len=enc_len1-hdr-MAC_SIZE;
            if (cmp_len==ref_len) for (size_t j=0;j<cmp_len;j++) total_flips+=__builtin_popcount(ref[j]^cmp[j]);
        } else {
            uint8_t *iv1=NULL; size_t iv1_len=0;
            enc1=cascade_encrypt(mod_key,data,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
            if (enc_len1==ref_len) for (size_t j=0;j<enc_len1;j++) total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
            if (iv1) free(iv1);
        }
        free(enc1);
    }
    build_op_table(key);

    double ratio=(total_bits>0)?(double)total_flips/((double)(KEY_SIZE*8)*(double)total_bits):0.0;
    printf("  Avalanche effect (key):    %.2f%%  (ideal ~50%%)\n", ratio*100.0);
    free(enc0); if (iv0) free(iv0);
}

/* ── interactive helpers ─────────────────────────────────────────────────── */

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

static void read_hex_key(uint8_t key[32]) {
    printf("  Key (hex 64 chars): ");
    fflush(stdout);
    char buf[128]={0};
    if (fgets(buf,sizeof(buf),stdin)==NULL) return;
    buf[strcspn(buf,"\r\n")]=0;
    if (strlen(buf)<64) { fprintf(stderr,"  Key too short, using zeros\n"); return; }
    for (int i=0;i<32;i++) { unsigned int v=0; sscanf(buf+i*2,"%02x",&v); key[i]=(uint8_t)v; }
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Парсинг аргументов командной строки */
    int double_pass = 1; /* по умолчанию: двойной каскад */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-s")==0 || strcmp(argv[i],"--single")==0)
            double_pass = 0;
        else if (strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--double")==0)
            double_pass = 1;
        else if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) {
            printf("Usage: %s [OPTIONS]\n"
                   "  -s, --single   Одиночный каскад (1 проход вперёд)\n"
                   "  -d, --double   Двойной каскад (2 прохода) [по умолчанию]\n"
                   "  -h, --help     Эта справка\n", argv[0]);
            return 0;
        }
    }

    uint8_t key[32] = {0};
    RAND_bytes(key, 32);
    build_op_table(key);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║          WBC1-CASCADE-NEW  (без SHA в hot path)         ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  Каскад:  %-46s ║\n",
           double_pass ? "ДВОЙНОЙ  (-d/--double)  [прямой + обратный]"
                       : "ОДИНОЧНЫЙ (-s/--single)  [только прямой]");
    printf("║  Раунды:  32  (= длина ключа)  |  SHA: только init/MAC  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    while (1) {
        printf("\n"
               "=== WBC1-CASCADE-NEW [%s] ===\n"
               "1. Encrypt / decrypt text\n"
               "2. Run self-tests\n"
               "3. Benchmark performance\n"
               "4. Avalanche + differential + statistics\n"
               "5. Switch cascade mode\n"
               "6. Exit\n"
               "Select (1-6): ",
               double_pass ? "DOUBLE" : "SINGLE");
        fflush(stdout);

        char choice[8]={0};
        if (fgets(choice,sizeof(choice),stdin)==NULL) break;

        if (choice[0]=='1') {
            printf("  Text to encrypt: ");
            fflush(stdout);
            char text[4096]={0};
            if (fgets(text,sizeof(text),stdin)==NULL) continue;
            text[strcspn(text,"\r\n")]=0;
            size_t text_len = strlen(text);

            EncMode mode = select_mode();
            printf("  Generate key? (y/n): "); fflush(stdout);
            char yn[8]={0};
            if (fgets(yn,sizeof(yn),stdin)==NULL) continue;
            if (yn[0]=='y'||yn[0]=='Y') {
                RAND_bytes(key,32);
                printf("  Generated key: ");
                for (int i=0;i<32;i++) printf("%02x",key[i]);
                printf("\n");
            } else { read_hex_key(key); }
            build_op_table(key);

            int block_size = auto_block_size((int)text_len);
            print_hex("Input HEX:", (const uint8_t*)text, text_len);

            size_t enc_len=0, dec_len=0;
            uint8_t *enc=NULL, *dec=NULL;

            if (mode==MODE_WBC_CTR_HMAC) {
                enc = cascade_encrypt_ctr_hmac(key,(const uint8_t*)text,text_len,block_size,NULL,&enc_len);
                print_hex("Encrypted HEX:", enc, enc_len);
                dec = cascade_decrypt_ctr_hmac(key, enc, enc_len, &dec_len);
            } else {
                uint8_t *iv=NULL; size_t iv_len=0;
                enc = cascade_encrypt(key,(const uint8_t*)text,text_len,mode,NULL,
                                      block_size,&iv,&iv_len,double_pass,&enc_len);
                print_hex("Encrypted HEX:", enc, enc_len);
                dec = cascade_decrypt(key, enc, enc_len, mode, iv, block_size,
                                      double_pass, &dec_len);
                if (iv) free(iv);
            }
            if (dec) {
                print_hex("Decrypted HEX:", dec, dec_len);
                printf("  Decrypted:     %.*s\n",(int)dec_len,dec);
                free(dec);
            }
            if (enc) free(enc);

        } else if (choice[0]=='2') {
            EncMode mode = select_mode();
            run_self_tests(key, mode, double_pass);

        } else if (choice[0]=='3') {
            EncMode mode = select_mode();
            benchmark(key, mode, double_pass);

        } else if (choice[0]=='4') {
            printf("  Test text (Enter=random 1024B, or N for N random bytes): ");
            fflush(stdout);
            char text[4096]={0};
            if (fgets(text,sizeof(text),stdin)==NULL) continue;
            text[strcspn(text,"\r\n")]=0;
            size_t text_len = strlen(text);
            static uint8_t rand_buf[4096];
            const uint8_t *tdata; size_t tlen;
            if (text_len==0) { RAND_bytes(rand_buf,1024); tdata=rand_buf; tlen=1024; }
            else {
                char *endp=NULL; long nreq=strtol(text,&endp,10);
                if (endp!=text&&*endp=='\0'&&nreq>0) {
                    size_t nb=(size_t)nreq; if(nb>sizeof(rand_buf))nb=sizeof(rand_buf);
                    RAND_bytes(rand_buf,(int)nb); tdata=rand_buf; tlen=nb;
                    printf("  Generated %zu random bytes.\n",tlen);
                } else { tdata=(const uint8_t*)text; tlen=text_len; }
            }
            EncMode mode = select_mode();
            int block_size = auto_block_size((int)tlen);

            size_t enc_len=0;
            uint8_t *enc, *iv=NULL; size_t iv_len=0;
            if (mode==MODE_WBC_CTR_HMAC)
                enc=cascade_encrypt_ctr_hmac(key,tdata,tlen,block_size,NULL,&enc_len);
            else
                enc=cascade_encrypt(key,tdata,tlen,mode,NULL,block_size,
                                    &iv,&iv_len,double_pass,&enc_len);
            printf("\n");
            avalanche_test(key, tdata, tlen, mode, double_pass);
            differential_test(key, tdata, tlen, mode, double_pass);
            per_block_avalanche(key, tdata, tlen);
            if (mode==MODE_WBC_CTR_HMAC) {
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
                statistics_tests(tdata,tlen,enc+hdr,enc_len-hdr-MAC_SIZE);
                nist_sts_quick_tests(enc+hdr,enc_len-hdr-MAC_SIZE);
            } else {
                statistics_tests(tdata,tlen,enc,enc_len);
                nist_sts_quick_tests(enc,enc_len);
            }
            free(enc); if (iv) free(iv);

        } else if (choice[0]=='5') {
            double_pass = !double_pass;
            printf("  Cascade mode: %s\n", double_pass?"DOUBLE (прямой + обратный)":"SINGLE (только прямой)");

        } else {
            printf("Bye!\n");
            break;
        }
    }
    return 0;
}
