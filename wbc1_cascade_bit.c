/*
 * WBC1-CASCADE-BIT
 * ================
 * Бит-уровневый вариант WBC1-Cascade.
 *
 * Отличия от wbc1_cascade_new1.c:
 *   - Перестановки работают с ОТДЕЛЬНЫМИ БИТАМИ (не байтами).
 *     Куб для бит: dim_bit = dim_byte * 2  (так как (2n)³ = 8·n³).
 *   - «Циклический сдвиг» — круговой сдвиг ВСЕГО битового массива на k позиций,
 *     что обеспечивает cross-byte диффузию (в отличие от побитового сдвига внутри байтов).
 *   - Key whitening (XOR с cascade key) до и после раундов.
 *   - Флаг --no-cascade отключает каскад (фиксированный ключ для всех блоков).
 *
 * Build:
 *   gcc -O2 -o wbc1_cascade_bit wbc1_cascade_bit.c -lssl -lcrypto -lm
 *
 * Flags:
 *   --no-cascade   использовать фиксированный ключ для всех блоков (без CASCADE)
 *   -s / --single  одиночный каскад [по умолчанию]
 *   -d / --double  двойной каскад (прямой + обратный)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── constants ──────────────────────────────────────────────────────────── */

#define MAGIC        "WBC1"
#define MAGIC_LEN    4
#define VERSION      0x01
#define VERSION_CASC 0x06   /* bit-level version tag */
#define NONCE_SIZE   12
#define MAC_SIZE     32
#define KEY_SIZE     32
#define ROUNDS       32
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

static uint8_t rotate_left(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b << n) | (b >> (8 - n)));
}

/* ── SHA-256/512 wrappers ────────────────────────────────────────────────── */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
}
static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    SHA512(data, len, out);
}

/* ── cube data structure ─────────────────────────────────────────────────── */

typedef struct { uint8_t *data; int dim; } Cube;

static inline int idx3(int dim, int i, int j, int k) {
    return i * dim * dim + j * dim + k;
}

/* MAX_DIM=32 для бит-куба: 32³=32768 бит = 4096 байт (максимальный блок) */
#define MAX_DIM   32
#define MAX_SLICE (MAX_DIM * MAX_DIM)

static void rot90_2d(uint8_t *mat, int dim, int k) {
    k = ((k % 4) + 4) % 4;
    uint8_t *tmp = (uint8_t *)malloc((size_t)(dim * dim));
    for (int t = 0; t < k; t++) {
        for (int i = 0; i < dim; i++)
            for (int j = 0; j < dim; j++)
                tmp[i * dim + j] = mat[j * dim + (dim - 1 - i)];
        memcpy(mat, tmp, (size_t)(dim * dim));
    }
    free(tmp);
}

static void get_slice(const Cube *c, int axis, int pos, uint8_t *sl) {
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
    uint8_t *sl = (uint8_t *)malloc((size_t)(c->dim * c->dim));
    get_slice(c, axis, pos, sl);
    rot90_2d(sl, c->dim, k);
    set_slice(c, axis, pos, sl);
    free(sl);
}

static void rotate_whole_cube(Cube *c, int axis, int k) {
    k = ((k % 4) + 4) % 4;
    int dim = c->dim, total = dim*dim*dim;
    uint8_t *tmp = (uint8_t *)malloc((size_t)total);
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
        memcpy(c->data, tmp, (size_t)total);
    }
    free(tmp);
}

static void diagflip(Cube *c, int axis) {
    int dim = c->dim, total = dim*dim*dim;
    uint8_t *tmp = (uint8_t *)malloc((size_t)total);
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++)
            for (int k = 0; k < dim; k++) {
                int di, dj, dk;
                if      (axis == 0) { di=i; dj=k; dk=j; }
                else if (axis == 1) { di=k; dj=j; dk=i; }
                else                { di=j; dj=i; dk=k; }
                tmp[idx3(dim,di,dj,dk)] = c->data[idx3(dim,i,j,k)];
            }
    memcpy(c->data, tmp, (size_t)total);
    free(tmp);
}

static void swap_layers(Cube *c, int axis, int idx1, int idx2) {
    int dim = c->dim;
    idx1 = ((idx1%dim)+dim)%dim;
    idx2 = ((idx2%dim)+dim)%dim;
    uint8_t *s1 = (uint8_t *)malloc((size_t)(dim * dim));
    uint8_t *s2 = (uint8_t *)malloc((size_t)(dim * dim));
    get_slice(c,axis,idx1,s1); get_slice(c,axis,idx2,s2);
    set_slice(c,axis,idx1,s2); set_slice(c,axis,idx2,s1);
    free(s1); free(s2);
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

/* ═══════════════════════════════════════════════════════════════════════════
 * БИТ-УРОВНЕВЫЕ ТАБЛИЦЫ ПЕРЕСТАНОВОК
 *
 * Для блока из N байт:
 *   byte_dim = dim_for(N)    (n: n³=N)
 *   bit_dim  = byte_dim * 2  (2n: (2n)³=8n³=N*8 бит)
 *   total_bits = N * 8
 *
 * Те же g_ops применяются к кубу с bit_dim: операции (поворот грани/слоя,
 * перестановка слоёв, диагональное отражение) работают для любого dim.
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint16_t *g_bit_perms_buf = NULL;
static int       g_bit_perm_bs   = -1;   /* block_size для которого построены */
static int       g_bit_total     = 0;    /* = g_bit_perm_bs * 8 */

static void build_bit_perm_table(int block_size) {
    if (g_bit_perm_bs == block_size) return;
    free(g_bit_perms_buf);

    int byte_dim   = dim_for(block_size);
    int bit_dim    = byte_dim * 2;          /* dim куба для бит */
    int total_bits = block_size * 8;        /* = bit_dim³       */

    g_bit_perms_buf = (uint16_t *)malloc((size_t)2 * NUM_OPS * total_bits * sizeof(uint16_t));
    g_bit_perm_bs   = block_size;
    g_bit_total     = total_bits;

    uint8_t *tmp = (uint8_t *)malloc((size_t)total_bits);

    for (int op = 0; op < NUM_OPS; op++) {
        uint16_t *fwd = g_bit_perms_buf + (size_t) op            * total_bits;
        uint16_t *inv = g_bit_perms_buf + (size_t)(op + NUM_OPS) * total_bits;

        /* Младшие 8 бит индекса */
        for (int i = 0; i < total_bits; i++) tmp[i] = (uint8_t)(i & 0xFF);
        { Cube c = { tmp, bit_dim }; apply_composed_op(&c, &g_ops[op], 0); }
        for (int j = 0; j < total_bits; j++) fwd[j] = (uint16_t)(tmp[j] & 0xFF);

        /* Старшие 8 бит индекса (для total_bits > 256) */
        if (total_bits > 256) {
            for (int i = 0; i < total_bits; i++) tmp[i] = (uint8_t)(i >> 8);
            { Cube c = { tmp, bit_dim }; apply_composed_op(&c, &g_ops[op], 0); }
            for (int j = 0; j < total_bits; j++) fwd[j] |= (uint16_t)((uint16_t)tmp[j] << 8);
        }

        /* Обратная перестановка */
        for (int j = 0; j < total_bits; j++) inv[fwd[j]] = (uint16_t)j;
    }
    free(tmp);
}

/* ── бит-уровневые операции ──────────────────────────────────────────────── */

/*
 * Применить бит-перестановку: бит на позиции i переходит на позицию perm[i].
 *
 * Оптимизация: обрабатываем один входной байт за раз — это снижает число
 * обращений к памяти и позволяет пропустить нулевые байты целиком.
 * Внутренний цикл развёрнут (8 итераций), без ветвлений через маскирование.
 */
/*
 * Gather-подход: для каждого OUTPUT байта читаем 8 бит из СЛУЧАЙНЫХ позиций input.
 * perm[ob*8+j] = какой INPUT бит идёт в выходной бит j байта ob.
 *
 * Преимущество перед scatter: ПОСЛЕДОВАТЕЛЬНАЯ ЗАПИСЬ в out (нет read-modify-write
 * зависимостей), не нужен memset, компилятор может авто-векторизовать.
 * Здесь perm — это ОБРАТНАЯ перестановка (inverse), см. вызовы в encrypt/decrypt.
 *
 * __restrict__ подсказывает компилятору, что буферы не перекрываются.
 */
static void apply_bit_perm(const uint8_t * restrict in, int bytes,
                            const uint16_t * restrict perm,
                            uint8_t * restrict out) {
    for (int ob = 0; ob < bytes; ob++) {
        const uint16_t *p = perm + (ob << 3);
        /* Полностью разворачиваем 8 бит — компилятор видит независимые операции */
#define _GP(J) (uint8_t)(((in[p[J]>>3] >> (p[J]&7)) & 1u) << (J))
        out[ob] = _GP(0)|_GP(1)|_GP(2)|_GP(3)|_GP(4)|_GP(5)|_GP(6)|_GP(7);
#undef _GP
    }
}

/*
 * Круговой сдвиг ВСЕГО битового массива на k бит (k ∈ 1..7).
 *
 * Оптимизация: байт-уровневая реализация O(bytes) вместо O(bytes*8).
 * Идея: круговой сдвиг на k бит вправо:
 *   out[b] = (in[b] >> k) | (in[(b-1+bytes)%bytes] << (8-k))
 * — эквивалентно carry-сдвигу байтов с переносом через границы байт.
 * Нет деления, нет модуля в цикле, нет malloc.
 */
static void cyclic_shift_bits(uint8_t *data, int bytes, int k, int right) {
    /* k всегда 1..7 (вызывается только если op_id & 7 != 0) */
    uint8_t tmp[4096];  /* bytes ≤ 4096 */
    if (right) {
        /* Правый сдвиг на k бит */
        uint8_t carry = data[bytes - 1] << (8 - k);
        for (int b = 0; b < bytes; b++) {
            uint8_t cur = data[b];
            tmp[b] = (cur >> k) | carry;
            carry  = cur << (8 - k);
        }
    } else {
        /* Левый сдвиг на k бит */
        uint8_t carry = data[0] >> (8 - k);
        for (int b = bytes - 1; b >= 0; b--) {
            uint8_t cur = data[b];
            tmp[b] = (cur << k) | carry;
            carry  = cur >> (8 - k);
        }
    }
    memcpy(data, tmp, (size_t)bytes);
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

/* ── derive_cascade_key ──────────────────────────────────────────────────── */

static void derive_cascade_key(const uint8_t *enc_block, int block_bytes,
                                uint8_t new_rk[KEY_SIZE]) {
    uint8_t S[64] = {0};
    for (int j = 0; j < block_bytes; j++)
        S[j & 63] ^= enc_block[j];

    for (int r = 0; r < 4; r++) {
        uint8_t c = (uint8_t)(S[63] ^ r);
        for (int i = 0; i < 64; i++) {
            c = (uint8_t)(S[i] + rotate_left(c, 5) + (uint8_t)(67*i + 29*r));
            S[i] = c;
        }
        c = (uint8_t)(S[0] ^ (uint8_t)(r * 37));
        for (int i = 63; i >= 0; i--) {
            c = S[i] ^ (uint8_t)((c >> 3) | (c << 5)); /* rotate_right(c,3) */
            S[i] = c;
        }
    }

    memcpy(new_rk, S, KEY_SIZE);
}

/* ==========================================================================
 * БИТ-УРОВНЕВЫЕ encrypt_block / decrypt_block
 *
 * Каждый раунд r ∈ [0, ROUNDS):
 *   1. Бит-перестановка  — apply_bit_perm(perm[key[r] % 127])
 *   2. Круговой сдвиг    — cyclic_shift_bits(op_id & 7, right)
 *
 * Key whitening (XOR с cascade key) — до и после всех раундов.
 *
 * В отличие от байтовой версии, один изменённый бит после перестановки
 * попадает в ДРУГОЙ БАЙТ, что обеспечивает реальный avalanche внутри блока.
 * ========================================================================== */

static void encrypt_block_bit(const uint8_t *key_mat, const uint8_t *block,
                               int block_size, uint8_t *out) {
    /* Стековые буферы и ping-pong указатели (без memcpy в цикле) */
    uint8_t _a[4096], _b[4096];
    uint8_t *cur = _a, *tmp = _b;
    int total_bits = block_size * 8;
    memcpy(cur, block, (size_t)block_size);

    /* Key whitening: начальное */
    for (int i = 0; i < block_size; i++)
        cur[i] ^= key_mat[i % KEY_SIZE];

    for (int r = 0; r < ROUNDS; r++) {
        int op_id = key_mat[r] % NUM_OPS;

        /* 1. Бит-перестановка (gather): используем inv_perm для gather-подхода */
        const uint16_t *inv_p = g_bit_perms_buf + (size_t)(op_id + NUM_OPS) * total_bits;
        apply_bit_perm(cur, block_size, inv_p, tmp);
        /* ping-pong: меняем указатели вместо memcpy */
        { uint8_t *t = cur; cur = tmp; tmp = t; }

        /* 2. Круговой сдвиг всего массива бит */
        int shift = op_id & 7;
        if (shift) cyclic_shift_bits(cur, block_size, shift, 1);
    }

    /* Key whitening: финальное */
    for (int i = 0; i < block_size; i++)
        cur[i] ^= key_mat[i % KEY_SIZE];

    memcpy(out, cur, (size_t)block_size);
}

static void decrypt_block_bit(const uint8_t *key_mat, const uint8_t *block,
                               int block_size, uint8_t *out) {
    uint8_t _a[4096], _b[4096];
    uint8_t *cur = _a, *tmp = _b;
    int total_bits = block_size * 8;
    memcpy(cur, block, (size_t)block_size);

    /* Undo финального whitening */
    for (int i = 0; i < block_size; i++)
        cur[i] ^= key_mat[i % KEY_SIZE];

    for (int r = ROUNDS - 1; r >= 0; r--) {
        int op_id = key_mat[r] % NUM_OPS;

        /* 2. Undo кругового сдвига (в обратную сторону) */
        int shift = op_id & 7;
        if (shift) cyclic_shift_bits(cur, block_size, shift, 0);

        /* 1. Обратная бит-перестановка (gather): используем fwd_perm */
        const uint16_t *fwd_p = g_bit_perms_buf + (size_t)op_id * total_bits;
        apply_bit_perm(cur, block_size, fwd_p, tmp);
        { uint8_t *t = cur; cur = tmp; tmp = t; }
    }

    /* Undo начального whitening */
    for (int i = 0; i < block_size; i++)
        cur[i] ^= key_mat[i % KEY_SIZE];

    memcpy(out, cur, (size_t)block_size);
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

static int mode_is_key_avalanche(EncMode mode) {
    return (mode==MODE_CTR || mode==MODE_CFB || mode==MODE_OFB || mode==MODE_WBC_CTR_HMAC);
}

/* ── глобальный флаг каскада ─────────────────────────────────────────────── */

static int g_use_cascade = 1;  /* 1 = каскад включён, 0 = фиксированный ключ */

/* ── вспомогательная функция инициализации таблиц ───────────────────────── */

static void init_tables(const uint8_t key[KEY_SIZE], int block_size) {
    build_op_table(key);
    build_bit_perm_table(block_size);
}

/* ── cascade_encrypt / cascade_decrypt ──────────────────────────────────── */

static uint8_t *cascade_encrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode,
                                  const uint8_t *iv_in, int block_size,
                                  uint8_t **iv_out, size_t *iv_len_out,
                                  int double_pass,
                                  size_t *out_len) {
    int block_bytes = block_size;
    init_tables(master_key, block_size);
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
            encrypt_block_bit(rk, blk, block_size, out_b);
            if (g_use_cascade) derive_cascade_key(out_b, block_bytes, rk);
        } else if (mode == MODE_CBC) {
            for (int i=0;i<block_bytes;i++) tmp_block[i]=blk[i]^prev[i];
            encrypt_block_bit(rk, tmp_block, block_size, out_b);
            if (g_use_cascade) derive_cascade_key(out_b, block_bytes, rk);
            memcpy(prev, out_b, block_bytes);
        } else if (mode == MODE_CFB) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, out_b, block_bytes);
        } else if (mode == MODE_OFB) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, enc_prev, block_bytes);
        } else if (mode == MODE_CTR) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
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
        encrypt_block_bit(rk_bwd, inter + b * block_bytes, block_size,
                          result + b * block_bytes);
        if (g_use_cascade) derive_cascade_key(result + b * block_bytes, block_bytes, rk_bwd);
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
    init_tables(master_key, block_size);
    size_t n_blocks = data_len / block_bytes;

    uint8_t *inter     = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len + 1);

    if (double_pass) {
        uint8_t rk_bwd[KEY_SIZE];
        derive_cascade_key(master_key, KEY_SIZE, rk_bwd);

        for (int b = (int)n_blocks - 1; b >= 0; b--) {
            decrypt_block_bit(rk_bwd, data + b * block_bytes, block_size,
                              inter + b * block_bytes);
            if (g_use_cascade) derive_cascade_key(data + b * block_bytes, block_bytes, rk_bwd);
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
            decrypt_block_bit(rk, blk, block_size, out_b);
            if (g_use_cascade) derive_cascade_key(blk, block_bytes, rk);
        } else if (mode == MODE_CBC) {
            decrypt_block_bit(rk, blk, block_size, tmp);
            for (int i=0;i<block_bytes;i++) out_b[i]=tmp[i]^prev[i];
            if (g_use_cascade) derive_cascade_key(blk, block_bytes, rk);
            memcpy(prev, blk, block_bytes);
        } else if (mode == MODE_CFB) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, blk, block_bytes);
        } else if (mode == MODE_OFB) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
            for (int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev, enc_prev, block_bytes);
        } else if (mode == MODE_CTR) {
            encrypt_block_bit(rk, prev, block_size, enc_prev);
            if (g_use_cascade) derive_cascade_key(enc_prev, block_bytes, rk);
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

/* ── WBC-CTR-HMAC ────────────────────────────────────────────────────────── */

static uint8_t *cascade_encrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           int block_size,
                                           const uint8_t *nonce_in,
                                           size_t *out_len) {
    int block_bytes = block_size;
    init_tables(key, block_size);
    uint8_t nonce[NONCE_SIZE];
    if (nonce_in) memcpy(nonce,nonce_in,NONCE_SIZE);
    else RAND_bytes(nonce,NONCE_SIZE);

    uint8_t key_crypt[32], key_mac[32];
    kdf(key, nonce, key_crypt, key_mac);

    size_t padded_len;
    uint8_t *padded  = wbc1_pad(data, data_len, block_bytes, &padded_len);
    size_t n_blocks  = padded_len / block_bytes;
    uint8_t *cipher  = (uint8_t *)malloc(padded_len);

    uint8_t rk[KEY_SIZE];
    memcpy(rk, key_crypt, KEY_SIZE);
    int ctr_tail_sz = (block_bytes > NONCE_SIZE) ? block_bytes-NONCE_SIZE : 1;

    for (size_t b = 0; b < n_blocks; b++) {
        uint8_t ctr_block[4096];
        for (int j = 0; j < block_bytes; j++) ctr_block[j] = rk[j % KEY_SIZE];
        for (int j = 0; j < NONCE_SIZE && j < block_bytes; j++) ctr_block[j] ^= nonce[j];
        for (int i=ctr_tail_sz-1; i>=0; i--)
            ctr_block[NONCE_SIZE+i] ^= (uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block_bit(rk, ctr_block, block_size, enc_ctr);
        if (g_use_cascade) derive_cascade_key(enc_ctr, block_bytes, rk);
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
    init_tables(key, block_size);
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
    uint8_t rk[KEY_SIZE];
    memcpy(rk, key_crypt, KEY_SIZE);
    int ctr_tail_sz = (block_bytes>NONCE_SIZE) ? block_bytes-NONCE_SIZE : 1;

    for (size_t b=0; b<n_blocks; b++) {
        uint8_t ctr_block[4096];
        for (int j = 0; j < block_bytes; j++) ctr_block[j] = rk[j % KEY_SIZE];
        for (int j = 0; j < NONCE_SIZE && j < block_bytes; j++) ctr_block[j] ^= nonce[j];
        for (int i=ctr_tail_sz-1;i>=0;i--)
            ctr_block[NONCE_SIZE+i] ^= (uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block_bit(rk, ctr_block, block_size, enc_ctr);
        if (g_use_cascade) derive_cascade_key(enc_ctr, block_bytes, rk);
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

/* ── self-tests ──────────────────────────────────────────────────────────── */

static void run_self_tests(const uint8_t key[32], EncMode mode, int double_pass) {
    printf("\n%s\n","────────────────────────────────────────────────────────────");
    printf("  Self-tests  |  mode=%s  cascade=%s  key_cascade=%s\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE",
           g_use_cascade ? "ON" : "OFF");
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

static int cmp_double_asc_s(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}
static double aggregate_bench_time(double *t, int n, int trim) {
    if (!trim || n < 5) { double s=0; for(int i=0;i<n;i++) s+=t[i]; return s/n; }
    double tmp[64]; memcpy(tmp,t,(size_t)n*sizeof(double));
    qsort(tmp,(size_t)n,sizeof(double),cmp_double_asc_s);
    int cut=(n>=15)?2:1, start=cut, end=n-cut;
    if(end<=start){double s=0; for(int i=0;i<n;i++) s+=t[i]; return s/n;}
    double s=0; for(int i=start;i<end;i++) s+=tmp[i]; return s/(end-start);
}

static void benchmark(const uint8_t key[32], EncMode mode, int double_pass) {
    static const int sizes[] = {1,10,100,1000,10000,100000,1000000};
    int ns = (int)(sizeof(sizes)/sizeof(sizes[0]));
    int repeats = 5;
    int trim_outliers = 1;
    {
        const char *env = getenv("WBC_BENCH_REPEATS");
        if (env) { int v=atoi(env); if(v>=3&&v<=64) repeats=v; }
    }
    {
        const char *env = getenv("WBC_BENCH_TRIM");
        if (env && env[0] == '0') trim_outliers = 0;
    }

    printf("\n  Benchmark  |  mode=%s  cascade=%s  key_cascade=%s\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE",
           g_use_cascade ? "ON" : "OFF");
    printf("  (Бит-перестановки медленнее байтовых ~8×)\n");
    printf("  Repeats: %d  |  Aggregation: %s\n", repeats, trim_outliers ? "trimmed mean" : "mean");
    printf("  %10s  %10s  %14s  %14s  Integrity\n",
           "Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)");
    printf("  %s\n","------------------------------------------------------------------");

    for (int si=0; si<ns; si++) {
        int sz = sizes[si];
        uint8_t *data = (uint8_t*)malloc(sz);
        RAND_bytes(data, sz);
        int block_size = auto_block_size(sz);
        int all_ok = 1;

        double enc_times[64]={0}, dec_times[64]={0};
        for (int r=0; r<repeats; r++) {
            struct timespec t0,t1;
            size_t enc_len=0, dec_len=0;
            uint8_t *enc=NULL, *dec=NULL;
            uint8_t *iv=NULL; size_t iv_len=0;

            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC)
                enc = cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&enc_len);
            else
                enc = cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            enc_times[r] = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            clock_gettime(CLOCK_MONOTONIC,&t0);
            if (mode==MODE_WBC_CTR_HMAC)
                dec = cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            else
                dec = cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            dec_times[r] = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            if (!dec||dec_len!=(size_t)sz||memcmp(dec,data,sz)!=0) all_ok=0;
            if (iv) free(iv);
            free(enc); if (dec) free(dec);
        }
        double enc_avg = aggregate_bench_time(enc_times,repeats,trim_outliers);
        double dec_avg = aggregate_bench_time(dec_times,repeats,trim_outliers);
        double enc_spd = ((double)sz/1024.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_spd = ((double)sz/1024.0)/(dec_avg>0?dec_avg:1e-9);
        printf("  %10.2f  %10.5f  %14.2f  %14.2f  %s\n",
               (double)sz/1024.0, enc_avg, enc_spd, dec_spd, all_ok?"OK":"FAIL");
        free(data);
    }
    printf("\n");
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

/* ── avalanche test ──────────────────────────────────────────────────────── */

static void avalanche_test(const uint8_t key[KEY_SIZE], const uint8_t *data,
                            size_t data_len, EncMode mode, int double_pass) {
    if (data_len==0) { printf("  Avalanche effect: N/A\n"); return; }
    int is_stream = mode_is_key_avalanche(mode);
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

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int double_pass = 0;  /* по умолчанию: одиночный каскад */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-s")==0 || strcmp(argv[i],"--single")==0)
            double_pass = 0;
        else if (strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--double")==0)
            double_pass = 1;
        else if (strcmp(argv[i],"--no-cascade")==0)
            g_use_cascade = 0;
        else if (strcmp(argv[i],"--cascade")==0)
            g_use_cascade = 1;
        else if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) {
            printf("Usage: %s [OPTIONS]\n"
                   "  -s, --single      Одиночный каскад [по умолчанию]\n"
                   "  -d, --double      Двойной каскад\n"
                   "  --no-cascade      Отключить cascade key evolution\n"
                   "  --cascade         Включить cascade key evolution [по умолчанию]\n"
                   "  -h, --help        Эта справка\n\n"
                   "Бит-уровневая версия WBC1: перестановки работают с отдельными битами.\n"
                   "Куб: dim = 2 * byte_dim (пример: блок 1331 байт → бит-куб 22×22×22)\n",
                   argv[0]);
            return 0;
        }
    }

    uint8_t key[32] = {0};
    RAND_bytes(key, 32);
    build_op_table(key);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         WBC1-CASCADE-BIT  (бит-уровневые перестановки)  ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  Cascade: %-46s ║\n",
           double_pass ? "DOUBLE  (-d/--double)" : "SINGLE  (-s/--single)  [default]");
    printf("║  Key cascade: %-42s ║\n",
           g_use_cascade ? "ON  (--cascade)  [default]" : "OFF  (--no-cascade)");
    printf("║  Раунды: 32  |  Бит-перестановка + круговой сдвиг бит   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  Примечание: ~8× медленнее байтовой версии (bit-by-bit ops)\n");

    while (1) {
        printf("\n"
               "=== WBC1-CASCADE-BIT [%s][cascade=%s] ===\n"
               "1. Encrypt / decrypt text\n"
               "2. Run self-tests\n"
               "3. Benchmark performance\n"
               "4. Avalanche + differential + statistics\n"
               "5. Switch cascade mode\n"
               "6. Toggle key cascade (cascade=%s)\n"
               "7. Exit\n"
               "Select (1-7): ",
               double_pass ? "DOUBLE" : "SINGLE",
               g_use_cascade ? "ON" : "OFF",
               g_use_cascade ? "ON→OFF" : "OFF→ON");
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
            if (!mode_is_key_avalanche(mode))
                differential_test(key, tdata, tlen, mode, double_pass);
            if (mode==MODE_WBC_CTR_HMAC) {
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
                statistics_tests(tdata,tlen,enc+hdr,enc_len-hdr-MAC_SIZE);
            } else {
                statistics_tests(tdata,tlen,enc,enc_len);
            }
            free(enc); if (iv) free(iv);

        } else if (choice[0]=='5') {
            double_pass = !double_pass;
            printf("  Cascade mode: %s\n", double_pass?"DOUBLE":"SINGLE");

        } else if (choice[0]=='6') {
            g_use_cascade = !g_use_cascade;
            printf("  Key cascade: %s\n", g_use_cascade?"ON (ключ меняется между блоками)":"OFF (фиксированный ключ)");

        } else {
            printf("Bye!\n");
            break;
        }
    }

    free(g_bit_perms_buf);
    return 0;
}
