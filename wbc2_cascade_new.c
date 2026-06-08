/*
 * WBC2-CASCADE-NEW -- Послідовна версія WBC2: перестановка + XOR + S-box + зсув
 * ===============================================================================
 * Основа: wbc1_cascade_new0.c (32 раунди послідовно, без кешу складеної перест.)
 *
 * Відмінності від wbc1_cascade_new0:
 *   + Ключ-залежний S-box (байтова підстановка {0..255} → {0..255}, бієкція)
 *     Будується одноразово: SHA-256(key) → MT19937 seed → Fisher-Yates shuffle
 *     Кешується по key_mat, оновлюється автоматично при зміні ключа (cascade)
 *
 *   + XOR з раундовим ключом після кожної перестановки
 *
 * Структура раунду r (encrypt):
 *   1. perm:   apply_operation(op_id, fwd)           — перестановка куба (WBC1)
 *   2. XOR:    buf[i] ^= key_mat[(i + r) % KEY_SIZE]  — байтовий XOR з ключем
 *   3. S-box:  buf[i] = sbox[buf[i]]                  — нелінійна підстановка
 *   4. rotate: bitwise_rotate_cube(op_id & 7, right)  — циклічний зсув бітів
 *
 * Структура раунду r (decrypt, у зворотному порядку):
 *   4'. undo rotate: bitwise_rotate_cube(op_id & 7, left)
 *   3'. inv S-box:   buf[i] = inv_sbox[buf[i]]
 *   2'. undo XOR:    buf[i] ^= key_mat[(i + r) % KEY_SIZE]  (XOR is self-inverse)
 *   1'. inv perm:    apply_operation(op_id, inv)
 *
 * БЕЗ дифузії (на відміну від wbc2_original_parallel.c)
 *
 * Cascade: derive_cascade_key() між блоками — S-box і XOR ключ міняються з ним
 * Режими: ECB, CBC, CFB, OFB, CTR, WBC-CTR-HMAC  (single і double pass)
 *
 * Build:
 *   gcc -O3 -march=native -o wbc2_cascade_new wbc2_cascade_new.c -lssl -lcrypto -lm
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

#define MAGIC        "WBC2"
#define MAGIC_LEN    4
#define VERSION_CASC 0x06
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

/* ── byte utilities ─────────────────────────────────────────────────────── */

static uint8_t rotate_right(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b >> n) | (b << (8 - n)));
}
static uint8_t rotate_left(uint8_t b, int n) {
    n &= 7; return (uint8_t)((b << n) | (b >> (8 - n)));
}

/* ── SHA wrappers ───────────────────────────────────────────────────────── */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) { SHA256(data, len, out); }
static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) { SHA512(data, len, out); }

/* ── Cube structure ─────────────────────────────────────────────────────── */

typedef struct { uint8_t *data; int dim; } Cube;

static inline int idx3(int dim, int i, int j, int k) { return i*dim*dim + j*dim + k; }

#define MAX_DIM   16
#define MAX_SLICE (MAX_DIM * MAX_DIM)
#define MAX_CUBE  (MAX_DIM * MAX_DIM * MAX_DIM)

static void rot90_2d(uint8_t *mat, int dim, int k) {
    k = ((k % 4) + 4) % 4;
    uint8_t tmp[dim * dim];
    for (int t = 0; t < k; t++) {
        for (int i = 0; i < dim; i++)
            for (int j = 0; j < dim; j++)
                tmp[i*dim+j] = mat[j*dim+(dim-1-i)];
        memcpy(mat, tmp, dim*dim);
    }
}

static void get_slice(const Cube *c, int axis, int pos, uint8_t sl[MAX_SLICE]) {
    int dim = c->dim, p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if (axis == 0)      sl[i*dim+j] = c->data[idx3(dim,p,i,j)];
            else if (axis == 1) sl[i*dim+j] = c->data[idx3(dim,i,p,j)];
            else                sl[i*dim+j] = c->data[idx3(dim,i,j,p)];
        }
}

static void set_slice(Cube *c, int axis, int pos, const uint8_t *sl) {
    int dim = c->dim, p = ((pos % dim) + dim) % dim;
    for (int i = 0; i < dim; i++)
        for (int j = 0; j < dim; j++) {
            if (axis == 0)      c->data[idx3(dim,p,i,j)] = sl[i*dim+j];
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
                    int coords[3]={i,j,k2};
                    int new_a0=coords[a1], new_a1=dim-1-coords[a0];
                    int nc[3]={i,j,k2}; nc[a0]=new_a0; nc[a1]=new_a1;
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
                if      (axis==0) { di=i; dj=k; dk=j; }
                else if (axis==1) { di=k; dj=j; dk=i; }
                else              { di=j; dj=i; dk=k; }
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

/* ── operation table (same as wbc1_cascade_new0) ───────────────────────── */

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
static int mt_randint(MT *m, int a, int b) { int r=b-a+1; if(r<=0)return a; return a+(int)(mt_rand(m)%(uint32_t)r); }
static int mt_choice(MT *m, int n)         { return (int)(mt_rand(m)%(uint32_t)n); }
static void mt_shuffle(MT *m, int *arr, int n) {
    for (int i=n-1;i>0;i--) { int j=mt_randint(m,0,i); int tmp=arr[i]; arr[i]=arr[j]; arr[j]=tmp; }
}
static uint32_t sha256_seed(const uint8_t *h32) {
    return ((uint32_t)h32[28]<<24)|((uint32_t)h32[29]<<16)|((uint32_t)h32[30]<<8)|(uint32_t)h32[31];
}

typedef struct { uint8_t type; int8_t name; int8_t dir; } BaseOp;
static const int N_STATIC_BASE = 107;

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

typedef struct { const char *name; const char *moves; } AlgDef;
static const AlgDef ALGS[] = {
    {"T-Perm","R U R' U' R' F R2 U' R' U' R U R' F'"},
    {"Y-Perm","F R U' R' U' R U R' F' R U R' U' R' F R F'"},
    {"J-Perm","R U R' F' R U R' U' R' F R2 U' R' U'"},
    {"F-Perm","R' U' F' R U R' U' R' F R2 U' R' U' R U R' U R"},
    {"A-Perm","x' R2 D2 R' U' R D2 R' U R' x"},
    {"E-Perm","x' R U' R' D R U R' D' R U R' D R U' R' D' x"},
    {"R-Perm","R U' R' U' R U R D R' U' R D' R' U2 R'"},
    {"U-Perm","R U' R U R U R U' R' U' R2"},
    {"V-Perm","R' U R' U' y R' F' R2 U' R' U R' F R F"},
    {"N-Perm","R U R' U R U R' F' R U R' U' R' F R2 U' R' U2 R U' R'"},
    {"Z-Perm","M2 U M2 U M' U2 M2 U2 M' U2"},
    {"H-Perm","M2 U M2 U2 M2 U M2"},
    {"Checkerboard","M2 E2 S2"},
    {"Cube-in-Cube","F L F U' R U F2 L2 U' L' B D' B' L2 U"},
    {"Superflip","U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2"},
    {"Six-Spot","U D' R L' F B' U D'"},
    {"Tetris","L R F B U' D' L' R'"},
    {"Anaconda","L U B' U' R L' B R' F B' D R D' F'"},
    {"Python","F2 R' B' U R' L F' L F' B D' R B L2"},
    {"Black Mamba","R D L F' R U' R' F L' D' R' U"},
};
#define NUM_ALGS 20

static int dir_char_to_k(char d, int inv) {
    int k; switch(d) { case '\'': k=-1; break; case '2': k=2; break; case '3': k=3; break; default: k=1; break; }
    return inv ? -k : k;
}

static void apply_move_token(Cube *cube, const char *tok, int inv) {
    if (!tok || !*tok) return;
    int len=(int)strlen(tok); char base=tok[0];
    char dmod=(len>1&&(tok[len-1]=='\''||tok[len-1]=='2'||tok[len-1]=='3'))?tok[len-1]:0;
    int k=dir_char_to_k(dmod,inv);
    if (base=='U'){rotate_slice(cube,0, 0,k);return;} if (base=='D'){rotate_slice(cube,0,-1,k);return;}
    if (base=='L'){rotate_slice(cube,1, 0,k);return;} if (base=='R'){rotate_slice(cube,1,-1,k);return;}
    if (base=='F'){rotate_slice(cube,2, 0,k);return;} if (base=='B'){rotate_slice(cube,2,-1,k);return;}
    if (base=='M'){rotate_slice(cube,1, 1,k);return;} if (base=='E'){rotate_slice(cube,0, 1,k);return;}
    if (base=='S'){rotate_slice(cube,2, 1,k);return;} if (base=='x'){rotate_whole_cube(cube,0,k);return;}
    if (base=='y'){rotate_whole_cube(cube,1,k);return;} if (base=='z'){rotate_whole_cube(cube,2,k);return;}
}

static void apply_alg_string(Cube *cube, const char *moves_str, int inv) {
    char buf[512]; strncpy(buf,moves_str,sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    for (char *p=buf;*p;p++) if(*p==',') *p=' ';
    char *tokens[256]; int ntok=0;
    char *tok=strtok(buf," ");
    while(tok&&ntok<255){tokens[ntok++]=tok;tok=strtok(NULL," ");}
    if (!inv) for(int i=0;i<ntok;i++) apply_move_token(cube,tokens[i],0);
    else      for(int i=ntok-1;i>=0;i--) apply_move_token(cube,tokens[i],1);
}

static void apply_prim_op(Cube *cube, const PrimOp *op, int inv) {
    static const int face_axis[]={0,0,1,1,2,2},face_pos[]={0,-1,0,-1,0,-1},dir_k[]={1,-1,2,3};
    static const int slice_axis[]={1,0,2},wide_axis[]={0,0,1,1,2,2},cube_axis[]={0,1,2};
    int type=op->type,name=op->name,dir=op->dir;
    int k=dir_k[((dir%4)+4)%4]; if(inv) k=-k;
    if (type==OP_FACE)     rotate_slice(cube,face_axis[name&7],face_pos[name&7],k);
    else if(type==OP_SLICE) rotate_slice(cube,slice_axis[name%3],1,k);
    else if(type==OP_WIDE) { int ax=wide_axis[name&7]; rotate_slice(cube,ax,0,k); rotate_slice(cube,ax,1,k); }
    else if(type==OP_CUBE_ROT) rotate_whole_cube(cube,cube_axis[name%3],k);
    else if(type==OP_ALG||type==OP_PATTERN) apply_alg_string(cube,ALGS[name%NUM_ALGS].moves,inv);
    else if(type==OP_SWAP) swap_layers(cube,name%3,dir,dir+1);
    else if(type==OP_DIAGFLIP) diagflip(cube,name%3);
}

static void apply_composed_op(Cube *cube, const ComposedOp *cop, int inv) {
    if (inv) for(int i=cop->len-1;i>=0;i--) apply_prim_op(cube,&cop->moves[i],1);
    else     for(int i=0;i<cop->len;i++)    apply_prim_op(cube,&cop->moves[i],0);
}

static void build_op_table(const uint8_t key[32]) {
    for (int i=0;i<NUM_OPS;i++) {
        uint8_t h[32],buf[KEY_SIZE+7+4]; memcpy(buf,key,KEY_SIZE); memcpy(buf+KEY_SIZE,"WBC1_OP",7);
        buf[KEY_SIZE+7]=(uint8_t)i; buf[KEY_SIZE+8]=(uint8_t)(i>>8); buf[KEY_SIZE+9]=0; buf[KEY_SIZE+10]=0;
        sha256(buf,KEY_SIZE+11,h);
        MT mt; mt_seed(&mt,sha256_seed(h));
        int chain_len=mt_randint(&mt,3,6); g_ops[i].len=chain_len;
        for(int j=0;j<chain_len;j++) build_prim_op_from_base_idx(&g_ops[i].moves[j],mt_choice(&mt,N_STATIC_BASE));
    }
    uint8_t key_hash[32]; sha256(key,KEY_SIZE,key_hash);
    MT mt; mt_seed(&mt,sha256_seed(key_hash));
    int order[NUM_OPS]; for(int i=0;i<NUM_OPS;i++) order[i]=i;
    mt_shuffle(&mt,order,NUM_OPS);
    ComposedOp tmp[NUM_OPS]; memcpy(tmp,g_ops,sizeof(g_ops));
    for(int i=0;i<NUM_OPS;i++) g_ops[i]=tmp[order[i]];
}

/* ── permutation table (build once per block size) ───────────────────────── */

static uint16_t *g_perms_buf = NULL;
static int       g_perm_bs   = -1;

static void build_perm_table(int block_size) {
    if (g_perm_bs == block_size) return;
    free(g_perms_buf);
    g_perms_buf = (uint16_t *)malloc((size_t)2 * NUM_OPS * block_size * sizeof(uint16_t));
    g_perm_bs   = block_size;
    int dim = dim_for(block_size);
    uint8_t tmp[block_size];
    for (int op = 0; op < NUM_OPS; op++) {
        uint16_t *fwd = g_perms_buf + (size_t) op            * block_size;
        uint16_t *inv = g_perms_buf + (size_t)(op + NUM_OPS) * block_size;
        for (int i=0;i<block_size;i++) tmp[i]=(uint8_t)(i&0xFF);
        { Cube c={tmp,dim}; apply_composed_op(&c,&g_ops[op],0); }
        for (int j=0;j<block_size;j++) fwd[j]=(uint16_t)tmp[j];
        if (block_size > 256) {
            for (int i=0;i<block_size;i++) tmp[i]=(uint8_t)(i>>8);
            { Cube c={tmp,dim}; apply_composed_op(&c,&g_ops[op],0); }
            for (int j=0;j<block_size;j++) fwd[j]|=(uint16_t)((uint16_t)tmp[j]<<8);
        }
        for (int i=0;i<block_size;i++) inv[fwd[i]]=(uint16_t)i;
    }
}

static void apply_operation(Cube *cube, int op_id, int inverse) {
    int idx=((op_id%NUM_OPS)+NUM_OPS)%NUM_OPS;
    int bs=cube->dim*cube->dim*cube->dim;
    const uint16_t *perm=inverse?g_perms_buf+(size_t)(idx+NUM_OPS)*bs:g_perms_buf+(size_t)idx*bs;
    uint8_t tmp[bs];
    for(int i=0;i<bs;i++) tmp[i]=cube->data[perm[i]];
    memcpy(cube->data,tmp,bs);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * KEY-DEPENDENT S-BOX
 *
 * Будується за підходом wbc2_original_parallel.c:
 *   1. S[i] = i  (identity)
 *   2. seed = SHA-256(key)[0..3]  (4-byte seed)
 *   3. MT19937(seed) → Fisher-Yates shuffle → бієкція {0..255}
 *   4. Інверсія: inv_sbox[sbox[i]] = i
 *
 * Кеш: якщо key_mat не змінився — перебудова не відбувається (O(1)).
 * В cascade-режимі key_mat змінюється кожен блок →
 *   оновлення кожен блок (1× SHA-256 + 255× MT19937 ≈ мізерно).
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t g_sbox[256];
static uint8_t g_inv_sbox[256];
static uint8_t g_sbox_key[KEY_SIZE];
static int     g_sbox_valid = 0;

static void build_sbox(const uint8_t *key) {
    if (g_sbox_valid && memcmp(g_sbox_key, key, KEY_SIZE) == 0) return;

    /* Крок 1: базова лінійна таблиця S[i] = i */
    for (int i = 0; i < 256; i++) g_sbox[i] = (uint8_t)i;

    /* Крок 2: seed = SHA-256(key) перші 4 байти */
    uint8_t h[32]; sha256(key, KEY_SIZE, h);
    uint32_t seed = ((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|(uint32_t)h[3];

    /* Крок 3: MT19937 + Fisher-Yates */
    MT mt; mt_seed(&mt, seed);
    for (int i = 255; i > 0; i--) {
        uint32_t j = mt_rand(&mt) % (uint32_t)(i + 1);
        uint8_t tmp = g_sbox[i]; g_sbox[i] = g_sbox[j]; g_sbox[j] = tmp;
    }

    /* Крок 4: інверсна таблиця */
    for (int i = 0; i < 256; i++) g_inv_sbox[g_sbox[i]] = (uint8_t)i;

    memcpy(g_sbox_key, key, KEY_SIZE);
    g_sbox_valid = 1;
}

/* ── padding ────────────────────────────────────────────────────────────── */

static uint8_t *wbc1_pad(const uint8_t *data, size_t data_len,
                          int block_bytes, size_t *out_len) {
    int remainder = (int)(data_len % block_bytes);
    int fill_len  = (remainder==0) ? 0 : block_bytes-remainder;
    size_t aligned = data_len+fill_len, total = aligned+block_bytes;
    uint8_t *out = (uint8_t *)calloc(total,1);
    memcpy(out,data,data_len);
    out[aligned]   = (uint8_t)(fill_len&0xFF);
    out[aligned+1] = (uint8_t)((fill_len>>8)&0xFF);
    *out_len = total; return out;
}

static uint8_t *wbc1_unpad(const uint8_t *data, size_t data_len,
                             int block_bytes, size_t *out_len) {
    if ((int)data_len < block_bytes) { *out_len=0; return (uint8_t*)calloc(1,1); }
    int fill_len = (int)data[data_len-block_bytes]|((int)data[data_len-block_bytes+1]<<8);
    size_t strip = block_bytes+fill_len;
    if (strip > data_len) { *out_len=0; return (uint8_t*)calloc(1,1); }
    *out_len = data_len-strip;
    uint8_t *out = (uint8_t *)malloc(*out_len+1);
    memcpy(out,data,*out_len); out[*out_len]=0; return out;
}

/* ── derive_cascade_key ─────────────────────────────────────────────────── */

static void derive_cascade_key(const uint8_t *enc_block, int block_bytes,
                                uint8_t new_rk[KEY_SIZE]) {
    uint8_t S[64] = {0};
    for (int j=0;j<block_bytes;j++) S[j&63] ^= enc_block[j];
    for (int r=0;r<4;r++) {
        uint8_t c=(uint8_t)(S[63]^r);
        for (int i=0;i<64;i++) { c=(uint8_t)(S[i]+rotate_left(c,5)+(uint8_t)(67*i+29*r)); S[i]=c; }
        c=(uint8_t)(S[0]^(uint8_t)(r*37));
        for (int i=63;i>=0;i--) { c=S[i]^rotate_right(c,3); S[i]=c; }
    }
    memcpy(new_rk,S,KEY_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BLOCK CIPHER  (WBC2: perm → XOR → S-box → rotate, 32 rounds)
 *
 * encrypt:
 *   whitening_in  → 32× (perm, XOR, S-box, rotate) → whitening_out
 *
 * decrypt (strict inverse):
 *   undo whitening_out → 32× (undo rotate, inv S-box, undo XOR, inv perm) → undo whitening_in
 * ═══════════════════════════════════════════════════════════════════════════ */

static void encrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int N = block_size;
    /* Build/refresh cascade-aware S-box */
    build_sbox(key_mat);

    uint8_t buf[N];
    /* 1. Initial key whitening */
    for (int i=0;i<N;i++) buf[i] = block[i] ^ key_mat[i % KEY_SIZE];

    /* 2. 32 rounds: perm → XOR → S-box → rotate */
    for (int r=0; r<ROUNDS; r++) {
        int op_id = key_mat[r] % NUM_OPS;
        Cube c = { buf, dim_for(N) };

        /* a) Cube permutation */
        apply_operation(&c, op_id, 0);

        /* b) XOR with round key material (position- and round-dependent) */
        for (int i=0;i<N;i++) buf[i] ^= key_mat[(i + r) % KEY_SIZE];

        /* c) Key-dependent S-box (non-linear substitution) */
        for (int i=0;i<N;i++) buf[i] = g_sbox[buf[i]];

        /* d) Cyclic bit rotation */
        bitwise_rotate_cube(&c, op_id & 7, 1);
    }

    /* 3. Final key whitening */
    for (int i=0;i<N;i++) out[i] = buf[i] ^ key_mat[i % KEY_SIZE];
}

static void decrypt_block(const uint8_t *key_mat, const uint8_t *block,
                           int block_size, uint8_t *out) {
    int N = block_size;
    /* Build/refresh S-box (must match encrypt_block for same key_mat) */
    build_sbox(key_mat);

    uint8_t buf[N];
    /* 1. Undo final key whitening */
    for (int i=0;i<N;i++) buf[i] = block[i] ^ key_mat[i % KEY_SIZE];

    /* 2. 32 rounds in reverse: undo rotate → inv S-box → undo XOR → inv perm */
    for (int r=ROUNDS-1; r>=0; r--) {
        int op_id = key_mat[r] % NUM_OPS;
        Cube c = { buf, dim_for(N) };

        /* d' undo cyclic rotation */
        bitwise_rotate_cube(&c, op_id & 7, 0);

        /* c' inverse S-box */
        for (int i=0;i<N;i++) buf[i] = g_inv_sbox[buf[i]];

        /* b' undo XOR (self-inverse) */
        for (int i=0;i<N;i++) buf[i] ^= key_mat[(i + r) % KEY_SIZE];

        /* a' inverse cube permutation */
        apply_operation(&c, op_id, 1);
    }

    /* 3. Undo initial key whitening */
    for (int i=0;i<N;i++) out[i] = buf[i] ^ key_mat[i % KEY_SIZE];
}

/* ── KDF + HMAC ─────────────────────────────────────────────────────────── */

static void kdf(const uint8_t key[32], const uint8_t nonce[NONCE_SIZE],
                uint8_t key_crypt[32], uint8_t key_mac[32]) {
    uint8_t in[32+NONCE_SIZE]; memcpy(in,key,32); memcpy(in+32,nonce,NONCE_SIZE);
    uint8_t h[64]; sha512(in,32+NONCE_SIZE,h);
    memcpy(key_crypt,h,32); memcpy(key_mac,h+32,32);
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *data, size_t dlen, uint8_t out[32]) {
    unsigned int olen=32;
    HMAC(EVP_sha256(),key,(int)klen,data,dlen,out,&olen);
}

/* ── mode helpers ───────────────────────────────────────────────────────── */

typedef enum { MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR,
               MODE_WBC_CTR_HMAC } EncMode;

static const char *mode_name(EncMode m) {
    switch(m){case MODE_ECB:return "ECB";case MODE_CBC:return "CBC";
              case MODE_CFB:return "CFB";case MODE_OFB:return "OFB";
              case MODE_CTR:return "CTR";case MODE_WBC_CTR_HMAC:return "WBC-CTR-HMAC";
              default:return "?";}
}
static int mode_is_key_avalanche(EncMode mode) {
    return (mode==MODE_CTR||mode==MODE_CFB||mode==MODE_OFB||mode==MODE_WBC_CTR_HMAC);
}

/* ── cascade_encrypt / cascade_decrypt ─────────────────────────────────── */

static uint8_t *cascade_encrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode, const uint8_t *iv_in, int block_size,
                                  uint8_t **iv_out, size_t *iv_len_out,
                                  int double_pass, size_t *out_len) {
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
        if (iv_in) memcpy(iv, iv_in, block_bytes); else RAND_bytes(iv, block_bytes);
        if (iv_out) { *iv_out=(uint8_t*)malloc(block_bytes); memcpy(*iv_out,iv,block_bytes); *iv_len_out=block_bytes; }
    } else { if (iv_out) { *iv_out=NULL; *iv_len_out=0; } }

    uint8_t rk[KEY_SIZE]; memcpy(rk, master_key, KEY_SIZE);
    uint8_t prev[4096], tmp_block[4096], enc_prev[4096];
    memcpy(prev, iv, block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = padded + b*block_bytes;
        uint8_t       *out_b = inter  + b*block_bytes;

        if (mode==MODE_ECB) {
            encrypt_block(rk,blk,block_size,out_b);
            derive_cascade_key(out_b,block_bytes,rk);
        } else if (mode==MODE_CBC) {
            for(int i=0;i<block_bytes;i++) tmp_block[i]=blk[i]^prev[i];
            encrypt_block(rk,tmp_block,block_size,out_b);
            derive_cascade_key(out_b,block_bytes,rk); memcpy(prev,out_b,block_bytes);
        } else if (mode==MODE_CFB) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev,out_b,block_bytes);
        } else if (mode==MODE_OFB) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev,enc_prev,block_bytes);
        } else if (mode==MODE_CTR) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            int carry=1; for(int i=block_bytes-1;i>=0&&carry;i--){int v=prev[i]+carry;prev[i]=(uint8_t)(v&0xFF);carry=v>>8;}
        }
    }
    free(padded);

    if (!double_pass) { *out_len=padded_len; return inter; }

    uint8_t rk_bwd[KEY_SIZE]; derive_cascade_key(master_key,KEY_SIZE,rk_bwd);
    for (int b=(int)n_blocks-1;b>=0;b--) {
        encrypt_block(rk_bwd,inter+b*block_bytes,block_size,result+b*block_bytes);
        derive_cascade_key(result+b*block_bytes,block_bytes,rk_bwd);
    }
    *out_len=padded_len; free(inter); return result;
}

static uint8_t *cascade_decrypt(const uint8_t master_key[KEY_SIZE],
                                  const uint8_t *data, size_t data_len,
                                  EncMode mode, const uint8_t *iv,
                                  int block_size, int double_pass, size_t *out_len) {
    int block_bytes = block_size;
    build_op_table(master_key);
    g_perm_bs = -1;
    build_perm_table(block_bytes);
    size_t n_blocks = data_len / block_bytes;

    uint8_t *inter     = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len+1);

    if (double_pass) {
        uint8_t rk_bwd[KEY_SIZE]; derive_cascade_key(master_key,KEY_SIZE,rk_bwd);
        for (int b=(int)n_blocks-1;b>=0;b--) {
            decrypt_block(rk_bwd,data+b*block_bytes,block_size,inter+b*block_bytes);
            derive_cascade_key(data+b*block_bytes,block_bytes,rk_bwd);
        }
    } else { memcpy(inter,data,data_len); }

    uint8_t rk[KEY_SIZE]; memcpy(rk,master_key,KEY_SIZE);
    uint8_t prev[4096],enc_prev[4096],tmp[4096];
    if (iv) memcpy(prev,iv,block_bytes); else memset(prev,0,block_bytes);

    for (size_t b = 0; b < n_blocks; b++) {
        const uint8_t *blk   = inter     + b*block_bytes;
        uint8_t       *out_b = decrypted + b*block_bytes;

        if (mode==MODE_ECB) {
            decrypt_block(rk,blk,block_size,out_b);
            derive_cascade_key(blk,block_bytes,rk);
        } else if (mode==MODE_CBC) {
            decrypt_block(rk,blk,block_size,tmp);
            for(int i=0;i<block_bytes;i++) out_b[i]=tmp[i]^prev[i];
            derive_cascade_key(blk,block_bytes,rk); memcpy(prev,blk,block_bytes);
        } else if (mode==MODE_CFB) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev,blk,block_bytes);
        } else if (mode==MODE_OFB) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            memcpy(prev,enc_prev,block_bytes);
        } else if (mode==MODE_CTR) {
            encrypt_block(rk,prev,block_size,enc_prev);
            derive_cascade_key(enc_prev,block_bytes,rk);
            for(int i=0;i<block_bytes;i++) out_b[i]=blk[i]^enc_prev[i];
            int carry=1; for(int i=block_bytes-1;i>=0&&carry;i--){int v=prev[i]+carry;prev[i]=(uint8_t)(v&0xFF);carry=v>>8;}
        }
    }

    uint8_t *res = wbc1_unpad(decrypted,data_len,block_bytes,out_len);
    free(inter); free(decrypted); return res;
}

/* ── WBC-CTR-HMAC ───────────────────────────────────────────────────────── */

static uint8_t *cascade_encrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *data, size_t data_len,
                                           int block_size, const uint8_t *nonce_in,
                                           size_t *out_len) {
    int block_bytes = block_size;
    build_op_table(key); g_perm_bs=-1; build_perm_table(block_bytes);
    uint8_t nonce[NONCE_SIZE];
    if (nonce_in) memcpy(nonce,nonce_in,NONCE_SIZE); else RAND_bytes(nonce,NONCE_SIZE);
    uint8_t key_crypt[32],key_mac[32]; kdf(key,nonce,key_crypt,key_mac);
    size_t padded_len; uint8_t *padded=wbc1_pad(data,data_len,block_bytes,&padded_len);
    size_t n_blocks=padded_len/block_bytes;
    uint8_t *cipher=(uint8_t*)malloc(padded_len);
    uint8_t rk[KEY_SIZE]; memcpy(rk,key_crypt,KEY_SIZE);
    int ctr_tail_sz=(block_bytes>NONCE_SIZE)?block_bytes-NONCE_SIZE:1;
    for (size_t b=0;b<n_blocks;b++) {
        uint8_t ctr_block[4096];
        for(int j=0;j<block_bytes;j++) ctr_block[j]=rk[j%KEY_SIZE];
        for(int j=0;j<NONCE_SIZE&&j<block_bytes;j++) ctr_block[j]^=nonce[j];
        for(int i=ctr_tail_sz-1;i>=0;i--) ctr_block[NONCE_SIZE+i]^=(uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(rk,ctr_block,block_size,enc_ctr);
        derive_cascade_key(enc_ctr,block_bytes,rk);
        for(int i=0;i<block_bytes;i++) cipher[b*block_bytes+i]=padded[b*block_bytes+i]^enc_ctr[i];
    }
    free(padded);
    size_t hdr_len=MAGIC_LEN+1+2+NONCE_SIZE;
    uint8_t header[32]; memcpy(header,MAGIC,MAGIC_LEN);
    header[MAGIC_LEN]=VERSION_CASC; header[MAGIC_LEN+1]=(uint8_t)(block_size>>8); header[MAGIC_LEN+2]=(uint8_t)(block_size&0xFF);
    memcpy(header+MAGIC_LEN+3,nonce,NONCE_SIZE);
    uint8_t mac[32]; uint8_t *mac_in=(uint8_t*)malloc(hdr_len+padded_len);
    memcpy(mac_in,header,hdr_len); memcpy(mac_in+hdr_len,cipher,padded_len);
    hmac_sha256(key_mac,32,mac_in,hdr_len+padded_len,mac); free(mac_in);
    *out_len=hdr_len+padded_len+MAC_SIZE;
    uint8_t *result=(uint8_t*)malloc(*out_len);
    memcpy(result,header,hdr_len); memcpy(result+hdr_len,cipher,padded_len); memcpy(result+hdr_len+padded_len,mac,MAC_SIZE);
    free(cipher); return result;
}

static uint8_t *cascade_decrypt_ctr_hmac(const uint8_t key[KEY_SIZE],
                                           const uint8_t *file_bytes, size_t file_len,
                                           size_t *out_len) {
    if (file_len<(size_t)(MAGIC_LEN+1+2+NONCE_SIZE+MAC_SIZE)){fprintf(stderr,"ERROR: file too short\n");return NULL;}
    if (memcmp(file_bytes,MAGIC,MAGIC_LEN)!=0){fprintf(stderr,"ERROR: invalid magic\n");return NULL;}
    if (file_bytes[MAGIC_LEN]!=VERSION_CASC){fprintf(stderr,"ERROR: version mismatch\n");return NULL;}
    int block_size=((int)file_bytes[MAGIC_LEN+1]<<8)|file_bytes[MAGIC_LEN+2];
    build_op_table(key); g_perm_bs=-1; build_perm_table(block_size);
    const uint8_t *nonce=file_bytes+MAGIC_LEN+3;
    size_t hdr_len=MAGIC_LEN+1+2+NONCE_SIZE;
    const uint8_t *mac_actual=file_bytes+file_len-MAC_SIZE;
    const uint8_t *cipher=file_bytes+hdr_len;
    size_t cipher_len=file_len-hdr_len-MAC_SIZE;
    uint8_t key_crypt[32],key_mac[32]; kdf(key,nonce,key_crypt,key_mac);
    uint8_t mac_expected[32]; uint8_t *mac_in=(uint8_t*)malloc(hdr_len+cipher_len);
    memcpy(mac_in,file_bytes,hdr_len); memcpy(mac_in+hdr_len,cipher,cipher_len);
    hmac_sha256(key_mac,32,mac_in,hdr_len+cipher_len,mac_expected); free(mac_in);
    int diff=0; for(int i=0;i<MAC_SIZE;i++) diff|=mac_actual[i]^mac_expected[i];
    if (diff){fprintf(stderr,"ERROR: MAC failed\n");return NULL;}
    int block_bytes=block_size; size_t n_blocks=cipher_len/block_bytes;
    uint8_t *plain=(uint8_t*)malloc(cipher_len+1);
    uint8_t rk[KEY_SIZE]; memcpy(rk,key_crypt,KEY_SIZE);
    int ctr_tail_sz=(block_bytes>NONCE_SIZE)?block_bytes-NONCE_SIZE:1;
    for (size_t b=0;b<n_blocks;b++) {
        uint8_t ctr_block[4096];
        for(int j=0;j<block_bytes;j++) ctr_block[j]=rk[j%KEY_SIZE];
        for(int j=0;j<NONCE_SIZE&&j<block_bytes;j++) ctr_block[j]^=nonce[j];
        for(int i=ctr_tail_sz-1;i>=0;i--) ctr_block[NONCE_SIZE+i]^=(uint8_t)(b>>(8*(ctr_tail_sz-1-i)));
        uint8_t enc_ctr[4096];
        encrypt_block(rk,ctr_block,block_size,enc_ctr);
        derive_cascade_key(enc_ctr,block_bytes,rk);
        for(int i=0;i<block_bytes;i++) plain[b*block_bytes+i]=cipher[b*block_bytes+i]^enc_ctr[i];
    }
    uint8_t *result=wbc1_unpad(plain,cipher_len,block_bytes,out_len);
    free(plain); return result;
}

/* ── statistics ─────────────────────────────────────────────────────────── */

static double shannon_entropy(const uint8_t *d, size_t l) {
    if (!l) return 0.0;
    size_t f[256]={0}; for(size_t i=0;i<l;i++) f[d[i]]++;
    double h=0.0; for(int i=0;i<256;i++) if(f[i]){double p=(double)f[i]/l;h-=p*log2(p);}
    return h;
}
static double chi_square(const uint8_t *d, size_t l) {
    if (!l) return 0.0;
    size_t f[256]={0}; for(size_t i=0;i<l;i++) f[d[i]]++;
    double e=(double)l/256.0,c=0.0;
    for(int i=0;i<256;i++){double x=(double)f[i]-e;c+=x*x/e;} return c;
}
static double correlation(const uint8_t *x, const uint8_t *y, size_t n) {
    if (!n) return 0.0;
    double mx=0,my=0; for(size_t i=0;i<n;i++){mx+=x[i];my+=y[i];}mx/=n;my/=n;
    double cov=0,vx=0,vy=0;
    for(size_t i=0;i<n;i++){double a=x[i]-mx,b=y[i]-my;cov+=a*b;vx+=a*a;vy+=b*b;}
    return (vx>0&&vy>0)?cov/(sqrt(vx)*sqrt(vy)):0.0;
}

/* ── self-tests ─────────────────────────────────────────────────────────── */

static void run_self_tests(const uint8_t key[32], EncMode mode, int double_pass) {
    printf("\n%s\n","────────────────────────────────────────────────────────────");
    printf("  Self-tests  |  mode=%s  cascade=%s  [WBC2 perm+XOR+Sbox+rot]\n",
           mode_name(mode), double_pass?"DOUBLE":"SINGLE");
    printf("%s\n","────────────────────────────────────────────────────────────");
    typedef struct { const char *label; const uint8_t *data; size_t len; } T;
    uint8_t rand100[100]; RAND_bytes(rand100,100);
    uint8_t range256[256]; for(int i=0;i<256;i++) range256[i]=(uint8_t)i;
    uint8_t a64[64]; memset(a64,'A',64);
    uint8_t b300[300]; memset(b300,'B',300);
    uint8_t *d10k=(uint8_t*)malloc(10000);  RAND_bytes(d10k,10000);
    uint8_t *d100k=(uint8_t*)malloc(100000);RAND_bytes(d100k,100000);
    T tests[] = {
        {"Short text",       (const uint8_t*)"Hello World!",12},
        {"One block (64B)",  a64,64},
        {"300 bytes",        b300,300},
        {"Binary (100B)",    rand100,100},
        {"Empty input",      (const uint8_t*)"",0},
        {"All byte values",  range256,256},
        {"Single byte",      (const uint8_t*)"X",1},
        {"10 000 bytes",     d10k,10000},
        {"100 000 bytes",    d100k,100000},
    };
    int n=(int)(sizeof(tests)/sizeof(tests[0])),passed=0;
    for (int t=0;t<n;t++) {
        int block_size=auto_block_size((int)tests[t].len);
        size_t enc_len=0,dec_len=0; int ok=0;
        if (mode==MODE_WBC_CTR_HMAC) {
            uint8_t *enc=cascade_encrypt_ctr_hmac(key,tests[t].data,tests[t].len,block_size,NULL,&enc_len);
            uint8_t *dec=cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            ok=dec&&dec_len==tests[t].len&&memcmp(dec,tests[t].data,dec_len)==0;
            free(enc);if(dec)free(dec);
        } else {
            uint8_t *iv=NULL;size_t iv_len=0;
            uint8_t *enc=cascade_encrypt(key,tests[t].data,tests[t].len,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            uint8_t *dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            ok=dec_len==tests[t].len&&memcmp(dec,tests[t].data,dec_len)==0;
            free(enc);free(dec);if(iv)free(iv);
        }
        printf("  %-35s %s\n",tests[t].label,ok?"PASS ✓":"FAIL ✗");
        if(ok) passed++;
    }
    printf("%s\n","────────────────────────────────────────────────────────────");
    printf("  Results: %d/%d passed\n\n",passed,n);
    free(d10k);free(d100k);
}

/* ── benchmark helpers ──────────────────────────────────────────────────── */

static double read_cpu_mhz(void) {
    FILE *f=fopen("/proc/cpuinfo","r"); if(!f) return 0.0;
    char line[256]; double mhz=0.0;
    while(fgets(line,sizeof(line),f))
        if(strncmp(line,"cpu MHz",7)==0){char *p=strchr(line,':');if(p){mhz=atof(p+1);break;}}
    fclose(f); return mhz;
}

static int cmp_double_asc(const void *a,const void *b){double da=*(const double*)a,db=*(const double*)b;return(da>db)-(da<db);}

static double aggregate_bench_time(double *t, int n, int trim) {
    if (!trim||n<5){double s=0;for(int i=0;i<n;i++)s+=t[i];return s/n;}
    double tmp[64];memcpy(tmp,t,(size_t)n*sizeof(double));
    qsort(tmp,(size_t)n,sizeof(double),cmp_double_asc);
    int cut=(n>=15)?2:1,start=cut,end=n-cut;
    if(end<=start){double s=0;for(int i=0;i<n;i++)s+=t[i];return s/n;}
    double s=0;for(int i=start;i<end;i++)s+=tmp[i];return s/(end-start);
}

/* ── benchmark ──────────────────────────────────────────────────────────── */

static void benchmark(const uint8_t key[32], EncMode mode, int double_pass) {
    static const int sizes_def[]={1,10,100,1000,10000,100000,1000000,10000000};
    static const int sizes_1gb[]={1,10,100,1000,10000,100000,1000000,10000000,1073741824};
    const int *sizes=sizes_def;
    int ns=(int)(sizeof(sizes_def)/sizeof(sizes_def[0]));
    int repeats=10,trim_outliers=1;
    {const char *e=getenv("WBC_BENCH_REPEATS");if(e){int v=atoi(e);if(v>=3&&v<=64)repeats=v;}}
    {const char *e=getenv("WBC_BENCH_TRIM");if(e&&e[0]=='0')trim_outliers=0;}
    {const char *e=getenv("WBC_BENCH_1GB");if(e&&e[0]=='1'){sizes=sizes_1gb;ns=(int)(sizeof(sizes_1gb)/sizeof(sizes_1gb[0]));}}
    double enc_spds[16]={0},dec_spds[16]={0};int bsizes[16]={0};

    printf("\n  Benchmark  |  mode=%s  cascade=%s  [WBC2: perm+XOR+Sbox+rot]\n",
           mode_name(mode),double_pass?"DOUBLE":"SINGLE");
    printf("  Repeats: %d  |  Aggregation: %s\n",repeats,trim_outliers?"trimmed mean":"mean");
    printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  Integrity\n",
           "Size (KB)","Enc (s)","Enc (KB/s)","Dec (KB/s)","Enc (MB/s)","Dec (MB/s)","Enc (Mbit/s)","Dec (Mbit/s)");
    printf("  %s\n","--------------------------------------------------------------------------------------------------------------");

    for (int si=0;si<ns;si++) {
        int sz=sizes[si];
        uint8_t *data=(uint8_t*)malloc(sz);RAND_bytes(data,sz);
        int block_size=auto_block_size(sz);
        int all_ok=1;

        /* warmup */
        {size_t el=0,dl=0;uint8_t *iv=NULL;size_t iv_len=0;uint8_t *e=NULL,*d=NULL;
         if(mode==MODE_WBC_CTR_HMAC){e=cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&el);d=cascade_decrypt_ctr_hmac(key,e,el,&dl);}
         else{e=cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&el);d=cascade_decrypt(key,e,el,mode,iv,block_size,double_pass,&dl);if(iv)free(iv);}
         free(e);if(d)free(d);}

        double enc_times[64]={0},dec_times[64]={0};
        for (int r=0;r<repeats;r++) {
            struct timespec t0,t1;
            size_t enc_len=0,dec_len=0;uint8_t *enc=NULL,*dec=NULL,*iv=NULL;size_t iv_len=0;
            clock_gettime(CLOCK_MONOTONIC,&t0);
            if(mode==MODE_WBC_CTR_HMAC) enc=cascade_encrypt_ctr_hmac(key,data,sz,block_size,NULL,&enc_len);
            else enc=cascade_encrypt(key,data,sz,mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            enc_times[r]=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            clock_gettime(CLOCK_MONOTONIC,&t0);
            if(mode==MODE_WBC_CTR_HMAC) dec=cascade_decrypt_ctr_hmac(key,enc,enc_len,&dec_len);
            else dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            dec_times[r]=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

            if(!dec||dec_len!=(size_t)sz||memcmp(dec,data,sz)!=0) all_ok=0;
            if(iv)free(iv);free(enc);if(dec)free(dec);
        }
        double enc_avg=aggregate_bench_time(enc_times,repeats,trim_outliers);
        double dec_avg=aggregate_bench_time(dec_times,repeats,trim_outliers);
        double enc_spd=((double)sz/1024.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_spd=((double)sz/1024.0)/(dec_avg>0?dec_avg:1e-9);
        double enc_mbps=((double)sz/1000000.0)/(enc_avg>0?enc_avg:1e-9);
        double dec_mbps=((double)sz/1000000.0)/(dec_avg>0?dec_avg:1e-9);
        printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
               (double)sz/1024.0,enc_avg,enc_spd,dec_spd,enc_mbps,dec_mbps,enc_mbps*8,dec_mbps*8,all_ok?"OK":"FAIL");
        enc_spds[si]=enc_spd;dec_spds[si]=dec_spd;bsizes[si]=block_size;
        free(data);
    }

    /* --- CPB table --- */
    {
        double cpu_mhz=read_cpu_mhz();
        if (cpu_mhz>0) {
            printf("\n  --- Цикли / байт  (CPU: %.0f МГц) ---\n",cpu_mhz);
            printf("  %10s  %8s  %8s  %12s  %12s  %10s  %10s\n",
                   "Size (KB)","Enc CPB","Dec CPB","E Cyc/blk","D Cyc/blk","E B/cycle","D B/cycle");
            printf("  %s\n","--------------------------------------------------------------------------");
            for (int si=0;si<ns;si++) {
                double ecpb=(enc_spds[si]>0)?cpu_mhz*1e6/(enc_spds[si]*1024.0):0.0;
                double dcpb=(dec_spds[si]>0)?cpu_mhz*1e6/(dec_spds[si]*1024.0):0.0;
                printf("  %10.2f  %8.2f  %8.2f  %12.0f  %12.0f  %10.5f  %10.5f\n",
                       (double)sizes[si]/1024.0,ecpb,dcpb,
                       ecpb*(double)bsizes[si],dcpb*(double)bsizes[si],
                       (ecpb>0)?1.0/ecpb:0.0,(dcpb>0)?1.0/dcpb:0.0);
            }
        } else { printf("\n  CPB: частота CPU недоступна\n"); }
    }
    printf("\n");
}

/* ── fixed-key benchmark ────────────────────────────────────────────────── */

static void benchmark_fixed_key(const uint8_t key[KEY_SIZE]) {
    static const int DATA_MB=32;
    int N=1331;
    size_t total=(size_t)DATA_MB*1024*1024;
    size_t nblocks=total/(size_t)N; total=nblocks*(size_t)N;
    uint8_t *data=(uint8_t*)malloc(total),*enc=(uint8_t*)malloc(total),*dec=(uint8_t*)malloc(total);
    if(!data||!enc||!dec){free(data);free(enc);free(dec);printf("  OOM\n");return;}
    RAND_bytes(data,(int)(total>INT_MAX?INT_MAX:total));
    build_op_table(key); build_perm_table(N); build_sbox(key);

    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    for(size_t b=0;b<nblocks;b++) encrypt_block(key,data+b*N,N,enc+b*N);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double t_enc=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    clock_gettime(CLOCK_MONOTONIC,&t0);
    for(size_t b=0;b<nblocks;b++) decrypt_block(key,enc+b*N,N,dec+b*N);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double t_dec=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    int ok=(memcmp(data,dec,total)==0);
    double spd_e=(total/1024.0/1024.0)/(t_enc>0?t_enc:1e-9);
    double spd_d=(total/1024.0/1024.0)/(t_dec>0?t_dec:1e-9);
    double cpu_mhz=read_cpu_mhz();
    printf("\n  Fixed-key benchmark  (%d MB, блок %d байт, %zu блоків)\n",DATA_MB,N,nblocks);
    printf("  WBC2 round: perm → XOR → S-box → rotate\n");
    printf("  Encrypt: %8.1f MB/s",spd_e);
    if(cpu_mhz>0) printf("  CPB: %.2f",cpu_mhz*1e6/(spd_e*1e6));
    printf("\n  Decrypt: %8.1f MB/s",spd_d);
    if(cpu_mhz>0) printf("  CPB: %.2f",cpu_mhz*1e6/(spd_d*1e6));
    printf("\n  Integrity: %s\n\n",ok?"OK":"FAIL");
    free(data);free(enc);free(dec);
}

/* ── statistics_tests / differential_test ───────────────────────────────── */

static void statistics_tests(const uint8_t *plain, size_t plain_len,
                               const uint8_t *cipher, size_t cipher_len) {
    printf("\n  === STATISTICAL TESTS ===\n");
    printf("  Shannon entropy (plain):    %.4f bits/byte\n", shannon_entropy(plain,plain_len));
    printf("  Shannon entropy (cipher):   %.4f bits/byte  (ideal 8.0)\n", shannon_entropy(cipher,cipher_len));
    printf("  Chi-square (ciphertext):    %.2f         (ideal ~256)\n", chi_square(cipher,cipher_len));
    size_t cmp_len = plain_len < cipher_len ? plain_len : cipher_len;
    printf("  Correlation plain<->cipher: %.4f             (ideal ~0)\n", correlation(plain,cipher,cmp_len));
    int reps=0;
    for (size_t i=1;i<cipher_len;i++) if (cipher[i]==cipher[i-1]) reps++;
    printf("  Adjacent byte repeats:      %d\n", reps);
}

/* ── differential test (key avalanche) ─────────────────────────────────── */

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
        uint8_t mod_key[KEY_SIZE]; memcpy(mod_key,key,KEY_SIZE);
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
    printf("  Avalanche effect (key):     %.2f%%  (ideal ~50%%)\n", ratio*100.0);
    free(enc0); if (iv0) free(iv0);
}

/* ── avalanche test ─────────────────────────────────────────────────────── */

static void avalanche_test(const uint8_t key[KEY_SIZE], const uint8_t *data,
                            size_t data_len, EncMode mode, int double_pass) {
    if (data_len==0){printf("  Avalanche effect: N/A\n");return;}
    int is_stream=mode_is_key_avalanche(mode);
    int block_size=auto_block_size((int)data_len);
    size_t enc_len0=0;uint8_t *iv0=NULL;size_t iv0_len=0;uint8_t *enc0;
    const uint8_t *ref;size_t ref_len;const uint8_t *nonce0=NULL;

    if (mode==MODE_WBC_CTR_HMAC) {
        enc0=cascade_encrypt_ctr_hmac(key,data,data_len,block_size,NULL,&enc_len0);
        size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;ref=enc0+hdr;ref_len=enc_len0-hdr-MAC_SIZE;nonce0=enc0+MAGIC_LEN+3;
    } else {
        enc0=cascade_encrypt(key,data,data_len,mode,NULL,block_size,&iv0,&iv0_len,double_pass,&enc_len0);
        ref=enc0;ref_len=enc_len0;
    }
    long long total_flips=0,total_bits=(long long)ref_len*8;
    size_t flip_count=is_stream?(size_t)(KEY_SIZE*8):data_len*8;
    for (size_t i=0;i<flip_count;i++) {
        size_t enc_len1=0;uint8_t *enc1;
        if (is_stream) {
            uint8_t mod_key[KEY_SIZE];memcpy(mod_key,key,KEY_SIZE);mod_key[i/8]^=(uint8_t)(1<<(i%8));
            if (mode==MODE_WBC_CTR_HMAC) {
                enc1=cascade_encrypt_ctr_hmac(mod_key,data,data_len,block_size,nonce0,&enc_len1);
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;const uint8_t *cmp=enc1+hdr;size_t cmp_len=enc_len1-hdr-MAC_SIZE;
                if(cmp_len==ref_len)for(size_t j=0;j<cmp_len;j++)total_flips+=__builtin_popcount(ref[j]^cmp[j]);
            } else {
                uint8_t *iv1=NULL;size_t iv1_len=0;
                enc1=cascade_encrypt(mod_key,data,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
                if(enc_len1==ref_len)for(size_t j=0;j<enc_len1;j++)total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
                if(iv1)free(iv1);
            }
        } else {
            uint8_t *mod=(uint8_t*)malloc(data_len);memcpy(mod,data,data_len);mod[i/8]^=(uint8_t)(1<<(i%8));
            uint8_t *iv1=NULL;size_t iv1_len=0;
            enc1=cascade_encrypt(key,mod,data_len,mode,iv0,block_size,&iv1,&iv1_len,double_pass,&enc_len1);
            if(enc_len1==ref_len)for(size_t j=0;j<enc_len1;j++)total_flips+=__builtin_popcount(enc0[j]^enc1[j]);
            if(iv1)free(iv1);free(mod);
        }
        free(enc1);
    }
    double ratio=(double)total_flips/((double)flip_count*(double)total_bits);
    printf("  Avalanche effect %s: %.2f%%  (ideal ~50%%)\n",is_stream?"(key)":"(plaintext)",ratio*100.0);
    free(enc0);if(iv0)free(iv0);
}

/* ── mode select ────────────────────────────────────────────────────────── */

static EncMode select_mode(void) {
    printf("  Select mode:\n    1. ECB\n    2. CBC\n    3. CFB\n    4. OFB\n    5. CTR\n    6. WBC-CTR-HMAC\n  Mode [1-6, default=1]: ");
    fflush(stdout);
    char buf[16]={0};if(fgets(buf,sizeof(buf),stdin)==NULL)return MODE_ECB;
    switch(buf[0]){case '2':return MODE_CBC;case '3':return MODE_CFB;case '4':return MODE_OFB;case '5':return MODE_CTR;case '6':return MODE_WBC_CTR_HMAC;default:return MODE_ECB;}
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int double_pass=1;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"-s")==0||strcmp(argv[i],"--single")==0) double_pass=0;
        if(strcmp(argv[i],"-d")==0||strcmp(argv[i],"--double")==0) double_pass=1;
    }

    uint8_t key[32]={
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x76,0x2e,0x7f,0x60,0xae,0x2b,0xb4,0x1a,
        0x68,0x21,0x6f,0x2c,0xdb,0x34,0x12,0x99
    };

    printf("\n  WBC2-CASCADE-NEW  [perm → XOR → S-box → rotate, 32 rounds, no diffusion]\n");
    printf("  S-box: SHA-256(key) → MT19937 seed → Fisher-Yates shuffle {0..255}\n");
    printf("  cascade=%s\n\n",double_pass?"DOUBLE":"SINGLE");

    int running=1; EncMode mode=MODE_ECB;
    while(running) {
        printf("  ┌─ Menu ─────────────────────────────────────────────────────┐\n"
               "  │  1. Encrypt/Decrypt text                                   │\n"
               "  │  2. Self-tests (9 cases)                                   │\n"
               "  │  3. Benchmark (cascade, all sizes)                         │\n"
               "  │  4. Fixed-key benchmark                                    │\n"
               "  │  5. Avalanche test                                         │\n"
               "  │  6. Switch cascade mode (%s)                           │\n"
               "  │  7. Exit                                                   │\n"
               "  └────────────────────────────────────────────────────────────┘\n"
               "  Mode: %s  Choice: ",
               double_pass?"DOUBLE":"SINGLE",mode_name(mode));
        fflush(stdout);
        char buf[8]={0};if(fgets(buf,sizeof(buf),stdin)==NULL)break;
        int choice=atoi(buf);
        switch(choice) {
        case 1:{
            printf("  Enter text: ");fflush(stdout);
            char tbuf[4096]={0};if(!fgets(tbuf,sizeof(tbuf),stdin))break;
            tbuf[strcspn(tbuf,"\r\n")]=0;
            int block_size=auto_block_size((int)strlen(tbuf));
            size_t enc_len=0,dec_len=0;uint8_t *iv=NULL;size_t iv_len=0;
            uint8_t *enc=cascade_encrypt(key,(uint8_t*)tbuf,strlen(tbuf),mode,NULL,block_size,&iv,&iv_len,double_pass,&enc_len);
            uint8_t *dec=cascade_decrypt(key,enc,enc_len,mode,iv,block_size,double_pass,&dec_len);
            printf("  Encrypted (%zu bytes): ",enc_len);
            for(size_t i=0;i<(enc_len<32?enc_len:32);i++) printf("%02x",enc[i]);
            if(enc_len>32)printf("...");
            printf("\n  Decrypted: %.*s\n",(int)dec_len,dec);
            free(enc);free(dec);if(iv)free(iv);break;}
        case 2: mode=select_mode(); run_self_tests(key,mode,double_pass); break;
        case 3: mode=select_mode(); benchmark(key,mode,double_pass);      break;
        case 4: benchmark_fixed_key(key);                                  break;
        case 5:{
            printf("  Test text (Enter=random 1024B, or N for N random bytes): ");fflush(stdout);
            char tbuf[4096]={0};if(!fgets(tbuf,sizeof(tbuf),stdin))break;
            tbuf[strcspn(tbuf,"\r\n")]=0;
            static uint8_t rand_buf[65536];
            const uint8_t *tdata; size_t tlen;
            if (strlen(tbuf)==0) {
                RAND_bytes(rand_buf,1024); tdata=rand_buf; tlen=1024;
                printf("  Generated 1024 random bytes.\n");
            } else {
                char *endp=NULL; long nreq=strtol(tbuf,&endp,10);
                if (endp!=tbuf&&*endp=='\0'&&nreq>0) {
                    size_t nb=(size_t)nreq; if(nb>sizeof(rand_buf))nb=sizeof(rand_buf);
                    RAND_bytes(rand_buf,(int)nb); tdata=rand_buf; tlen=nb;
                    printf("  Generated %zu random bytes.\n",tlen);
                } else { tdata=(const uint8_t*)tbuf; tlen=strlen(tbuf); }
            }
            mode=select_mode();
            int bsz=auto_block_size((int)tlen);
            size_t enc_len=0; uint8_t *iv=NULL; size_t iv_len=0; uint8_t *enc=NULL;
            if (mode==MODE_WBC_CTR_HMAC)
                enc=cascade_encrypt_ctr_hmac(key,tdata,tlen,bsz,NULL,&enc_len);
            else
                enc=cascade_encrypt(key,tdata,tlen,mode,NULL,bsz,&iv,&iv_len,double_pass,&enc_len);
            printf("\n");
            avalanche_test(key,tdata,tlen,mode,double_pass);
            if (!mode_is_key_avalanche(mode))
                differential_test(key,tdata,tlen,mode,double_pass);
            if (mode==MODE_WBC_CTR_HMAC) {
                size_t hdr=MAGIC_LEN+1+2+NONCE_SIZE;
                statistics_tests(tdata,tlen,enc+hdr,enc_len-hdr-MAC_SIZE);
            } else {
                statistics_tests(tdata,tlen,enc,enc_len);
            }
            free(enc); if(iv)free(iv); break;}
        case 6: double_pass=!double_pass; printf("  Cascade: %s\n",double_pass?"DOUBLE":"SINGLE"); break;
        case 7: running=0; break;
        default: printf("  Unknown choice\n"); break;
        }
    }
    free(g_perms_buf);
    printf("  Bye.\n"); return 0;
}
