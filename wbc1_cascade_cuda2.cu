/*
 * WBC1-Cascade-CUDA -- GPU-accelerated implementation
 * =====================================================
/*
 * Grid  = (n_messages, 1, 1)    — each CUDA block = one message
 * Block = (threads, 1, 1)       — adaptive: 64/128/256 threads
 *  - 256 threads/block cooperate on each cipher block (4096 bytes)
 *  - Cascade key chaining runs ENTIRELY on GPU (no CPU round-trips)
 *  - Permutation tables: built on CPU, transferred to GPU once
 *  - Shared memory per CUDA block: ~8 KB
 *    [cube 4096] + [tmp 4096] + [cascade_key 32] + [round_key 4096] = 12 KB
/*
 * Grid  = (n_messages, 1, 1)    — each CUDA block = one message
 * Block = (threads, 1, 1)       — adaptive: 64/128/256 threads
 *  - mix_cube          : parallel two-level prefix-XOR scan
 *  - XOR round key     : 256 threads, fully parallel
 *  - bitwise_rotate    : 256 threads, fully parallel
 *  - derive_cascade_key: 64 threads for fold step, thread-0 for F+B mixing
 *
 * Build (CUDA + MPI, requires CUDA Toolkit >= 11.0, sm_70+):
 *   nvcc -O2 -arch=sm_70 -ccbin mpicxx -o wbc1_cascade_cuda wbc1_cascade_cuda.cu \
 *        -lssl -lcrypto -lm
 *
 * Run (single process):
 *   ./wbc1_cascade_cuda           # menu
 *   ./wbc1_cascade_cuda --bench   # GPU vs CPU benchmark
 *   ./wbc1_cascade_cuda --test    # self-tests
 *
 * Run (multi-process, one rank per GPU):
 *   mpirun -np 4 ./wbc1_cascade_cuda --bench
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <cuda_runtime.h>
#include <mpi.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── CUDA error check ─────────────────────────────────────────────────────── */

#define CUDA_CHECK(call) do {                                        \
    cudaError_t _e = (call);                                         \
    if (_e != cudaSuccess) {                                         \
        fprintf(stderr, "CUDA error %s:%d: %s\n",                   \
                __FILE__, __LINE__, cudaGetErrorString(_e));         \
        exit(EXIT_FAILURE);                                          \
    }                                                                \
} while(0)

/* ── constants ─────────────────────────────────────────────────────────────── */

#define KEY_SIZE     32
#define ROUNDS       32   /* = KEY_SIZE: one round per key byte */
#define NUM_OPS      127
#define MAX_BLOCK    4096 /* 16^3 */
#define T_PER_BLOCK  256  /* CUDA threads per CUDA block */
#define ELEMS_PER_T  (MAX_BLOCK / T_PER_BLOCK) /* 16 bytes per thread */

/* Shared memory layout per CUDA block:
 *   [0              .. 4095] s_cube      (current cipher block)
 *   [4096           .. 8191] s_tmp       (permutation scratch)
 *   [8192           .. 8223] s_ckey      (cascade key, 32 bytes)
 *   [8224           .. 12319] s_rk       (pre-computed round key, 4096 bytes)
 *   total: 12320 bytes ~ 12 KB
 */
#define SHM_CUBE_OFF   0
#define SHM_TMP_OFF    (MAX_BLOCK)
#define SHM_CKEY_OFF   (2 * MAX_BLOCK)
#define SHM_RK_OFF     (2 * MAX_BLOCK + KEY_SIZE)
#define SHM_TOTAL      (2 * MAX_BLOCK + KEY_SIZE + MAX_BLOCK)

/* ── cube sizes (used by both CPU and GPU) ─────────────────────────────────── */

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

/* ============================================================================
 * CPU-SIDE INFRASTRUCTURE (operation table, permutation table)
 * ============================================================================ */

#define MT_N 624
typedef struct { uint32_t mt[MT_N]; int idx; } MT;
static void mt_seed(MT *m, uint32_t seed) {
    m->mt[0] = seed;
    for (int i=1;i<MT_N;i++)
        m->mt[i]=1812433253UL*(m->mt[i-1]^(m->mt[i-1]>>30))+(uint32_t)i;
    m->idx=MT_N;
}
static uint32_t mt_rand(MT *m) {
    if(m->idx>=MT_N){
        for(int i=0;i<MT_N;i++){
            uint32_t y=(m->mt[i]&0x80000000UL)|(m->mt[(i+1)%MT_N]&0x7fffffffUL);
            m->mt[i]=m->mt[(i+397)%MT_N]^(y>>1);
            if(y&1) m->mt[i]^=2567483615UL;
        }
        m->idx=0;
    }
    uint32_t y=m->mt[m->idx++];
    y^=y>>11; y^=(y<<7)&2636928640UL; y^=(y<<15)&4022730752UL; y^=y>>18;
    return y;
}
static int mt_randint(MT *m,int a,int b){int r=b-a+1;if(r<=0)return a;return a+(int)(mt_rand(m)%(uint32_t)r);}
static int mt_choice(MT *m,int n){return(int)(mt_rand(m)%(uint32_t)n);}
static void mt_shuffle(MT *m,int *arr,int n){for(int i=n-1;i>0;i--){int j=mt_randint(m,0,i);int t=arr[i];arr[i]=arr[j];arr[j]=t;}}

static uint32_t sha256_seed(const uint8_t *h32){
    return((uint32_t)h32[28]<<24)|((uint32_t)h32[29]<<16)|((uint32_t)h32[30]<<8)|(uint32_t)h32[31];
}
static void sha256_wrap(const uint8_t *data, size_t len, uint8_t out[32]){ SHA256(data,len,out); }

#define OP_FACE 0
#define OP_SLICE 1
#define OP_WIDE 2
#define OP_CUBE_ROT 3
#define OP_ALG 4
#define OP_PATTERN 5
#define OP_SWAP 6
#define OP_DIAGFLIP 7
#define MAX_CHAIN 8
#define N_STATIC_BASE 107
#define NUM_ALGS 20

typedef struct { uint8_t type; int8_t name; int8_t dir; } PrimOp;
typedef struct { PrimOp moves[MAX_CHAIN]; int len; } ComposedOp;
static ComposedOp g_ops[NUM_OPS];

static const char *ALGS_MOVES[NUM_ALGS] = {
    "R U R' U' R' F R2 U' R' U' R U R' F'",
    "F R U' R' U' R U R' F' R U R' U' R' F R F'",
    "R U R' F' R U R' U' R' F R2 U' R' U'",
    "R' U' F' R U R' U' R' F R2 U' R' U' R U R' U R",
    "x' R2 D2 R' U' R D2 R' U R' x",
    "x' R U' R' D R U R' D' R U R' D R U' R' D' x",
    "R U' R' U' R U R D R' U' R D' R' U2 R'",
    "R U' R U R U R U' R' U' R2",
    "R' U R' U' y R' F' R2 U' R' U R' F R F",
    "R U R' U R U R' F' R U R' U' R' F R2 U' R' U2 R U' R'",
    "M2 U M2 U M' U2 M2 U2 M' U2",
    "M2 U M2 U2 M2 U M2",
    "M2 E2 S2",
    "F L F U' R U F2 L2 U' L' B D' B' L2 U",
    "U R2 F B R B2 R U2 L B2 R U' D' R2 F R' L B2 U2 F2",
    "U D' R L' F B' U D'",
    "L R F B U' D' L' R'",
    "L U B' U' R L' B R' F B' D R D' F'",
    "F2 R' B' U R' L F' L F' B D' R B L2",
    "R D L F' R U' R' F L' D' R' U"
};

/* ── cube helpers for CPU perm-table building only ─────────────────────────── */

typedef struct { uint8_t *data; int dim; } Cube_h;

static inline int idx3_h(int dim,int i,int j,int k){return i*dim*dim+j*dim+k;}

static void get_slice_h(const Cube_h *c,int axis,int pos,uint8_t *sl){
    int dim=c->dim,p=((pos%dim)+dim)%dim;
    for(int i=0;i<dim;i++) for(int j=0;j<dim;j++){
        if(axis==0)      sl[i*dim+j]=c->data[idx3_h(dim,p,i,j)];
        else if(axis==1) sl[i*dim+j]=c->data[idx3_h(dim,i,p,j)];
        else             sl[i*dim+j]=c->data[idx3_h(dim,i,j,p)];
    }
}
static void set_slice_h(Cube_h *c,int axis,int pos,const uint8_t *sl){
    int dim=c->dim,p=((pos%dim)+dim)%dim;
    for(int i=0;i<dim;i++) for(int j=0;j<dim;j++){
        if(axis==0)      c->data[idx3_h(dim,p,i,j)]=sl[i*dim+j];
        else if(axis==1) c->data[idx3_h(dim,i,p,j)]=sl[i*dim+j];
        else             c->data[idx3_h(dim,i,j,p)]=sl[i*dim+j];
    }
}
static void rot90_2d_h(uint8_t *mat,int dim,int k){
    k=((k%4)+4)%4;
    uint8_t tmp[256];
    for(int t=0;t<k;t++){
        for(int i=0;i<dim;i++) for(int j=0;j<dim;j++)
            tmp[i*dim+j]=mat[j*dim+(dim-1-i)];
        memcpy(mat,tmp,(size_t)dim*dim);
    }
}
static void rotate_slice_h(Cube_h *c,int axis,int pos,int k){
    uint8_t sl[256];
    get_slice_h(c,axis,pos,sl); rot90_2d_h(sl,c->dim,k); set_slice_h(c,axis,pos,sl);
}
static void rotate_whole_h(Cube_h *c,int axis,int k){
    k=((k%4)+4)%4; int dim=c->dim,total=dim*dim*dim;
    uint8_t tmp[4096];
    for(int t=0;t<k;t++){
        int a0=axis,a1=(axis+1)%3;
        for(int i=0;i<dim;i++) for(int j=0;j<dim;j++) for(int kk=0;kk<dim;kk++){
            int coords[3]={i,j,kk};
            int nca0=coords[a1], nca1=dim-1-coords[a0];
            int nc[3]={i,j,kk}; nc[a0]=nca0; nc[a1]=nca1;
            tmp[idx3_h(dim,nc[0],nc[1],nc[2])]=c->data[idx3_h(dim,i,j,kk)];
        }
        memcpy(c->data,tmp,(size_t)total);
    }
}
static void diagflip_h(Cube_h *c,int axis){
    int dim=c->dim,total=dim*dim*dim; uint8_t tmp[4096];
    for(int i=0;i<dim;i++) for(int j=0;j<dim;j++) for(int k=0;k<dim;k++){
        int di,dj,dk;
        if(axis==0){di=i;dj=k;dk=j;}else if(axis==1){di=k;dj=j;dk=i;}else{di=j;dj=i;dk=k;}
        tmp[idx3_h(dim,di,dj,dk)]=c->data[idx3_h(dim,i,j,k)];
    }
    memcpy(c->data,tmp,(size_t)total);
}
static void swap_layers_h(Cube_h *c,int axis,int a,int b){
    int dim=c->dim; a=((a%dim)+dim)%dim; b=((b%dim)+dim)%dim;
    uint8_t s1[256],s2[256];
    get_slice_h(c,axis,a,s1); get_slice_h(c,axis,b,s2);
    set_slice_h(c,axis,a,s2); set_slice_h(c,axis,b,s1);
}

static void build_prim_op_h(PrimOp *out,int base_idx){
    int i=base_idx;
    if(i<24){out->type=OP_FACE;    out->name=(int8_t)(i/4);out->dir=(int8_t)(i%4);return;}i-=24;
    if(i<12){out->type=OP_SLICE;   out->name=(int8_t)(i/4);out->dir=(int8_t)(i%4);return;}i-=12;
    if(i<24){out->type=OP_WIDE;    out->name=(int8_t)(i/4);out->dir=(int8_t)(i%4);return;}i-=24;
    if(i<12){out->type=OP_CUBE_ROT;out->name=(int8_t)(i/4);out->dir=(int8_t)(i%4);return;}i-=12;
    if(i<12){out->type=OP_ALG;     out->name=(int8_t)i;    out->dir=0;             return;}i-=12;
    if(i< 8){out->type=OP_PATTERN; out->name=(int8_t)(12+i);out->dir=0;            return;}i-=8;
    if(i<12){out->type=OP_SWAP;    out->name=(int8_t)(i/4);out->dir=(int8_t)(i%4); return;}i-=12;
    if(i< 3){out->type=OP_DIAGFLIP;out->name=(int8_t)i;    out->dir=0;             return;}
    out->type=OP_FACE;out->name=0;out->dir=0;
}

static int dchar_k(char d,int inv){
    int k; switch(d){case '\'':k=-1;break;case '2':k=2;break;case '3':k=3;break;default:k=1;break;}
    return inv?-k:k;
}
static void apply_token_h(Cube_h *c,const char *tok,int inv){
    if(!tok||!*tok)return;
    int len=(int)strlen(tok);
    char base=tok[0];
    char dm=(len>1&&(tok[len-1]=='\''||tok[len-1]=='2'||tok[len-1]=='3'))?tok[len-1]:0;
    int k=dchar_k(dm,inv);
    static const int fa[]={0,0,1,1,2,2};static const int fp[]={0,-1,0,-1,0,-1};
    static const int dk[]={1,-1,2,3};
    (void)dk;
    if(base=='U'){rotate_slice_h(c,0, 0,k);return;}
    if(base=='D'){rotate_slice_h(c,0,-1,k);return;}
    if(base=='L'){rotate_slice_h(c,1, 0,k);return;}
    if(base=='R'){rotate_slice_h(c,1,-1,k);return;}
    if(base=='F'){rotate_slice_h(c,2, 0,k);return;}
    if(base=='B'){rotate_slice_h(c,2,-1,k);return;}
    if(base=='M'){rotate_slice_h(c,1, 1,k);return;}
    if(base=='E'){rotate_slice_h(c,0, 1,k);return;}
    if(base=='S'){rotate_slice_h(c,2, 1,k);return;}
    if(base=='x'){rotate_whole_h(c,0,k);return;}
    if(base=='y'){rotate_whole_h(c,1,k);return;}
    if(base=='z'){rotate_whole_h(c,2,k);return;}
    (void)fa;(void)fp;
}
static void apply_alg_h(Cube_h *c,const char *moves,int inv){
    char buf[512]; strncpy(buf,moves,sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    for(char *p=buf;*p;p++) if(*p==',') *p=' ';
    char *toks[256]; int nt=0;
    char *t=strtok(buf," ");
    while(t&&nt<255){toks[nt++]=t;t=strtok(NULL," ");}
    if(!inv) for(int i=0;i<nt;i++) apply_token_h(c,toks[i],0);
    else     for(int i=nt-1;i>=0;i--) apply_token_h(c,toks[i],1);
}
static void apply_prim_h(Cube_h *c,const PrimOp *op,int inv){
    static const int fa[]={0,0,1,1,2,2};static const int fp[]={0,-1,0,-1,0,-1};
    static const int ca[]={0,1,2};
    int k;
    switch(((op->dir%4)+4)%4){case 0:k=1;break;case 1:k=-1;break;case 2:k=2;break;default:k=3;break;}
    if(inv)k=-k;
    if(op->type==OP_FACE){rotate_slice_h(c,fa[op->name&7],fp[op->name&7],k);}
    else if(op->type==OP_SLICE){rotate_slice_h(c,1,1,k);}
    else if(op->type==OP_WIDE){int ax=fa[op->name&7];rotate_slice_h(c,ax,0,k);rotate_slice_h(c,ax,1,k);}
    else if(op->type==OP_CUBE_ROT){rotate_whole_h(c,ca[op->name%3],k);}
    else if(op->type==OP_ALG||op->type==OP_PATTERN){apply_alg_h(c,ALGS_MOVES[op->name%NUM_ALGS],inv);}
    else if(op->type==OP_SWAP){swap_layers_h(c,op->name%3,op->dir,op->dir+1);}
    else if(op->type==OP_DIAGFLIP){diagflip_h(c,op->name%3);}
}
static void apply_composed_h(Cube_h *c,const ComposedOp *cop,int inv){
    if(inv){for(int i=cop->len-1;i>=0;i--) apply_prim_h(c,&cop->moves[i],1);}
    else   {for(int i=0;i<cop->len;i++) apply_prim_h(c,&cop->moves[i],0);}
}

static void build_op_table(const uint8_t key[32]){
    for(int i=0;i<NUM_OPS;i++){
        uint8_t h[32],buf[KEY_SIZE+11];
        memcpy(buf,key,KEY_SIZE); memcpy(buf+KEY_SIZE,"WBC1_OP",7);
        buf[KEY_SIZE+7]=(uint8_t)i; buf[KEY_SIZE+8]=(uint8_t)(i>>8);
        buf[KEY_SIZE+9]=0; buf[KEY_SIZE+10]=0;
        sha256_wrap(buf,KEY_SIZE+11,h);
        MT mt; mt_seed(&mt,sha256_seed(h));
        int chain_len=mt_randint(&mt,3,6); g_ops[i].len=chain_len;
        for(int j=0;j<chain_len;j++) build_prim_op_h(&g_ops[i].moves[j],mt_choice(&mt,N_STATIC_BASE));
    }
    uint8_t kh[32]; sha256_wrap(key,KEY_SIZE,kh);
    MT mt; mt_seed(&mt,sha256_seed(kh));
    int order[NUM_OPS]; for(int i=0;i<NUM_OPS;i++) order[i]=i;
    mt_shuffle(&mt,order,NUM_OPS);
    ComposedOp tmp[NUM_OPS]; memcpy(tmp,g_ops,sizeof(g_ops));
    for(int i=0;i<NUM_OPS;i++) g_ops[i]=tmp[order[i]];
}

/* ── permutation table (CPU side) ─────────────────────────────────────────── */

static uint16_t *h_perms = NULL; /* host-side perm table */
static uint16_t *d_perms = NULL; /* device-side perm table */
static int       h_perm_bs = -1;
static int       g_has_cuda = 1;

typedef struct {
    uint8_t *d_key_dev;
    uint8_t *d_in;
    uint8_t *d_out;
    size_t capacity;
    uint8_t cached_key[KEY_SIZE];
    int have_key;
} GpuBufferCache;

static GpuBufferCache g_gpu_cache = {0};

static void gpu_cache_reserve(size_t bytes){
    if(!g_has_cuda) return;
    if(g_gpu_cache.capacity >= bytes) return;

    if(g_gpu_cache.d_in)  CUDA_CHECK(cudaFree(g_gpu_cache.d_in));
    if(g_gpu_cache.d_out) CUDA_CHECK(cudaFree(g_gpu_cache.d_out));
    if(!g_gpu_cache.d_key_dev) CUDA_CHECK(cudaMalloc(&g_gpu_cache.d_key_dev, KEY_SIZE));

    CUDA_CHECK(cudaMalloc(&g_gpu_cache.d_in, bytes));
    CUDA_CHECK(cudaMalloc(&g_gpu_cache.d_out, bytes));
    g_gpu_cache.capacity = bytes;
}

static void gpu_cache_set_key(const uint8_t key[KEY_SIZE]){
    if(!g_has_cuda) return;
    if(g_gpu_cache.have_key && memcmp(g_gpu_cache.cached_key, key, KEY_SIZE) == 0) return;
    if(!g_gpu_cache.d_key_dev) CUDA_CHECK(cudaMalloc(&g_gpu_cache.d_key_dev, KEY_SIZE));
    CUDA_CHECK(cudaMemcpy(g_gpu_cache.d_key_dev, key, KEY_SIZE, cudaMemcpyHostToDevice));
    memcpy(g_gpu_cache.cached_key, key, KEY_SIZE);
    g_gpu_cache.have_key = 1;
}

static void gpu_cache_release(void){
    if(g_gpu_cache.d_key_dev) CUDA_CHECK(cudaFree(g_gpu_cache.d_key_dev));
    if(g_gpu_cache.d_in)      CUDA_CHECK(cudaFree(g_gpu_cache.d_in));
    if(g_gpu_cache.d_out)     CUDA_CHECK(cudaFree(g_gpu_cache.d_out));
    memset(&g_gpu_cache, 0, sizeof(g_gpu_cache));
}

static void build_perm_table_cpu(int block_size){
    if(h_perm_bs==block_size) return;
    free(h_perms);
    h_perms=(uint16_t*)malloc((size_t)2*NUM_OPS*block_size*sizeof(uint16_t));
    h_perm_bs=block_size;
    int dim=dim_for(block_size);
    uint8_t tmp[MAX_BLOCK];

    for(int op=0;op<NUM_OPS;op++){
        uint16_t *fwd=h_perms+(size_t)op*block_size;
        uint16_t *inv=h_perms+(size_t)(op+NUM_OPS)*block_size;
        uint8_t data[MAX_BLOCK];
        memset(data,0,MAX_BLOCK);
        for(int i=0;i<block_size;i++) data[i]=(uint8_t)(i&0xFF);
        Cube_h c={data,dim}; apply_composed_h(&c,&g_ops[op],0);
        for(int j=0;j<block_size;j++) fwd[j]=(uint16_t)data[j];
        if(block_size>256){
            memset(data,0,MAX_BLOCK);
            for(int i=0;i<block_size;i++) data[i]=(uint8_t)(i>>8);
            c={data,dim}; apply_composed_h(&c,&g_ops[op],0);
            for(int j=0;j<block_size;j++) fwd[j]|=(uint16_t)((uint16_t)data[j]<<8);
        }
        for(int i=0;i<block_size;i++) inv[fwd[i]]=(uint16_t)i;
    }
    (void)tmp;

    /* Upload to GPU only when CUDA is available. */
    if(g_has_cuda){
        if(d_perms) cudaFree(d_perms);
        size_t sz=(size_t)2*NUM_OPS*block_size*sizeof(uint16_t);
        CUDA_CHECK(cudaMalloc(&d_perms, sz));
        CUDA_CHECK(cudaMemcpy(d_perms, h_perms, sz, cudaMemcpyHostToDevice));
    }
}

/* ============================================================================
 * GPU DEVICE HELPERS
 * ============================================================================ */

__device__ static uint8_t d_rol8(uint8_t b, int n){
    n&=7; return (uint8_t)((b<<n)|(b>>(8-n)));
}
__device__ static uint8_t d_ror8(uint8_t b, int n){
    n&=7; return (uint8_t)((b>>n)|(b<<(8-n)));
}

/* Parallel inclusive prefix-XOR scan on s_cube in shared memory.
 * Uses two-level Blelloch approach: local scan per warp, then global.
 * Requires that block_size is a power of 2 OR handled generically below.
 * For simplicity we use a segmented scan across 256 threads × 16 elems. */
__device__ static void d_mix_cube(uint8_t *s, int n, int tid, int T){
    /* Partition [0, n) generically so small and non-divisible blocks stay valid. */
    int start = (tid * n) / T;
    int end   = ((tid + 1) * n) / T;

    for(int i = start + 1; i < end; i++)
        s[i] ^= s[i-1];
    __syncthreads();

    /* Step 2: broadcast segment tails into next segment (sequential, T steps)
     * Thread t's tail = s[base + n/T - 1]
     * Thread (t+1) gets XOR from thread t's tail
     * We do this with a shared scan on tails across T threads. */
    extern __shared__ uint8_t smem_base[];
    uint8_t *s_tails = smem_base + SHM_TOTAL; /* extra T bytes appended to SHM */
    s_tails[tid] = (end > start) ? s[end - 1] : 0;
    __syncthreads();

    /* prefix XOR on tails (thread 0 does it sequentially: cheap, T=256 ops) */
    if(tid == 0){
        for(int i = 1; i < T; i++)
            s_tails[i] ^= s_tails[i-1];
    }
    __syncthreads();

    /* Step 3: each thread (except t=0) adjusts its segment */
    if(tid > 0 && end > start){
        uint8_t carry = s_tails[tid-1];
        for(int i = start; i < end; i++)
            s[i] ^= carry;
    }
    __syncthreads();
}

/* Inverse mix_cube: parallel inverse prefix XOR.
 * inv_prefix_XOR: orig[i] = result[i] ^ result[i-1]  (trivially data-parallel).
 *
 * For small n many threads have empty segments; using s_tails[tid-1] would
 * skip over those empty slots and produce the wrong carry.  Instead every
 * thread saves s[start-1] (its own predecessor) BEFORE any element is
 * modified – the read is always of the original result[] array. */
__device__ static void d_inv_mix_cube(uint8_t *s, int n, int tid, int T){
    int start = (tid * n) / T;
    int end   = ((tid + 1) * n) / T;

    extern __shared__ uint8_t smem_base[];
    uint8_t *s_pre = smem_base + SHM_TOTAL; /* T bytes scratch */

    /* Each thread reads its own predecessor (result[start-1]) before step 2
     * touches anything.  Thread 0 / empty segments use 0 (identity). */
    s_pre[tid] = (start > 0) ? s[start - 1] : 0;
    __syncthreads();

    /* Within-segment inverse prefix XOR: right-to-left so s[i-1] is untouched */
    for(int i = end - 1; i > start; i--)
        s[i] ^= s[i - 1];
    __syncthreads();

    /* Cross-segment boundary: fix s[start] using the saved predecessor */
    if(end > start)
        s[start] ^= s_pre[tid];
    __syncthreads();
}

/* derive_cascade_key: 64 threads for fold, thread-0 for F+B mixing */
__device__ static void d_derive_cascade_key(
    const uint8_t *enc_block, int block_bytes,
    uint8_t *s_ckey, /* shared memory [KEY_SIZE] output */
    int tid)
{
    /* Use first 64 threads to fold enc_block into S[64] */
    __shared__ uint8_t s_S[64];
    if(tid < 64) s_S[tid] = 0;
    __syncthreads();

    /* Each of 64 threads accumulates its XOR lane */
    if(tid < 64){
        uint8_t acc = 0;
        for(int j = tid; j < block_bytes; j += 64)
            acc ^= enc_block[j];
        s_S[tid] = acc;
    }
    __syncthreads();

    /* F+B mixing — sequential, thread 0 only */
    if(tid == 0){
        for(int r = 0; r < 4; r++){
            uint8_t c = (uint8_t)(s_S[63] ^ (uint8_t)r);
            for(int i = 0; i < 64; i++){
                c = (uint8_t)(s_S[i] + d_rol8(c,5) + (uint8_t)(67*i + 29*r));
                s_S[i] = c;
            }
            c = (uint8_t)(s_S[0] ^ (uint8_t)(r*37));
            for(int i = 63; i >= 0; i--){
                c = s_S[i] ^ d_ror8(c,3);
                s_S[i] = c;
            }
        }
        for(int i = 0; i < KEY_SIZE; i++) s_ckey[i] = s_S[i];
    }
    __syncthreads();
}

/* ============================================================================
 * MAIN CUDA KERNELS
 * ============================================================================
 *
 * Grid  = (n_messages, 1, 1)    — each CUDA block = one message
 * Block = (T_PER_BLOCK, 1, 1)   — 256 threads/CUDA-block
 *
 * Shared memory layout:
 *   [SHM_CUBE_OFF  .. +MAX_BLOCK)   s_cube    (cipher block)
 *   [SHM_TMP_OFF   .. +MAX_BLOCK)   s_tmp     (permutation temp)
 *   [SHM_CKEY_OFF  .. +KEY_SIZE)    s_ckey    (cascade key)
 *   [SHM_RK_OFF    .. +MAX_BLOCK)   s_rk      (round key for current round)
 *   [SHM_TOTAL     .. +threads) s_tails   (prefix scan tails)
 *
 *  Total: SHM_TOTAL + threads (max 12320 + 256 = 12576 bytes)
 */

__global__ void encrypt_message_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g);

__global__ void decrypt_message_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g);

static size_t shm_launch_bytes(int threads){
    return SHM_TOTAL + (size_t)threads;
}

static int select_threads_per_block(int block_size){
    (void)block_size;
    const char *env = getenv("WBC_CUDA_THREADS");
    if(env){
        int v = atoi(env);
        if(v == 64 || v == 128 || v == 256) return v;
    }

    /* Occupancy-driven choice: pick threads that maximize resident warps/SM
     * across both encrypt and decrypt kernels. */
    {
        const int candidates[3] = {64, 128, 256};
        int best_threads = 256;
        int best_score = -1;

        for(int i = 0; i < 3; i++){
            int t = candidates[i];
            int enc_blocks = 0;
            int dec_blocks = 0;
            size_t shm = shm_launch_bytes(t);

            cudaError_t e1 = cudaOccupancyMaxActiveBlocksPerMultiprocessor(
                &enc_blocks, encrypt_message_kernel, t, shm);
            cudaError_t e2 = cudaOccupancyMaxActiveBlocksPerMultiprocessor(
                &dec_blocks, decrypt_message_kernel, t, shm);

            if(e1 != cudaSuccess || e2 != cudaSuccess) continue;

            /* Conservative score: bottleneck kernel decides. */
            int min_blocks = (enc_blocks < dec_blocks) ? enc_blocks : dec_blocks;
            int score = min_blocks * t; /* proportional to active threads/SM */

            if(score > best_score){
                best_score = score;
                best_threads = t;
            }
        }

        return best_threads;
    }
}

/* Reusable round helpers for single- and double-pass kernels. */
__device__ static void d_encrypt_block_rounds(
    uint8_t *s_cube, uint8_t *s_tmp, uint8_t *s_ckey, uint8_t *s_rk,
    int block_size, int tid, int T, const uint16_t *d_perms_g)
{
    for(int r = 0; r < ROUNDS; r++){
        const int op_id = (int)(s_ckey[r] % NUM_OPS);
        const int shift  = r & 7;
        for(int i = tid; i < block_size; i += T)
            s_rk[i] = d_rol8(s_ckey[(i + r*7) % KEY_SIZE], shift);
        __syncthreads();
        { const uint16_t *perm = d_perms_g + (size_t)op_id * block_size;
          for(int i = tid; i < block_size; i += T) s_tmp[i] = s_cube[perm[i]]; }
        __syncthreads();
        for(int i = tid; i < block_size; i += T) s_cube[i] = s_tmp[i];
        __syncthreads();
        d_mix_cube(s_cube, block_size, tid, T);
        for(int i = tid; i < block_size; i += T) s_cube[i] ^= s_rk[i];
        __syncthreads();
        { const int n = op_id & 7;
          for(int i = tid; i < block_size; i += T) s_cube[i] = d_ror8(s_cube[i], n); }
        __syncthreads();
    }
}

__device__ static void d_decrypt_block_rounds(
    uint8_t *s_cube, uint8_t *s_tmp, uint8_t *s_ckey, uint8_t *s_rk,
    int block_size, int tid, int T, const uint16_t *d_perms_g)
{
    for(int r = ROUNDS-1; r >= 0; r--){
        const int op_id = (int)(s_ckey[r] % NUM_OPS);
        const int shift  = r & 7;
        for(int i = tid; i < block_size; i += T)
            s_rk[i] = d_rol8(s_ckey[(i + r*7) % KEY_SIZE], shift);
        __syncthreads();
                { const int n = op_id & 7;
                    for(int i = tid; i < block_size; i += T) s_cube[i] = d_rol8(s_cube[i], n); }
        __syncthreads();
        for(int i = tid; i < block_size; i += T) s_cube[i] ^= s_rk[i];
        __syncthreads();
        d_inv_mix_cube(s_cube, block_size, tid, T);
        { const uint16_t *ip = d_perms_g + (size_t)(op_id + NUM_OPS) * block_size;
          for(int i = tid; i < block_size; i += T) s_tmp[i] = s_cube[ip[i]]; }
        __syncthreads();
        for(int i = tid; i < block_size; i += T) s_cube[i] = s_tmp[i];
        __syncthreads();
    }
}

__global__ void encrypt_message_kernel(
    const uint8_t  *d_key,        /* initial cascade key (32 bytes per message,
                                     stride = KEY_SIZE × blockIdx.x)           */
    const uint8_t  *d_in,         /* padded input  (stride = n_blocks*block_size) */
    uint8_t        *d_out,        /* output        (same stride)                  */
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g     /* perm table on GPU                            */
){
    const int tid  = threadIdx.x;
    const int T    = blockDim.x;

    /* Shared memory partitioning */
    extern __shared__ uint8_t smem_base[];
    uint8_t *s_cube  = smem_base + SHM_CUBE_OFF;
    uint8_t *s_tmp   = smem_base + SHM_TMP_OFF;
    uint8_t *s_ckey  = smem_base + SHM_CKEY_OFF;
    uint8_t *s_rk    = smem_base + SHM_RK_OFF;
    /* s_tails lives at SHM_TOTAL, accessed via smem_base in d_mix_cube */

    /* Per-message offset */
    const int msg_id   = blockIdx.x;
    const size_t in_off  = (size_t)msg_id * n_blocks * block_size;
    const size_t out_off = (size_t)msg_id * n_blocks * block_size;

    /* Load initial cascade key */
    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();

    /* ── process cipher blocks sequentially (cascade dependency) ── */
    for(int blk = 0; blk < n_blocks; blk++){
        const uint8_t *src = d_in  + in_off  + (size_t)blk * block_size;
        uint8_t       *dst = d_out + out_off + (size_t)blk * block_size;

        /* Load cipher block into shared memory */
        for(int i = tid; i < block_size; i += T) s_cube[i] = src[i];
        __syncthreads();

        /* ── 32 rounds ── */
        for(int r = 0; r < ROUNDS; r++){
            const int op_id = (int)(s_ckey[r] % NUM_OPS);
            const int shift  = r & 7;

            /* Pre-compute round key for this round into s_rk */
            for(int i = tid; i < block_size; i += T)
                s_rk[i] = d_rol8(s_ckey[(i + r*7) % KEY_SIZE], shift);
            __syncthreads();

            /* == 1. apply_operation (forward permutation) == */
            {
                const uint16_t *perm = d_perms_g + (size_t)op_id * block_size;
                for(int i = tid; i < block_size; i += T)
                    s_tmp[i] = s_cube[perm[i]]; /* gather: global perm → shared cube */
            }
            __syncthreads();
            for(int i = tid; i < block_size; i += T) s_cube[i] = s_tmp[i];
            __syncthreads();

            /* == 2. mix_cube (parallel prefix XOR) == */
            d_mix_cube(s_cube, block_size, tid, T);
            /* __syncthreads() already called inside d_mix_cube */

            /* == 3. XOR round key == */
            for(int i = tid; i < block_size; i += T) s_cube[i] ^= s_rk[i];
            __syncthreads();

            /* == 4. bitwise_rotate_cube (right by op_id) == */
            {
                const int n = op_id & 7;
                for(int i = tid; i < block_size; i += T)
                    s_cube[i] = d_ror8(s_cube[i], n);
            }
            __syncthreads();
        } /* end ROUNDS */

        /* Store encrypted cipher block */
        for(int i = tid; i < block_size; i += T) dst[i] = s_cube[i];
        __syncthreads();

        /* Derive cascade key for next block */
        if(blk < n_blocks - 1)
            d_derive_cascade_key(s_cube, block_size, s_ckey, tid);
        /* __syncthreads() inside d_derive_cascade_key */
    } /* end blk */
}

__global__ void decrypt_message_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g);

__global__ void encrypt_double_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g);

__global__ void decrypt_double_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g);

__global__ void decrypt_message_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g)
{
    const int tid = threadIdx.x;
    const int T   = blockDim.x;

    extern __shared__ uint8_t smem_base[];
    uint8_t *s_cube = smem_base + SHM_CUBE_OFF;
    uint8_t *s_tmp  = smem_base + SHM_TMP_OFF;
    uint8_t *s_ckey = smem_base + SHM_CKEY_OFF;
    uint8_t *s_rk   = smem_base + SHM_RK_OFF;

    const int    msg_id  = blockIdx.x;
    const size_t in_off  = (size_t)msg_id * n_blocks * block_size;
    const size_t out_off = (size_t)msg_id * n_blocks * block_size;

    /* For decryption we need ALL cascade keys up-front (since each block's
     * cascade key depends on the previous block's ENCRYPTED output).
     * We pre-compute cascade keys in a forward pass, store in global scratch,
     * then decrypt blocks in forward order using stored keys.
     * This requires an extra pass but avoids a full CPU round-trip. */

    /* For simplicity in this reference implementation: decrypt block-by-block
     * keeping cascade_key chain identical to encryption.
     * Each decrypted block produces the same encrypted intermediate → same key. */

    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();

    /* Two-pass: forward pass to collect encrypted blocks (= cascade key sources),
     * then backward decrypt. Since encrypted data is already in d_in, cascade keys
     * are derived from d_in blocks directly. */

    /* Cascade keys array - one per block, 32 bytes each.
     * We allocate them on stack per thread-block (up to n_blocks * 32 bytes).
     * For large n_blocks this may exceed stack; use global scratch for large. */

    for(int blk = 0; blk < n_blocks; blk++){
        const uint8_t *enc_blk = d_in  + in_off  + (size_t)blk * block_size;
        uint8_t       *dst     = d_out + out_off + (size_t)blk * block_size;

        /* Load encrypted block */
        for(int i = tid; i < block_size; i += T) s_cube[i] = enc_blk[i];
        __syncthreads();

        /* Reverse rounds */
        for(int r = ROUNDS-1; r >= 0; r--){
            const int op_id = (int)(s_ckey[r] % NUM_OPS);
            const int shift  = r & 7;

            /* Pre-compute round key */
            for(int i = tid; i < block_size; i += T)
                s_rk[i] = d_rol8(s_ckey[(i + r*7) % KEY_SIZE], shift);
            __syncthreads();

            /* == 4 inv. bitwise_rotate_cube (left) == */
            {
                const int n = op_id & 7;
                for(int i = tid; i < block_size; i += T)
                    s_cube[i] = d_rol8(s_cube[i], n);
            }
            __syncthreads();

            /* == 3 inv. XOR round key (self-inverse) == */
            for(int i = tid; i < block_size; i += T) s_cube[i] ^= s_rk[i];
            __syncthreads();

            /* == 2 inv. mix_cube == */
            d_inv_mix_cube(s_cube, block_size, tid, T);

            /* == 1 inv. apply_operation (inverse permutation) == */
            {
                const uint16_t *inv_perm = d_perms_g + (size_t)(op_id + NUM_OPS) * block_size;
                for(int i = tid; i < block_size; i += T)
                    s_tmp[i] = s_cube[inv_perm[i]];
            }
            __syncthreads();
            for(int i = tid; i < block_size; i += T) s_cube[i] = s_tmp[i];
            __syncthreads();
        }

        /* Store decrypted block */
        for(int i = tid; i < block_size; i += T) dst[i] = s_cube[i];
        __syncthreads();

        /* Advance cascade key using ENCRYPTED block (same as during encryption) */
        if(blk < n_blocks - 1)
            d_derive_cascade_key(enc_blk, block_size, s_ckey, tid);
    }
}

__global__ void encrypt_double_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g)
{
    const int tid = threadIdx.x;
    const int T   = blockDim.x;

    extern __shared__ uint8_t smem_base[];
    uint8_t *s_cube = smem_base + SHM_CUBE_OFF;
    uint8_t *s_tmp  = smem_base + SHM_TMP_OFF;
    uint8_t *s_ckey = smem_base + SHM_CKEY_OFF;
    uint8_t *s_rk   = smem_base + SHM_RK_OFF;

    const int msg_id  = blockIdx.x;
    const size_t in_off  = (size_t)msg_id * n_blocks * block_size;
    const size_t out_off = (size_t)msg_id * n_blocks * block_size;

    /* Pass 1: forward. */
    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();
    for(int blk = 0; blk < n_blocks; blk++){
        const uint8_t *src = d_in  + in_off  + (size_t)blk * block_size;
        uint8_t       *dst = d_out + out_off + (size_t)blk * block_size;
        for(int i = tid; i < block_size; i += T) s_cube[i] = src[i];
        __syncthreads();
        d_encrypt_block_rounds(s_cube, s_tmp, s_ckey, s_rk, block_size, tid, T, d_perms_g);
        for(int i = tid; i < block_size; i += T) dst[i] = s_cube[i];
        __syncthreads();
        if(blk < n_blocks - 1)
            d_derive_cascade_key(s_cube, block_size, s_ckey, tid);
    }

    /* Pass 2: backward. */
    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();
    d_derive_cascade_key(s_ckey, KEY_SIZE, s_ckey, tid);
    for(int blk = n_blocks - 1; blk >= 0; blk--){
        uint8_t *p = d_out + out_off + (size_t)blk * block_size;
        for(int i = tid; i < block_size; i += T) s_cube[i] = p[i];
        __syncthreads();
        d_encrypt_block_rounds(s_cube, s_tmp, s_ckey, s_rk, block_size, tid, T, d_perms_g);
        for(int i = tid; i < block_size; i += T) p[i] = s_cube[i];
        __syncthreads();
        if(blk > 0)
            d_derive_cascade_key(s_cube, block_size, s_ckey, tid);
    }
}

__global__ void decrypt_double_kernel(
    const uint8_t  *d_key,
    const uint8_t  *d_in,
    uint8_t        *d_out,
    int             block_size,
    int             n_blocks,
    const uint16_t *d_perms_g)
{
    const int tid = threadIdx.x;
    const int T   = blockDim.x;

    extern __shared__ uint8_t smem_base[];
    uint8_t *s_cube = smem_base + SHM_CUBE_OFF;
    uint8_t *s_tmp  = smem_base + SHM_TMP_OFF;
    uint8_t *s_ckey = smem_base + SHM_CKEY_OFF;
    uint8_t *s_rk   = smem_base + SHM_RK_OFF;

    const int msg_id  = blockIdx.x;
    const size_t in_off  = (size_t)msg_id * n_blocks * block_size;
    const size_t out_off = (size_t)msg_id * n_blocks * block_size;

    /* Undo backward pass. */
    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();
    d_derive_cascade_key(s_ckey, KEY_SIZE, s_ckey, tid);
    for(int blk = n_blocks - 1; blk >= 0; blk--){
        const uint8_t *enc_blk = d_in  + in_off  + (size_t)blk * block_size;
        uint8_t       *dst     = d_out + out_off + (size_t)blk * block_size;
        for(int i = tid; i < block_size; i += T) s_cube[i] = enc_blk[i];
        __syncthreads();
        d_decrypt_block_rounds(s_cube, s_tmp, s_ckey, s_rk, block_size, tid, T, d_perms_g);
        for(int i = tid; i < block_size; i += T) dst[i] = s_cube[i];
        __syncthreads();
        d_derive_cascade_key(enc_blk, block_size, s_ckey, tid);
    }

    /* Undo forward pass in-place. */
    if(tid < KEY_SIZE) s_ckey[tid] = d_key[msg_id * KEY_SIZE + tid];
    __syncthreads();
    for(int blk = 0; blk < n_blocks; blk++){
        uint8_t *p = d_out + out_off + (size_t)blk * block_size;
        for(int i = tid; i < block_size; i += T) s_cube[i] = p[i];
        __syncthreads();
        d_decrypt_block_rounds(s_cube, s_tmp, s_ckey, s_rk, block_size, tid, T, d_perms_g);
        if(blk < n_blocks - 1)
            d_derive_cascade_key(p, block_size, s_ckey, tid);
        for(int i = tid; i < block_size; i += T) p[i] = s_cube[i];
        __syncthreads();
    }
}

/* ============================================================================
 * HOST-SIDE CUDA WRAPPERS
 * ============================================================================ */

/* Padding (CPU) */
static uint8_t *wbc1_pad(const uint8_t *data, size_t data_len,
                          int block_bytes, size_t *out_len){
    int rem   = (int)(data_len % block_bytes);
    int fill  = (rem==0) ? 0 : block_bytes - rem;
    size_t al = data_len + fill;
    size_t tot = al + block_bytes;
    uint8_t *out = (uint8_t*)calloc(tot, 1);
    memcpy(out, data, data_len);
    out[al]   = (uint8_t)(fill & 0xFF);
    out[al+1] = (uint8_t)((fill>>8) & 0xFF);
    *out_len = tot;
    return out;
}
static size_t wbc1_padded_len(size_t data_len, int block_bytes){
    int rem = (int)(data_len % block_bytes);
    int fill = (rem == 0) ? 0 : block_bytes - rem;
    return data_len + (size_t)fill + (size_t)block_bytes;
}
static void wbc1_pad_into(uint8_t *dst, const uint8_t *src,
                          size_t data_len, int block_bytes){
    size_t tot = wbc1_padded_len(data_len, block_bytes);
    int rem = (int)(data_len % block_bytes);
    int fill = (rem == 0) ? 0 : block_bytes - rem;
    size_t aligned_len = data_len + (size_t)fill;
    memset(dst, 0, tot);
    memcpy(dst, src, data_len);
    dst[aligned_len] = (uint8_t)(fill & 0xFF);
    dst[aligned_len + 1] = (uint8_t)((fill >> 8) & 0xFF);
}
static uint8_t *wbc1_unpad(const uint8_t *data, size_t data_len,
                             int block_bytes, size_t *out_len){
    if((int)data_len < block_bytes){ *out_len=0; return (uint8_t*)calloc(1,1); }
    int fill = (int)data[data_len-block_bytes] | ((int)data[data_len-block_bytes+1]<<8);
    size_t strip = (size_t)block_bytes + fill;
    if(strip > data_len){ *out_len=0; return (uint8_t*)calloc(1,1); }
    *out_len = data_len - strip;
    uint8_t *out = (uint8_t*)malloc(*out_len + 1);
    memcpy(out, data, *out_len); out[*out_len] = 0;
    return out;
}

/* Encrypt a single message using GPU (single-pass legacy path).
 * Returns heap-allocated ciphertext; caller frees.
 * n_msgs  = 1 for a single message; >1 for batch (all same key/block_size). */
static __attribute__((unused)) uint8_t *cuda_cascade_encrypt(
    const uint8_t *key,     /* KEY_SIZE bytes */
    const uint8_t *data,    size_t data_len,
    int            block_size,
    size_t        *enc_len_out)
{
    build_perm_table_cpu(block_size);

    size_t padded_len;
    uint8_t *padded = wbc1_pad(data, data_len, block_size, &padded_len);
    int n_blocks = (int)(padded_len / block_size);

    gpu_cache_reserve(padded_len);
    gpu_cache_set_key(key);

    CUDA_CHECK(cudaMemcpy(g_gpu_cache.d_in, padded, padded_len, cudaMemcpyHostToDevice));
    free(padded);

    {
        int threads = select_threads_per_block(block_size);
        encrypt_message_kernel<<<1, threads, shm_launch_bytes(threads)>>>(
        g_gpu_cache.d_key_dev, g_gpu_cache.d_in, g_gpu_cache.d_out,
        block_size, n_blocks, d_perms);
    }
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    /* Copy result back */
    uint8_t *result = (uint8_t*)malloc(padded_len);
    CUDA_CHECK(cudaMemcpy(result, g_gpu_cache.d_out, padded_len, cudaMemcpyDeviceToHost));

    *enc_len_out = padded_len;
    return result;
}

static __attribute__((unused)) uint8_t *cuda_cascade_decrypt(
    const uint8_t *key,
    const uint8_t *enc_data, size_t enc_len,
    int            block_size,
    size_t        *dec_len_out)
{
    build_perm_table_cpu(block_size);

    int n_blocks = (int)(enc_len / block_size);

    gpu_cache_reserve(enc_len);
    gpu_cache_set_key(key);

    CUDA_CHECK(cudaMemcpy(g_gpu_cache.d_in, enc_data, enc_len, cudaMemcpyHostToDevice));

    {
        int threads = select_threads_per_block(block_size);
        decrypt_message_kernel<<<1, threads, shm_launch_bytes(threads)>>>(
        g_gpu_cache.d_key_dev, g_gpu_cache.d_in, g_gpu_cache.d_out,
        block_size, n_blocks, d_perms);
    }
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    uint8_t *padded = (uint8_t*)malloc(enc_len);
    CUDA_CHECK(cudaMemcpy(padded, g_gpu_cache.d_out, enc_len, cudaMemcpyDeviceToHost));

    uint8_t *result = wbc1_unpad(padded, enc_len, block_size, dec_len_out);
    free(padded);
    return result;
}

static uint8_t *cuda_cascade_encrypt_double(
    const uint8_t *key, const uint8_t *data, size_t data_len,
    int block_size, size_t *enc_len_out)
{
    build_perm_table_cpu(block_size);

    size_t padded_len;
    uint8_t *padded = wbc1_pad(data, data_len, block_size, &padded_len);
    int n_blocks = (int)(padded_len / block_size);

    gpu_cache_reserve(padded_len);
    gpu_cache_set_key(key);

    CUDA_CHECK(cudaMemcpy(g_gpu_cache.d_in, padded, padded_len, cudaMemcpyHostToDevice));
    free(padded);

    {
        int threads = select_threads_per_block(block_size);
        encrypt_double_kernel<<<1, threads, shm_launch_bytes(threads)>>>(
            g_gpu_cache.d_key_dev, g_gpu_cache.d_in, g_gpu_cache.d_out,
            block_size, n_blocks, d_perms);
    }
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    uint8_t *result = (uint8_t*)malloc(padded_len);
    CUDA_CHECK(cudaMemcpy(result, g_gpu_cache.d_out, padded_len, cudaMemcpyDeviceToHost));
    *enc_len_out = padded_len;
    return result;
}

static uint8_t *cuda_cascade_decrypt_double(
    const uint8_t *key, const uint8_t *enc_data, size_t enc_len,
    int block_size, size_t *dec_len_out)
{
    build_perm_table_cpu(block_size);

    int n_blocks = (int)(enc_len / block_size);

    gpu_cache_reserve(enc_len);
    gpu_cache_set_key(key);

    CUDA_CHECK(cudaMemcpy(g_gpu_cache.d_in, enc_data, enc_len, cudaMemcpyHostToDevice));

    {
        int threads = select_threads_per_block(block_size);
        decrypt_double_kernel<<<1, threads, shm_launch_bytes(threads)>>>(
            g_gpu_cache.d_key_dev, g_gpu_cache.d_in, g_gpu_cache.d_out,
            block_size, n_blocks, d_perms);
    }
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    uint8_t *padded = (uint8_t*)malloc(enc_len);
    CUDA_CHECK(cudaMemcpy(padded, g_gpu_cache.d_out, enc_len, cudaMemcpyDeviceToHost));
    uint8_t *result = wbc1_unpad(padded, enc_len, block_size, dec_len_out);
    free(padded);
    return result;
}

/* ============================================================================
 * CPU REFERENCE (same as wbc1_cascade_new.c for comparison)
 * ============================================================================ */

static uint8_t cpu_rotate_right(uint8_t b,int n){n&=7;return(uint8_t)((b>>n)|(b<<(8-n)));}
static uint8_t cpu_rotate_left (uint8_t b,int n){n&=7;return(uint8_t)((b<<n)|(b>>(8-n)));}

static void cpu_mix_cube(uint8_t *data,int n){ for(int i=1;i<n;i++) data[i]^=data[i-1]; }
static void cpu_inv_mix_cube(uint8_t *data,int n){ for(int i=n-1;i>=1;i--) data[i]^=data[i-1]; }

static void cpu_apply_op(uint8_t *cube_data, int bs, int op_id, int inv){
    int idx=((op_id%NUM_OPS)+NUM_OPS)%NUM_OPS;
    const uint16_t *perm=inv?h_perms+(size_t)(idx+NUM_OPS)*bs:h_perms+(size_t)idx*bs;
    uint8_t tmp[MAX_BLOCK];
    for(int i=0;i<bs;i++) tmp[i]=cube_data[perm[i]];
    memcpy(cube_data,tmp,(size_t)bs);
}

static void cpu_derive_cascade_key(const uint8_t *enc_block,int block_bytes,uint8_t new_rk[KEY_SIZE]){
    uint8_t S[64]={0};
    for(int j=0;j<block_bytes;j++) S[j&63]^=enc_block[j];
    for(int r=0;r<4;r++){
        uint8_t c=(uint8_t)(S[63]^(uint8_t)r);
        for(int i=0;i<64;i++){c=(uint8_t)(S[i]+cpu_rotate_left(c,5)+(uint8_t)(67*i+29*r));S[i]=c;}
        c=(uint8_t)(S[0]^(uint8_t)(r*37));
        for(int i=63;i>=0;i--){c=S[i]^cpu_rotate_right(c,3);S[i]=c;}
    }
    memcpy(new_rk,S,KEY_SIZE);
}

static void cpu_encrypt_block(const uint8_t *key_mat,const uint8_t *block,int bs,uint8_t *out){
    uint8_t rk[ROUNDS][MAX_BLOCK];
    for(int r=0;r<ROUNDS;r++){
        int shift=r&7;
        for(int i=0;i<bs;i++) rk[r][i]=cpu_rotate_left(key_mat[(i+r*7)%KEY_SIZE],shift);
    }
    uint8_t cube[MAX_BLOCK]; memcpy(cube,block,(size_t)bs);
    for(int r=0;r<ROUNDS;r++){
        int op_id=(int)(key_mat[r]%NUM_OPS);
        cpu_apply_op(cube,bs,op_id,0);
        cpu_mix_cube(cube,bs);
        for(int i=0;i<bs;i++) cube[i]^=rk[r][i];
        for(int i=0;i<bs;i++) cube[i]=cpu_rotate_right(cube[i],op_id&7);
    }
    memcpy(out,cube,(size_t)bs);
}

static void cpu_decrypt_block(const uint8_t *key_mat,const uint8_t *block,int bs,uint8_t *out){
    uint8_t rk[ROUNDS][MAX_BLOCK];
    for(int r=0;r<ROUNDS;r++){
        int shift=r&7;
        for(int i=0;i<bs;i++) rk[r][i]=cpu_rotate_left(key_mat[(i+r*7)%KEY_SIZE],shift);
    }
    uint8_t cube[MAX_BLOCK]; memcpy(cube,block,(size_t)bs);
    for(int r=ROUNDS-1;r>=0;r--){
        int op_id=(int)(key_mat[r]%NUM_OPS);
        for(int i=0;i<bs;i++) cube[i]=cpu_rotate_left(cube[i],op_id&7);
        for(int i=0;i<bs;i++) cube[i]^=rk[r][i];
        cpu_inv_mix_cube(cube,bs);
        cpu_apply_op(cube,bs,op_id,1);
    }
    memcpy(out,cube,(size_t)bs);
}

static __attribute__((unused)) uint8_t *cpu_cascade_encrypt(const uint8_t *key,const uint8_t *data,size_t data_len,
                                     int block_size,size_t *enc_len){
    build_perm_table_cpu(block_size);
    size_t padded_len;
    uint8_t *padded=wbc1_pad(data,data_len,block_size,&padded_len);
    uint8_t *out=(uint8_t*)malloc(padded_len);
    int n_blocks=(int)(padded_len/block_size);
    uint8_t ckey[KEY_SIZE]; memcpy(ckey,key,KEY_SIZE);
    for(int b=0;b<n_blocks;b++){
        cpu_encrypt_block(ckey,padded+(size_t)b*block_size,block_size,out+(size_t)b*block_size);
        if(b<n_blocks-1) cpu_derive_cascade_key(out+(size_t)b*block_size,block_size,ckey);
    }
    free(padded);
    *enc_len=padded_len;
    return out;
}

static __attribute__((unused)) uint8_t *cpu_cascade_decrypt(const uint8_t *key,const uint8_t *enc,size_t enc_len,
                                     int block_size,size_t *dec_len){
    build_perm_table_cpu(block_size);
    uint8_t *out=(uint8_t*)malloc(enc_len);
    int n_blocks=(int)(enc_len/block_size);
    uint8_t ckey[KEY_SIZE]; memcpy(ckey,key,KEY_SIZE);
    for(int b=0;b<n_blocks;b++){
        cpu_decrypt_block(ckey,enc+(size_t)b*block_size,block_size,out+(size_t)b*block_size);
        if(b<n_blocks-1) cpu_derive_cascade_key(enc+(size_t)b*block_size,block_size,ckey);
    }
    return wbc1_unpad(out,enc_len,block_size,dec_len);
}

static uint8_t *cpu_cascade_encrypt_double(const uint8_t *key,const uint8_t *data,size_t data_len,
                                            int block_size,size_t *enc_len){
    build_perm_table_cpu(block_size);
    size_t padded_len;
    uint8_t *padded=wbc1_pad(data,data_len,block_size,&padded_len);
    int n_blocks=(int)(padded_len/block_size);
    uint8_t *inter=(uint8_t*)malloc(padded_len);
    uint8_t *out=(uint8_t*)malloc(padded_len);
    uint8_t ckey[KEY_SIZE]; memcpy(ckey,key,KEY_SIZE);

    for(int b=0;b<n_blocks;b++){
        cpu_encrypt_block(ckey,padded+(size_t)b*block_size,block_size,inter+(size_t)b*block_size);
        if(b<n_blocks-1) cpu_derive_cascade_key(inter+(size_t)b*block_size,block_size,ckey);
    }

    uint8_t rk_bwd[KEY_SIZE]; memcpy(rk_bwd,key,KEY_SIZE);
    cpu_derive_cascade_key(rk_bwd, KEY_SIZE, rk_bwd);
    for(int b=n_blocks-1;b>=0;b--){
        cpu_encrypt_block(rk_bwd,inter+(size_t)b*block_size,block_size,out+(size_t)b*block_size);
        cpu_derive_cascade_key(out+(size_t)b*block_size,block_size,rk_bwd);
    }

    free(inter);
    free(padded);
    *enc_len=padded_len;
    return out;
}

static uint8_t *cpu_cascade_decrypt_double(const uint8_t *key,const uint8_t *enc,size_t enc_len,
                                            int block_size,size_t *dec_len){
    build_perm_table_cpu(block_size);
    int n_blocks=(int)(enc_len/block_size);
    uint8_t *inter=(uint8_t*)malloc(enc_len);
    uint8_t *out=(uint8_t*)malloc(enc_len);

    uint8_t rk_bwd[KEY_SIZE]; memcpy(rk_bwd,key,KEY_SIZE);
    cpu_derive_cascade_key(rk_bwd, KEY_SIZE, rk_bwd);
    for(int b=n_blocks-1;b>=0;b--){
        cpu_decrypt_block(rk_bwd,enc+(size_t)b*block_size,block_size,inter+(size_t)b*block_size);
        cpu_derive_cascade_key(enc+(size_t)b*block_size,block_size,rk_bwd);
    }

    uint8_t ckey[KEY_SIZE]; memcpy(ckey,key,KEY_SIZE);
    for(int b=0;b<n_blocks;b++){
        cpu_decrypt_block(ckey,inter+(size_t)b*block_size,block_size,out+(size_t)b*block_size);
        if(b<n_blocks-1) cpu_derive_cascade_key(inter+(size_t)b*block_size,block_size,ckey);
    }

    free(inter);
    return wbc1_unpad(out,enc_len,block_size,dec_len);
}

/* ============================================================================
 * STATISTICAL ANALYSIS
 * ============================================================================ */

static double stat_entropy(const uint8_t *d, size_t n){
    if(!n) return 0.0;
    size_t freq[256]={0};
    for(size_t i=0;i<n;i++) freq[d[i]]++;
    double h=0.0;
    for(int i=0;i<256;i++){
        if(freq[i]){double p=(double)freq[i]/(double)n; h-=p*log2(p);}
    }
    return h;
}

static double stat_chi_square(const uint8_t *d, size_t n){
    if(!n) return 0.0;
    size_t freq[256]={0};
    for(size_t i=0;i<n;i++) freq[d[i]]++;
    double ex=(double)n/256.0, chi=0.0;
    for(int i=0;i<256;i++){double dv=(double)freq[i]-ex; chi+=dv*dv/ex;}
    return chi;
}

static double stat_correlation(const uint8_t *x, const uint8_t *y, size_t n){
    if(!n) return 0.0;
    double mx=0.0, my=0.0;
    for(size_t i=0;i<n;i++){mx+=x[i]; my+=y[i];}
    mx/=(double)n; my/=(double)n;
    double cov=0.0, vx=0.0, vy=0.0;
    for(size_t i=0;i<n;i++){
        double a=x[i]-mx, b=y[i]-my;
        cov+=a*b; vx+=a*a; vy+=b*b;
    }
    return (vx==0.0||vy==0.0)?0.0:cov/(sqrt(vx)*sqrt(vy));
}

static void print_statistics(const uint8_t *plain, size_t plen,
                              const uint8_t *cipher, size_t clen){
    size_t cmp = plen < clen ? plen : clen;
    int reps = 0;
    for(size_t i=1; i<clen; i++) if(cipher[i]==cipher[i-1]) reps++;
    printf("\n  ── Statistical Tests ────────────────────────────────────────\n");
    printf("  Shannon entropy (plain):    %.4f bits/byte\n", stat_entropy(plain,plen));
    printf("  Shannon entropy (cipher):   %.4f bits/byte  (ideal: 8.0)\n", stat_entropy(cipher,clen));
    printf("  Chi-square (ciphertext):    %.2f         (ideal: ~256)\n", stat_chi_square(cipher,clen));
    printf("  Correlation plain<->cipher: %+.4f             (ideal: ~0)\n", stat_correlation(plain,cipher,cmp));
    printf("  Adjacent byte repeats:      %d\n", reps);
}

/* Plaintext avalanche: flip each bit of plaintext, re-encrypt, count bit diffs */
static void avalanche_plaintext(const uint8_t key[KEY_SIZE],
                                 const uint8_t *data, size_t dlen, int bsz){
    build_op_table(key);
    h_perm_bs = -1;
    size_t enc_len0 = 0;
    uint8_t *enc0 = cpu_cascade_encrypt_double(key, data, dlen, bsz, &enc_len0);

    long long total_flips = 0;
    size_t flip_bits = dlen * 8;
    uint8_t *mod = (uint8_t*)malloc(dlen);

    for(size_t i = 0; i < flip_bits; i++){
        memcpy(mod, data, dlen);
        mod[i/8] ^= (uint8_t)(1u << (i%8));
        size_t enc_len1 = 0;
        h_perm_bs = -1;
        uint8_t *enc1 = cpu_cascade_encrypt_double(key, mod, dlen, bsz, &enc_len1);
        if(enc_len1 == enc_len0)
            for(size_t j=0; j<enc_len0; j++)
                total_flips += __builtin_popcount(enc0[j] ^ enc1[j]);
        free(enc1);
    }
    free(mod); free(enc0);

    double ratio = (flip_bits > 0 && enc_len0 > 0) ?
        (double)total_flips / ((double)flip_bits * (double)enc_len0 * 8.0) : 0.0;
    printf("  Avalanche (plaintext):      %.2f%%  (ideal: ~50%%)\n", ratio*100.0);
}

/* Key avalanche: flip each key bit, re-encrypt same plaintext, count bit diffs */
static void avalanche_key(const uint8_t key[KEY_SIZE],
                           const uint8_t *data, size_t dlen, int bsz){
    build_op_table(key);
    h_perm_bs = -1;
    size_t enc_len0 = 0;
    uint8_t *enc0 = cpu_cascade_encrypt_double(key, data, dlen, bsz, &enc_len0);

    long long total_flips = 0;

    for(int i = 0; i < KEY_SIZE*8; i++){
        uint8_t mod_key[KEY_SIZE]; memcpy(mod_key, key, KEY_SIZE);
        mod_key[i/8] ^= (uint8_t)(1u << (i%8));
        build_op_table(mod_key);
        h_perm_bs = -1;
        size_t enc_len1 = 0;
        uint8_t *enc1 = cpu_cascade_encrypt_double(mod_key, data, dlen, bsz, &enc_len1);
        if(enc_len1 == enc_len0)
            for(size_t j=0; j<enc_len0; j++)
                total_flips += __builtin_popcount(enc0[j] ^ enc1[j]);
        free(enc1);
    }
    free(enc0);

    /* Restore original key */
    build_op_table(key);
    h_perm_bs = -1;
    build_perm_table_cpu(bsz);

    double ratio = (KEY_SIZE*8 > 0 && enc_len0 > 0) ?
        (double)total_flips / ((double)(KEY_SIZE*8) * (double)enc_len0 * 8.0) : 0.0;
    printf("  Avalanche (key):            %.2f%%  (ideal: ~50%%)\n", ratio*100.0);
}

static int run_statistical_analysis(const uint8_t key[KEY_SIZE], int double_pass){
    /* 1000 bytes for statistics, 256 bytes for avalanche (2048 bit flips) */
    const int STAT_SZ  = 1000;
    const int AVLP_SZ  = 256;
    int bsz_stat = auto_block_size(STAT_SZ);
    int bsz_avlp = auto_block_size(AVLP_SZ);

    uint8_t *plain_stat = (uint8_t*)malloc((size_t)STAT_SZ);
    uint8_t *plain_avlp = (uint8_t*)malloc((size_t)AVLP_SZ);
    RAND_bytes(plain_stat, STAT_SZ);
    RAND_bytes(plain_avlp, AVLP_SZ);

    printf("\n  Statistical Analysis  (%s)\n",
           double_pass ? "CPU double-cascade encrypt, random key"
                       : "CPU single-cascade encrypt, random key");
    printf("  ─────────────────────────────────────────────────────────────\n");

    /* Statistics on 1000-byte ciphertext */
    build_op_table(key);
    h_perm_bs = -1;
    size_t enc_len = 0;
    uint8_t *enc = double_pass
        ? cpu_cascade_encrypt_double(key, plain_stat, (size_t)STAT_SZ, bsz_stat, &enc_len)
        : cpu_cascade_encrypt(key, plain_stat, (size_t)STAT_SZ, bsz_stat, &enc_len);
    print_statistics(plain_stat, (size_t)STAT_SZ, enc, enc_len);
    free(enc);

    /* Avalanche (256 bytes: 2048 bit flips for plaintext, 256 for key) */
    printf("\n  ── Avalanche Effect  (message size: %d B) ───────────────────\n", AVLP_SZ);
    avalanche_plaintext(key, plain_avlp, (size_t)AVLP_SZ, bsz_avlp);
    avalanche_key(key, plain_avlp, (size_t)AVLP_SZ, bsz_avlp);

    free(plain_stat); free(plain_avlp);
    return 0;
}

/* ============================================================================
 * SELF-TEST
 * ============================================================================ */

static int self_test(const uint8_t key[KEY_SIZE], int double_pass){
    printf("\n  Self-tests (%s)\n", double_pass
           ? (g_has_cuda ? "GPU double-cascade encrypt -> GPU double-cascade decrypt" : "CPU double-cascade encrypt -> CPU double-cascade decrypt")
           : (g_has_cuda ? "GPU single-cascade encrypt -> GPU single-cascade decrypt" : "CPU single-cascade encrypt -> CPU single-cascade decrypt"));
    int pass=0,fail=0;
    static const int sizes[]={8,27,64,125,1000,4096,10000,100000};
    int ns=(int)(sizeof(sizes)/sizeof(sizes[0]));
    for(int si=0;si<ns;si++){
        int sz=sizes[si];
        uint8_t *plain=(uint8_t*)malloc((size_t)sz);
        RAND_bytes(plain,sz);
        int bsz=auto_block_size(sz);
        build_op_table(key);
        size_t enc_len=0,dec_len=0;
        uint8_t *enc = g_has_cuda
            ? (double_pass ? cuda_cascade_encrypt_double(key,plain,(size_t)sz,bsz,&enc_len)
                           : cuda_cascade_encrypt(key,plain,(size_t)sz,bsz,&enc_len))
            : (double_pass ? cpu_cascade_encrypt_double(key,plain,(size_t)sz,bsz,&enc_len)
                           : cpu_cascade_encrypt(key,plain,(size_t)sz,bsz,&enc_len));
        uint8_t *dec = g_has_cuda
            ? (double_pass ? cuda_cascade_decrypt_double(key,enc,enc_len,bsz,&dec_len)
                           : cuda_cascade_decrypt(key,enc,enc_len,bsz,&dec_len))
            : (double_pass ? cpu_cascade_decrypt_double(key,enc,enc_len,bsz,&dec_len)
                           : cpu_cascade_decrypt(key,enc,enc_len,bsz,&dec_len));
        int ok=(dec&&dec_len==(size_t)sz&&memcmp(dec,plain,sz)==0);
        printf("  [%s] sz=%6d  block=%4d  enc_len=%6zu  dec_len=%6zu\n",
               ok?"PASS":"FAIL",sz,bsz,enc_len,dec_len);
        if(ok)pass++; else fail++;
        free(plain);free(enc);free(dec);
    }
    printf("  Result: %d/%d PASS\n",pass,pass+fail);
    return fail==0?0:1;
}

/* ============================================================================
 * BENCHMARK  (GPU vs CPU, same format as wbc1_cascade_new.c)
 * ============================================================================ */

static int cmp_d(const void *a,const void *b){
    double da=*(const double*)a,db=*(const double*)b;
    return(da>db)-(da<db);
}
static double trimmed_mean_d(double *t,int n){
    if(n<5){double s=0;for(int i=0;i<n;i++)s+=t[i];return s/n;}
    double tmp[64];memcpy(tmp,t,(size_t)n*sizeof(double));
    qsort(tmp,(size_t)n,sizeof(double),cmp_d);
    int cut=(n>=15)?2:1,start=cut,end=n-cut;
    if(end<=start){double s=0;for(int i=0;i<n;i++)s+=t[i];return s/n;}
    double s=0;for(int i=start;i<end;i++)s+=tmp[i];return s/(end-start);
}

static int load_benchmark_sizes(int *sizes, int max_sizes){
    static const int defaults[]={1,10,100,1000,10000,100000,1000000,10000000};
    const char *bytes_env = getenv("WBC_CUDA_BENCH_ONE_SIZE_BYTES");
    const char *mb_env = getenv("WBC_CUDA_BENCH_ONE_SIZE_MB");

    if(bytes_env && *bytes_env){
        long long v = atoll(bytes_env);
        if(v > 0 && v <= 2147483647LL){
            sizes[0] = (int)v;
            return 1;
        }
    }
    if(mb_env && *mb_env){
        long long v = atoll(mb_env);
        long long bytes = v * 1024LL * 1024LL;
        if(v > 0 && bytes <= 2147483647LL){
            sizes[0] = (int)bytes;
            return 1;
        }
    }

    for(int i = 0; i < max_sizes && i < (int)(sizeof(defaults)/sizeof(defaults[0])); i++)
        sizes[i] = defaults[i];
    return (int)(sizeof(defaults)/sizeof(defaults[0]));
}

/* Query the maximum number of CUDA blocks that can run concurrently on the
 * whole device (all SMs) for the encrypt+decrypt kernel pair with the given
 * cipher block_size.  Returns 1 on any error so callers are always safe. */
static int query_device_concurrent_blocks(int cipher_block_size){
    int threads = select_threads_per_block(cipher_block_size);
    size_t shm   = shm_launch_bytes(threads);

    int enc_per_sm = 0, dec_per_sm = 0;
    if(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
            &enc_per_sm, encrypt_message_kernel, threads, shm) != cudaSuccess)
        return 1;
    if(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
            &dec_per_sm, decrypt_message_kernel, threads, shm) != cudaSuccess)
        return 1;

    /* For cascade-sequential kernels the useful concurrency is 1 block per SM:
     * running more causes L1/SHM pressure without throughput gain since the
     * inner cipher-block loop is strictly sequential (key cascade dependency).
     * We use per_sm only to sanity-check the kernel fits on the device. */
    int per_sm = (enc_per_sm < dec_per_sm) ? enc_per_sm : dec_per_sm;
    if(per_sm < 1) return 1; /* kernel doesn't fit — caller will use batch=1 */

    cudaDeviceProp prop;
    int dev = 0;
    cudaGetDevice(&dev);
    if(cudaGetDeviceProperties(&prop, dev) != cudaSuccess) return 1;

    /* Target: exactly 1 block per SM so every SM is busy in one wave. */
    return prop.multiProcessorCount;
}

/* Adaptive benchmark policy is opt-in via WBC_CUDA_BENCH_ADAPTIVE=1.
 * Default policy remains fixed for fast, comparable benchmark runs. */
static int benchmark_adaptive_enabled(void){
    const char *env = getenv("WBC_CUDA_BENCH_ADAPTIVE");
    return (env && atoi(env) != 0) ? 1 : 0;
}

/* Total benchmark work (cluster-wide, before split across ranks).
 * Override with WBC_CUDA_BENCH_TOTAL_MB. */
static size_t benchmark_target_total_bytes(size_t msg_sz){
    const char *env_total_mb = getenv("WBC_CUDA_BENCH_TOTAL_MB");
    if(env_total_mb){
        int mb = atoi(env_total_mb);
        if(mb >= 64) return (size_t)mb * 1024u * 1024u;
    }

    if(!benchmark_adaptive_enabled()){
        (void)msg_sz;
        return 256u * 1024u * 1024u;
    }

    /* Keep tiny/medium sizes fast, but increase work for large messages so
     * MPI/CUDA overhead does not dominate the timing. */
    if(msg_sz >= (size_t)(4u * 1024u * 1024u)) return 1024u * 1024u * 1024u; /* 1 GB */
    if(msg_sz >= (size_t)(1u * 1024u * 1024u)) return 512u * 1024u * 1024u;  /* 512 MB */
    return 256u * 1024u * 1024u;                                              /* 256 MB */
}

/* Minimum benchmark messages per rank for large message sizes.
 * Override with WBC_CUDA_BENCH_MIN_MSGS_PER_RANK. */
static size_t benchmark_min_msgs_per_rank(size_t msg_sz){
    const char *env_min_msgs = getenv("WBC_CUDA_BENCH_MIN_MSGS_PER_RANK");
    if(env_min_msgs){
        int v = atoi(env_min_msgs);
        if(v >= 1) return (size_t)v;
    }

    if(!benchmark_adaptive_enabled()){
        (void)msg_sz;
        return 1;
    }

    if(msg_sz >= (size_t)(4u * 1024u * 1024u)) return 16; /* >=4 MB */
    if(msg_sz >= (size_t)(1u * 1024u * 1024u)) return 8;  /* >=1 MB */
    return 1;
}

/* Compute per-rank batch so that:
 *   (a) total cluster work is adaptive by message size (split evenly)
 *   (b) at least one full scheduling wave on the GPU (occupancy floor) so the
 *       GPU is never starved — this is the key fix for large-message slowdown
 *   (c) device memory for 3 buffers stays within VRAM_BUDGET
 *   (d) host memory for 4 arrays stays within HOST_BUDGET
 * No hard cap — limits come from actual hardware budgets. */
static int auto_bench_batch_msgs(size_t padded_len, size_t msg_sz,
                                  int world_size, int cipher_block_size){
    const char *env = getenv("WBC_CUDA_BENCH_BATCH");
    if(env){ int v = atoi(env); if(v >= 1) return v; }

    /* (a) cluster-wide sizing */
    const size_t target_total = benchmark_target_total_bytes(msg_sz);
    size_t total_msgs = (target_total + padded_len - 1) / padded_len;
    if(total_msgs < (size_t)world_size) total_msgs = (size_t)world_size;
    size_t batch = (total_msgs + (size_t)world_size - 1) / (size_t)world_size;

    /* Keep enough independent messages per rank for large sizes so timing is
     * less sensitive to launch/barrier jitter and better reflects GPU scaling. */
    {
        size_t min_msgs = benchmark_min_msgs_per_rank(msg_sz);
        if(batch < min_msgs) batch = min_msgs;
    }

    /* (b) occupancy floor: ensure at least one full GPU wave per rank.
     * Use occupancy API unless manually overridden with WBC_CUDA_MIN_BLOCKS. */
    size_t min_blocks;
    {
        const char *env_min = getenv("WBC_CUDA_MIN_BLOCKS");
        if(env_min && atoi(env_min) >= 1)
            min_blocks = (size_t)atoi(env_min);
        else
            min_blocks = (size_t)query_device_concurrent_blocks(cipher_block_size);
    }
    if(batch < min_blocks) batch = min_blocks;

    /* (c) VRAM budget: d_in + d_out (padded_len each) + d_key (KEY_SIZE each).
     * Use half of actually free VRAM to leave headroom for tables/stack. */
    {
        size_t vram_free = 0, vram_total = 0;
        size_t vram_budget;
        if(cudaMemGetInfo(&vram_free, &vram_total) == cudaSuccess && vram_free > 0)
            vram_budget = vram_free / 2;
        else
            vram_budget = 4UL * 1024 * 1024 * 1024; /* fallback 4 GB */
        size_t per_dev = 2 * padded_len + KEY_SIZE;
        size_t vram_cap = vram_budget / per_dev;
        if(batch > vram_cap) batch = vram_cap;
    }

    /* (d) host RAM budget: plain + padded + enc + dec.
     * Use half of free physical pages to leave headroom for OS/other ranks. */
    {
        size_t host_budget;
        long pages   = sysconf(_SC_AVPHYS_PAGES);
        long page_sz = sysconf(_SC_PAGE_SIZE);
        if(pages > 0 && page_sz > 0)
            host_budget = (size_t)pages * (size_t)page_sz / 2;
        else
            host_budget = 4UL * 1024 * 1024 * 1024; /* fallback 4 GB */
        size_t per_host = msg_sz + 3 * padded_len;
        if(per_host < 1) per_host = 1;
        size_t host_cap = host_budget / per_host;
        if(batch > host_cap) batch = host_cap;
    }

    /* Hard upper bound for tiny-message cases (1..100 bytes).
     * Interpret as TOTAL cap across all ranks so strong scaling is preserved.
     * Can be overridden with WBC_CUDA_BENCH_BATCH_MAX. */
    {
        size_t total_batch_max = 65536;
        const char *env_max = getenv("WBC_CUDA_BENCH_BATCH_MAX");
        if(env_max){
            int v = atoi(env_max);
            if(v >= 1) total_batch_max = (size_t)v;
        }
        size_t batch_max = (total_batch_max + (size_t)world_size - 1) / (size_t)world_size;
        if(batch_max < 1) batch_max = 1;
        if(batch > batch_max) batch = batch_max;
    }

    if(batch < 1) batch = 1;
    return (int)batch;
}

static int run_batched_gpu_roundtrip(const uint8_t key[KEY_SIZE],
                                     const uint8_t *key_batch,
                                     const uint8_t *plain_batch,
                                     uint8_t *padded_batch,
                                     uint8_t *enc_batch,
                                     uint8_t *dec_batch,
                                     int msg_count,
                                     size_t msg_len,
                                     int block_size,
                                     uint8_t *d_key_batch,
                                     uint8_t *d_in_batch,
                                     uint8_t *d_out_batch,
                                     size_t padded_len,
                                     int double_pass)
{
    const int n_blocks = (int)(padded_len / (size_t)block_size);
    const int threads = select_threads_per_block(block_size);
    const size_t total_plain = (size_t)msg_count * msg_len;
    const size_t total_padded = (size_t)msg_count * padded_len;

    RAND_bytes((unsigned char*)plain_batch, (int)total_plain);
    for(int msg = 0; msg < msg_count; msg++){
        wbc1_pad_into(padded_batch + (size_t)msg * padded_len,
                      plain_batch + (size_t)msg * msg_len,
                      msg_len, block_size);
    }

    (void)key;
    CUDA_CHECK(cudaMemcpy(d_key_batch, key_batch,
                          (size_t)msg_count * KEY_SIZE, cudaMemcpyHostToDevice));

    CUDA_CHECK(cudaMemcpy(d_in_batch, padded_batch, total_padded, cudaMemcpyHostToDevice));
    if(double_pass)
        encrypt_double_kernel<<<msg_count, threads, shm_launch_bytes(threads)>>> (
            d_key_batch, d_in_batch, d_out_batch, block_size, n_blocks, d_perms);
    else
        encrypt_message_kernel<<<msg_count, threads, shm_launch_bytes(threads)>>> (
            d_key_batch, d_in_batch, d_out_batch, block_size, n_blocks, d_perms);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(enc_batch, d_out_batch, total_padded, cudaMemcpyDeviceToHost));

    CUDA_CHECK(cudaMemcpy(d_in_batch, enc_batch, total_padded, cudaMemcpyHostToDevice));
    if(double_pass)
        decrypt_double_kernel<<<msg_count, threads, shm_launch_bytes(threads)>>> (
            d_key_batch, d_in_batch, d_out_batch, block_size, n_blocks, d_perms);
    else
        decrypt_message_kernel<<<msg_count, threads, shm_launch_bytes(threads)>>> (
            d_key_batch, d_in_batch, d_out_batch, block_size, n_blocks, d_perms);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(dec_batch, d_out_batch, total_padded, cudaMemcpyDeviceToHost));

    return memcmp(dec_batch, padded_batch, total_padded) == 0;
}

static void benchmark(const uint8_t key[KEY_SIZE], int double_pass){
    int world_rank = 0;
    int world_size = 1;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    if(!g_has_cuda){
        if(world_rank == 0) printf("\nGPU benchmark skipped: CUDA device is unavailable\n\n");
        return;
    }

    int sizes[8]={0};
    int ns=load_benchmark_sizes(sizes, 8);
    int repeats=10;

    const char *env=getenv("WBC_CUDA_BENCH_REPEATS");
    if(env){int v=atoi(env);if(v>=3&&v<=32)repeats=v;}

    build_op_table(key);

    if(world_rank == 0){
        const int adaptive = benchmark_adaptive_enabled();
        printf("\nPerformance Benchmark / Бенчмарк производительности (GPU, %s):\n", double_pass ? "double-cascade" : "single-cascade");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("  %10s  %10s  %14s  %14s  %12s  %12s  %14s  %14s  %s\n",
            "Size (KB)", "Enc (s)", "Enc (KB/s)", "Dec (KB/s)",
            "Enc (MB/s)", "Dec (MB/s)", "Enc (Mbit/s)", "Dec (Mbit/s)", "Integrity");
        printf("  %s\n","-----------------------------------------------------------------------------------------------------------------------");
        printf("  Timing mode: MPI_MAX across ranks (time decreases with more GPUs)\n");
        if(adaptive)
            printf("  Workload: adaptive total (256/512/1024 MB by message size) split across %d ranks\n", world_size);
        else
            printf("  Workload: fixed 256 MB total split equally across %d ranks (~%d MB/rank)\n",
                   world_size, (int)(256 / world_size));
        printf("            override: WBC_CUDA_BENCH_TOTAL_MB=<MB>\n");
        if(adaptive)
            printf("  Minimum msgs/rank for large sizes: auto (>=1MB: 8, >=4MB: 16)\n");
        else
            printf("  Minimum msgs/rank for large sizes: 1 (adaptive disabled)\n");
        printf("            override: WBC_CUDA_BENCH_MIN_MSGS_PER_RANK=<N>\n");
        printf("            adaptive toggle: WBC_CUDA_BENCH_ADAPTIVE=1\n");
        printf("  Throughput: aggregate = total_msgs_all_ranks * msg_size / max_rank_time\n");
         printf("  Scaling mode: fixed total work (set WBC_CUDA_MIN_BLOCKS>1 for stress mode)\n");
        printf("  Size column: logical size of one message\n");
        printf("  MPI ranks: %d\n", world_size);
        printf("  Repeats: %d  |  Aggregation: trimmed mean\n", repeats);
        if(ns == 1) printf("  Custom size override: %d bytes\n", sizes[0]);
    }

    for(int si=0;si<ns;si++){
        int sz=sizes[si];
        int bsz=auto_block_size(sz);
        int threads = select_threads_per_block(bsz);
        build_perm_table_cpu(bsz);
        size_t padded_len = wbc1_padded_len((size_t)sz, bsz);
        int batch_msgs = auto_bench_batch_msgs(padded_len, (size_t)sz, world_size, bsz);
        const int n_blocks_per_msg = (int)(padded_len / (size_t)bsz);
        const char *verbose_env = getenv("WBC_CUDA_BENCH_VERBOSE");
        size_t total_plain = (size_t)batch_msgs * (size_t)sz;
        size_t total_padded = (size_t)batch_msgs * padded_len;
        size_t total_key_bytes = (size_t)batch_msgs * KEY_SIZE;
        uint8_t *key_batch=(uint8_t*)malloc(total_key_bytes);
        uint8_t *plain_batch=(uint8_t*)malloc(total_plain);
        uint8_t *padded_batch=(uint8_t*)malloc(total_padded);
        uint8_t *enc_batch=(uint8_t*)malloc(total_padded);
        uint8_t *dec_batch=(uint8_t*)malloc(total_padded);
        uint8_t *d_key_batch=NULL, *d_in_batch=NULL, *d_out_batch=NULL;

        CUDA_CHECK(cudaMalloc(&d_key_batch, (size_t)batch_msgs * KEY_SIZE));
        CUDA_CHECK(cudaMalloc(&d_in_batch, total_padded));
        CUDA_CHECK(cudaMalloc(&d_out_batch, total_padded));

        if(world_rank == 0 && verbose_env && atoi(verbose_env) != 0){
            int occ_floor = query_device_concurrent_blocks(bsz);
            printf("  [dbg] size=%d B  block=%d  n_blocks/msg=%d  threads=%d  batch/rank=%d  occ_floor=%d  grid=%d\n",
                   sz, bsz, n_blocks_per_msg, threads, batch_msgs, occ_floor, batch_msgs);
        }

        for(int msg = 0; msg < batch_msgs; msg++)
            memcpy(key_batch + (size_t)msg * KEY_SIZE, key, KEY_SIZE);

        /* warmup */
        int warm_ok = 1;
        MPI_Barrier(MPI_COMM_WORLD);
        warm_ok = run_batched_gpu_roundtrip(key, key_batch, plain_batch, padded_batch, enc_batch, dec_batch,
                            batch_msgs, (size_t)sz, bsz,
                            d_key_batch, d_in_batch, d_out_batch, padded_len,
                            double_pass);
        MPI_Barrier(MPI_COMM_WORLD);

        double gpu_enc_t[32]={0};
        double gpu_dec_t[32]={0};
        int gpu_ok=warm_ok;

        RAND_bytes((unsigned char*)plain_batch, (int)total_plain);
        for(int msg = 0; msg < batch_msgs; msg++){
            wbc1_pad_into(padded_batch + (size_t)msg * padded_len,
                          plain_batch + (size_t)msg * (size_t)sz,
                          (size_t)sz, bsz);
        }
        CUDA_CHECK(cudaMemcpy(d_key_batch, key_batch, total_key_bytes, cudaMemcpyHostToDevice));

        for(int r=0;r<repeats;r++){
            struct timespec t0,t1;
            double enc_local = 0.0, enc_iter = 0.0;
            double dec_local = 0.0, dec_iter = 0.0;
            int iter_ok = 1;

            MPI_Barrier(MPI_COMM_WORLD);
            clock_gettime(CLOCK_MONOTONIC,&t0);
            CUDA_CHECK(cudaMemcpy(d_in_batch, padded_batch, total_padded, cudaMemcpyHostToDevice));
            if(double_pass)
                encrypt_double_kernel<<<batch_msgs, threads, shm_launch_bytes(threads)>>> (
                    d_key_batch, d_in_batch, d_out_batch, bsz, n_blocks_per_msg, d_perms);
            else
                encrypt_message_kernel<<<batch_msgs, threads, shm_launch_bytes(threads)>>> (
                    d_key_batch, d_in_batch, d_out_batch, bsz, n_blocks_per_msg, d_perms);
            CUDA_CHECK(cudaGetLastError());
            CUDA_CHECK(cudaDeviceSynchronize());
            CUDA_CHECK(cudaMemcpy(enc_batch, d_out_batch, total_padded, cudaMemcpyDeviceToHost));
            clock_gettime(CLOCK_MONOTONIC,&t1);
            enc_local=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
            MPI_Reduce(&enc_local, &enc_iter, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
            if(world_rank == 0) gpu_enc_t[r]=enc_iter;

            MPI_Barrier(MPI_COMM_WORLD);
            clock_gettime(CLOCK_MONOTONIC,&t0);
            CUDA_CHECK(cudaMemcpy(d_in_batch, enc_batch, total_padded, cudaMemcpyHostToDevice));
            if(double_pass)
                decrypt_double_kernel<<<batch_msgs, threads, shm_launch_bytes(threads)>>> (
                    d_key_batch, d_in_batch, d_out_batch, bsz, n_blocks_per_msg, d_perms);
            else
                decrypt_message_kernel<<<batch_msgs, threads, shm_launch_bytes(threads)>>> (
                    d_key_batch, d_in_batch, d_out_batch, bsz, n_blocks_per_msg, d_perms);
            CUDA_CHECK(cudaGetLastError());
            CUDA_CHECK(cudaDeviceSynchronize());
            CUDA_CHECK(cudaMemcpy(dec_batch, d_out_batch, total_padded, cudaMemcpyDeviceToHost));
            clock_gettime(CLOCK_MONOTONIC,&t1);
            dec_local=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
            if(memcmp(dec_batch, padded_batch, total_padded)!=0) iter_ok=0;
            MPI_Reduce(&dec_local, &dec_iter, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
            MPI_Allreduce(MPI_IN_PLACE, &iter_ok, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
            if(world_rank == 0){
                gpu_dec_t[r]=dec_iter;
                if(!iter_ok) gpu_ok=0;
            }
        }

        if(world_rank == 0){
            double ge=trimmed_mean_d(gpu_enc_t,repeats);
            double gd=trimmed_mean_d(gpu_dec_t,repeats);
            double total_kbs = ((double)sz * (double)batch_msgs * (double)world_size)/1024.0;
            double total_mbs = ((double)sz * (double)batch_msgs * (double)world_size)/1e6;
            double size_kb_per_rank = (double)sz/1024.0;
            double gpu_enc_kbs = total_kbs/(ge>0?ge:1e-9);
            double gpu_dec_kbs = total_kbs/(gd>0?gd:1e-9);

            double gpu_enc_mbs = total_mbs/(ge>0?ge:1e-9);
            double gpu_dec_mbs = total_mbs/(gd>0?gd:1e-9);

            printf("  %10.2f  %10.5f  %14.2f  %14.2f  %12.4f  %12.4f  %14.4f  %14.4f  %s\n",
                size_kb_per_rank, ge, gpu_enc_kbs, gpu_dec_kbs,
                gpu_enc_mbs, gpu_dec_mbs, gpu_enc_mbs*8.0, gpu_dec_mbs*8.0,
                gpu_ok ? "OK" : "FAIL");
        }
        cudaFree(d_key_batch);
        cudaFree(d_in_batch);
        cudaFree(d_out_batch);
        free(key_batch);
        free(plain_batch);
        free(padded_batch);
        free(enc_batch);
        free(dec_batch);
    }
    if(world_rank == 0) printf("\n");
}

static void print_hex_preview(const uint8_t *data, size_t len, size_t max_bytes){
    size_t n = (len < max_bytes) ? len : max_bytes;
    for(size_t i=0;i<n;i++) printf("%02x", data[i]);
    if(len > n) printf("...");
    printf("\n");
}

static int run_encrypt_task(const uint8_t key[KEY_SIZE], int mode, int data_kb, const char *custom_text, int double_pass){
    uint8_t *plain = NULL;
    size_t plain_len = 0;

    if(custom_text && *custom_text){
        plain_len = strlen(custom_text);
        plain = (uint8_t*)malloc(plain_len);
        if(!plain) return 1;
        memcpy(plain, custom_text, plain_len);
    } else if(mode == 1){
        if(data_kb < 1) data_kb = 1;
        plain_len = (size_t)data_kb * 1024u;
        plain = (uint8_t*)malloc(plain_len);
        if(!plain) return 1;
        RAND_bytes(plain, (int)plain_len);
    } else {
        const char *demo = "WBC1-Cascade-CUDA CLI demo text. This run validates GPU encrypt/decrypt path with MPI-aware startup.";
        plain_len = strlen(demo);
        plain = (uint8_t*)malloc(plain_len);
        if(!plain) return 1;
        memcpy(plain, demo, plain_len);
    }

    int block_size = auto_block_size((int)plain_len);
    build_op_table(key);

    struct timespec t0,t1;
    size_t enc_len = 0, dec_len = 0;

    clock_gettime(CLOCK_MONOTONIC,&t0);
    uint8_t *enc = g_has_cuda
        ? (double_pass ? cuda_cascade_encrypt_double(key, plain, plain_len, block_size, &enc_len)
                       : cuda_cascade_encrypt(key, plain, plain_len, block_size, &enc_len))
        : (double_pass ? cpu_cascade_encrypt_double(key, plain, plain_len, block_size, &enc_len)
                       : cpu_cascade_encrypt(key, plain, plain_len, block_size, &enc_len));
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double enc_t = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    clock_gettime(CLOCK_MONOTONIC,&t0);
    uint8_t *dec = g_has_cuda
        ? (double_pass ? cuda_cascade_decrypt_double(key, enc, enc_len, block_size, &dec_len)
                       : cuda_cascade_decrypt(key, enc, enc_len, block_size, &dec_len))
        : (double_pass ? cpu_cascade_decrypt_double(key, enc, enc_len, block_size, &dec_len)
                       : cpu_cascade_decrypt(key, enc, enc_len, block_size, &dec_len));
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double dec_t = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    int ok = (dec && dec_len == plain_len && memcmp(dec, plain, plain_len) == 0);

    printf("\n  Encrypt Task (%s)\n", g_has_cuda ? "CUDA" : "CPU fallback");
    printf("  Mode: %s\n", mode == 1 ? "random" : "demo");
    printf("  Plain length: %zu bytes  |  Block size: %d\n", plain_len, block_size);
    printf("  Encrypted length: %zu bytes\n", enc_len);
    printf("  Cipher preview: ");
    if(enc) print_hex_preview(enc, enc_len, 64);
    else printf("(null)\n");
    printf("  Encrypt: %.6f s  |  %.2f KB/s\n", enc_t, (plain_len/1024.0)/(enc_t>0?enc_t:1e-9));
    printf("  Decrypt: %.6f s  |  %.2f KB/s\n", dec_t, (plain_len/1024.0)/(dec_t>0?dec_t:1e-9));
    printf("  Integrity: %s\n\n", ok ? "OK" : "FAIL");

    free(plain);
    free(enc);
    free(dec);
    return ok ? 0 : 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static int env_to_int(const char *name, int defv){
    const char *v = getenv(name);
    if (!v || !*v) return defv;
    return atoi(v);
}

static void print_device_info(int world_rank){
    int dev=0;
    CUDA_CHECK(cudaGetDevice(&dev));
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop,dev));
    printf("  [rank %d] GPU %d: %s  |  SM %d.%d  |  %.0f MHz  |  SHM %zu KB/block\n",
           world_rank, dev,
           prop.name, prop.major, prop.minor,
           prop.clockRate/1000.0,
           prop.sharedMemPerBlock/1024);
}

int main(int argc, char *argv[]){
    MPI_Init(&argc, &argv);
    int world_rank = 0, world_size = 1;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int dev_count = 0;
    cudaError_t dev_err = cudaGetDeviceCount(&dev_count);
    g_has_cuda = (dev_err == cudaSuccess && dev_count > 0);
    if (!g_has_cuda) {
        /* Clear sticky CUDA error to allow CPU-only fallback mode. */
        (void)cudaGetLastError();
    }

    if (g_has_cuda) {
        /* Rank-to-GPU mapping: local rank on node chooses device. */
        int local_rank = env_to_int("OMPI_COMM_WORLD_LOCAL_RANK", -1);
        if (local_rank < 0) local_rank = env_to_int("MV2_COMM_WORLD_LOCAL_RANK", -1);
        if (local_rank < 0) local_rank = env_to_int("SLURM_LOCALID", -1);
        if (local_rank < 0) local_rank = world_rank;
        int dev = local_rank % dev_count;
        CUDA_CHECK(cudaSetDevice(dev));
    }

    if (world_rank == 0) {
        printf("╔══════════════════════════════════════════╗\n");
        printf("║      WBC1-Cascade-CUDA + MPI             ║\n");
        printf("╚══════════════════════════════════════════╝\n");
        printf("  MPI ranks: %d\n", world_size);
    }
    MPI_Barrier(MPI_COMM_WORLD);
    if (g_has_cuda) {
        print_device_info(world_rank);
    } else if (world_rank == 0) {
        printf("  CUDA devices: not found, CPU fallback mode enabled\n");
    }
    MPI_Barrier(MPI_COMM_WORLD);

    uint8_t key[KEY_SIZE];
    if (world_rank == 0) RAND_bytes(key,KEY_SIZE);
    MPI_Bcast(key, KEY_SIZE, MPI_BYTE, 0, MPI_COMM_WORLD);

    int use_named_cli = 0;
    for(int i=1;i<argc;i++){
        if(strncmp(argv[i], "--", 2) == 0){
            use_named_cli = 1;
            break;
        }
    }

    if(use_named_cli){
        int task = -1;          /* 0=encrypt, 1=analysis, 3=benchmark */
        int mode = 0;           /* 0=demo, 1=random */
        int data_kb = 1;
        const char *custom_text = NULL;
        int double_pass = 1;

        for(int i=1;i<argc;i++){
            if(strcmp(argv[i], "--single") == 0 || strcmp(argv[i], "--once") == 0){
                double_pass = 0;
                continue;
            } else if(strcmp(argv[i], "--double") == 0){
                double_pass = 1;
                continue;
            }

            if(strcmp(argv[i], "--task-encrypt") == 0 || strcmp(argv[i], "--encrypt") == 0){
                task = 0;
            } else if(strcmp(argv[i], "--task-analysis") == 0 || strcmp(argv[i], "--analysis") == 0 ||
                      strcmp(argv[i], "--stats") == 0 || strcmp(argv[i], "--task-stats") == 0 ||
                      strcmp(argv[i], "--task-test") == 0 || strcmp(argv[i], "--test") == 0){
                task = 1;
            } else if(strcmp(argv[i], "--task-benchmark") == 0 || strcmp(argv[i], "--benchmark") == 0 ||
                      strcmp(argv[i], "--bench") == 0){
                task = 3;
            } else if((strcmp(argv[i], "--task") == 0 || strcmp(argv[i], "-t") == 0) && i + 1 < argc){
                const char *v = argv[++i];
                if(strcmp(v, "0") == 0 || strcmp(v, "encrypt") == 0 || strcmp(v, "demo") == 0) task = 0;
                else if(strcmp(v, "1") == 0 || strcmp(v, "analysis") == 0 || strcmp(v, "stats") == 0 || strcmp(v, "test") == 0) task = 1;
                else if(strcmp(v, "3") == 0 || strcmp(v, "benchmark") == 0 || strcmp(v, "bench") == 0) task = 3;
            } else if((strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc){
                const char *v = argv[++i];
                if(strcmp(v, "random") == 0 || strcmp(v, "1") == 0) mode = 1;
                else mode = 0;
            } else if((strcmp(argv[i], "--size") == 0 || strcmp(argv[i], "-s") == 0) && i + 1 < argc){
                data_kb = atoi(argv[++i]);
                if(data_kb < 1) data_kb = 1;
            } else if(strcmp(argv[i], "--text") == 0 && i + 1 < argc){
                custom_text = argv[++i];
            } else if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0){
                if(world_rank == 0){
                    printf("Usage (named): %s --task <encrypt|analysis|benchmark> [--mode demo|random] [--size KB] [--text STRING] [--single|--double]\n", argv[0]);
                    printf("Aliases: --task-encrypt, --task-analysis, --task-benchmark\n");
                    printf("Compatibility: --single, --double and --once are accepted\n");
                    printf("Legacy compatibility: --test and --bench are supported\n");
                }
                MPI_Finalize();
                return 0;
            }
        }

        if(task < 0) task = 0;

        if(task == 3){
            benchmark(key, double_pass);
            MPI_Finalize();
            return 0;
        }
        if(task == 1){
            build_op_table(key);
            int rc = self_test(key, double_pass);
            if(world_rank == 0)
                run_statistical_analysis(key, double_pass);
            MPI_Finalize();
            return rc;
        }
        int rc = run_encrypt_task(key, mode, data_kb, custom_text, double_pass);
        MPI_Finalize();
        return rc;
    }

    if(argc>1 && strcmp(argv[1],"--test")==0){
        build_op_table(key);
        int rc = self_test(key, 1);
        MPI_Finalize();
        return rc;
    }

    if(argc>1 && strcmp(argv[1],"--bench")==0){
        benchmark(key, 1);
        MPI_Finalize();
        return 0;
    }

    /* Interactive menu */
    int choice=0;
    if (world_rank == 0) {
        printf("\n  1. Self-tests\n  2. Benchmark (GPU only)\n  0. Exit\n\n> ");
        if(scanf("%d",&choice)!=1) choice=0;
    }
    MPI_Bcast(&choice, 1, MPI_INT, 0, MPI_COMM_WORLD);
    build_op_table(key);
    if(choice==1){
        int rc = self_test(key, 1);
        gpu_cache_release();
        MPI_Finalize();
        return rc;
    }
    if(choice==2){
        benchmark(key, 1);
        gpu_cache_release();
        MPI_Finalize();
        return 0;
    }
    gpu_cache_release();
    MPI_Finalize();
    return 0;
}
