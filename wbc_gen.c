/*
 * wbc_gen.c — читает N байт из /dev/urandom, шифрует cascade_encrypt (ECB),
 * пишет шифртекст в stdout.
 *
 * Использование:
 *   ./wbc_gen <bytes> [mix|no-mix] > ct.bin
 *
 * По умолчанию используется mix.
 *
 * Компиляция:
 *   gcc -O2 -o wbc_gen wbc_gen.c -lssl -lcrypto -lm
 */
#define WBC_GEN_MODE  /* не включать main из wbc1_fixed_cascade.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* ── Минимальный встроенный код шифратора ───────────────────────────────── */

#define KEY_SIZE   32
#define ROUNDS     16
#define NUM_OPS   127
#define NONCE_SIZE 12
#define MAC_SIZE   32
#define MAGIC_LEN   4

static uint8_t rotate_left (uint8_t b, int n) { n&=7; return (uint8_t)((b<<n)|(b>>(8-n))); }
static uint8_t rotate_right(uint8_t b, int n) { n&=7; return (uint8_t)((b>>n)|(b<<(8-n))); }

static void sha256w(const uint8_t *d, size_t l, uint8_t o[32]) { SHA256(d,l,o); }

static int dim_for(int bs) {
    int d = 2;
    while ((d+1)*(d+1)*(d+1) <= bs) d++;
    return d;
}

static int auto_block_size(int n) {
    static const int cubes[] = {8,27,64,125,216,343,512,729,1000,1331,1728,2197,2744,3375,4096,0};
    int best = 8;
    for (int i = 0; cubes[i]; i++) if (cubes[i] <= n) best = cubes[i];
    return best;
}

static void get_round_key(const uint8_t *km, int r, int bs, uint8_t *out) {
    uint8_t base[KEY_SIZE+4];
    memcpy(base,km,KEY_SIZE);
    base[KEY_SIZE]=(uint8_t)r; base[KEY_SIZE+1]=base[KEY_SIZE+2]=base[KEY_SIZE+3]=0;
    uint8_t h[32]; sha256w(base,KEY_SIZE+4,h);
    uint8_t buf[4096]; int blen=32; memcpy(buf,h,32);
    int c=1;
    while(blen<bs){
        uint8_t tmp[KEY_SIZE+6]; memcpy(tmp,base,KEY_SIZE+4);
        tmp[KEY_SIZE+4]=(uint8_t)c; tmp[KEY_SIZE+5]=(uint8_t)(c>>8);
        sha256w(tmp,KEY_SIZE+6,h); memcpy(buf+blen,h,32); blen+=32; c++;
    }
    memcpy(out,buf,bs);
}

typedef struct { uint8_t *data; int dim; } Cube;
static Cube cube_alloc(int d){Cube c;c.dim=d;c.data=calloc(d*d*d,1);return c;}
static void cube_free(Cube *c){free(c->data);c->data=NULL;}
static inline int idx3(int d,int i,int j,int k){return i*d*d+j*d+k;}

static void rot90_2d(uint8_t *mat,int dim,int k){
    k=((k%4)+4)%4;
    for(int t=0;t<k;t++){
        uint8_t *tmp=malloc(dim*dim);
        for(int i=0;i<dim;i++) for(int j=0;j<dim;j++) tmp[i*dim+j]=mat[j*dim+(dim-1-i)];
        memcpy(mat,tmp,dim*dim); free(tmp);
    }
}
static uint8_t *get_slice(const Cube *c,int axis,int pos){
    int dim=c->dim; uint8_t *sl=malloc(dim*dim);
    int p=((pos%dim)+dim)%dim;
    for(int i=0;i<dim;i++) for(int j=0;j<dim;j++){
        if(axis==0) sl[i*dim+j]=c->data[idx3(dim,p,i,j)];
        else if(axis==1) sl[i*dim+j]=c->data[idx3(dim,i,p,j)];
        else sl[i*dim+j]=c->data[idx3(dim,i,j,p)];
    }
    return sl;
}
static void set_slice(Cube *c,int axis,int pos,const uint8_t *sl){
    int dim=c->dim; int p=((pos%dim)+dim)%dim;
    for(int i=0;i<dim;i++) for(int j=0;j<dim;j++){
        if(axis==0) c->data[idx3(dim,p,i,j)]=sl[i*dim+j];
        else if(axis==1) c->data[idx3(dim,i,p,j)]=sl[i*dim+j];
        else c->data[idx3(dim,i,j,p)]=sl[i*dim+j];
    }
}
typedef struct { int axis; int pos; int k; } SliceOp;
typedef struct { int n_ops; SliceOp ops[4]; int perm[3]; } ComposedOp;
static ComposedOp g_ops[NUM_OPS];
static int g_ops_init = 0;

static void init_ops(void){
    if(g_ops_init) return; g_ops_init=1;
    int idx=0;
    for(int ax=0;ax<3&&idx<NUM_OPS;ax++)
        for(int k=1;k<=3&&idx<NUM_OPS;k++)
            for(int pos=0;pos<4&&idx<NUM_OPS;pos++){
                g_ops[idx].n_ops=1; g_ops[idx].ops[0]=(SliceOp){ax,pos,k};
                g_ops[idx].perm[0]=0; g_ops[idx].perm[1]=1; g_ops[idx].perm[2]=2;
                idx++;
            }
    int perms[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
    for(int p=0;p<6&&idx<NUM_OPS;p++){
        g_ops[idx].n_ops=0;
        g_ops[idx].perm[0]=perms[p][0]; g_ops[idx].perm[1]=perms[p][1]; g_ops[idx].perm[2]=perms[p][2];
        idx++;
    }
    while(idx<NUM_OPS){
        g_ops[idx]=g_ops[idx%36]; idx++;
    }
}

static void apply_composed_op(Cube *c, const ComposedOp *op, int inv){
    int dim=c->dim;
    if(!inv){
        for(int o=0;o<op->n_ops;o++){
            uint8_t *sl=get_slice(c,op->ops[o].axis,op->ops[o].pos);
            rot90_2d(sl,dim,op->ops[o].k); set_slice(c,op->ops[o].axis,op->ops[o].pos,sl); free(sl);
        }
        if(op->perm[0]!=0||op->perm[1]!=1||op->perm[2]!=2){
            uint8_t *tmp=malloc(dim*dim*dim);
            for(int i=0;i<dim;i++) for(int j=0;j<dim;j++) for(int k=0;k<dim;k++){
                int src[3]={i,j,k}; int di=src[op->perm[0]],dj=src[op->perm[1]],dk=src[op->perm[2]];
                tmp[idx3(dim,di,dj,dk)]=c->data[idx3(dim,i,j,k)];
            }
            memcpy(c->data,tmp,dim*dim*dim); free(tmp);
        }
    } else {
        if(op->perm[0]!=0||op->perm[1]!=1||op->perm[2]!=2){
            int inv_perm[3]; for(int i=0;i<3;i++) inv_perm[op->perm[i]]=i;
            uint8_t *tmp=malloc(dim*dim*dim);
            for(int i=0;i<dim;i++) for(int j=0;j<dim;j++) for(int k=0;k<dim;k++){
                int src[3]={i,j,k}; int di=src[inv_perm[0]],dj=src[inv_perm[1]],dk=src[inv_perm[2]];
                tmp[idx3(dim,di,dj,dk)]=c->data[idx3(dim,i,j,k)];
            }
            memcpy(c->data,tmp,dim*dim*dim); free(tmp);
        }
        for(int o=op->n_ops-1;o>=0;o--){
            uint8_t *sl=get_slice(c,op->ops[o].axis,op->ops[o].pos);
            rot90_2d(sl,dim,-op->ops[o].k); set_slice(c,op->ops[o].axis,op->ops[o].pos,sl); free(sl);
        }
    }
}
static void apply_operation(Cube *c,int op_id,int inv){
    int idx=((op_id%NUM_OPS)+NUM_OPS)%NUM_OPS;
    apply_composed_op(c,&g_ops[idx],inv);
}
static void bitwise_rotate_cube(Cube *c,int n,int right){
    int sz=c->dim*c->dim*c->dim; n=((n%8)+8)%8;
    if(n==0) return;
    for(int i=0;i<sz;i++)
        c->data[i]=right ? rotate_right(c->data[i],n) : rotate_left(c->data[i],n);
}
static void mix_cube(uint8_t *d,int n){for(int i=1;i<n;i++) d[i]^=d[i-1];}

static void derive_cascade_key(const uint8_t *enc,int bs,uint8_t new_rk[KEY_SIZE]){
    uint8_t F[KEY_SIZE]={0};
    for(int j=0;j<bs;j++) F[j%KEY_SIZE]^=enc[j];
    for(int i=0;i<KEY_SIZE;i++){
        uint8_t zi=F[i]^rotate_left(F[(i+1)%KEY_SIZE],i%8)^rotate_right(F[(i-1+KEY_SIZE)%KEY_SIZE],(i+3)%8)^(uint8_t)((29*i)%256);
        new_rk[i]=(uint8_t)(zi^(zi>>4)^(uint8_t)((zi<<3)|(zi>>5))^(zi>>1));
    }
}

static void encrypt_block(const uint8_t *km,const uint8_t *blk,int bs,uint8_t *out,int use_mix){
    int dim=dim_for(bs);
    Cube cube=cube_alloc(dim); memcpy(cube.data,blk,bs);
    uint8_t rk[4096];
    for(int r=0;r<ROUNDS;r++){
        get_round_key(km,r,bs,rk);
        int op_id=rk[0]%NUM_OPS;
        apply_operation(&cube,op_id,0);
        if (use_mix) mix_cube(cube.data,bs);
        for(int i=0;i<bs;i++) cube.data[i]^=rk[i];
        bitwise_rotate_cube(&cube,op_id,1);
    }
    memcpy(out,cube.data,bs); cube_free(&cube);
}

static uint8_t *wbc1_pad(const uint8_t *data,size_t dlen,int bs,size_t *out_len){
    int rem=(int)(dlen%bs); int fill=rem?bs-rem:0;
    size_t total=dlen+fill+bs; uint8_t *out=calloc(total,1);
    memcpy(out,data,dlen); out[dlen+fill]=(uint8_t)(fill&0xFF); out[dlen+fill+1]=(uint8_t)((fill>>8)&0xFF);
    *out_len=total; return out;
}

/* ECB cascade encrypt */
static uint8_t *cascade_encrypt_ecb(const uint8_t *master_key,const uint8_t *data,size_t dlen,int bs,size_t *out_len,int use_mix){
    size_t plen; uint8_t *padded=wbc1_pad(data,dlen,bs,&plen);
    size_t nb=plen/bs;
    uint8_t *inter=malloc(plen), *result=malloc(plen);
    uint8_t rk[KEY_SIZE]; memcpy(rk,master_key,KEY_SIZE);
    for(size_t b=0;b<nb;b++){
        encrypt_block(rk,padded+b*bs,bs,inter+b*bs,use_mix);
        derive_cascade_key(inter+b*bs,bs,rk);
    }
    uint8_t rk_bwd[KEY_SIZE]; derive_cascade_key(master_key,KEY_SIZE,rk_bwd);
    for(int b=(int)nb-1;b>=0;b--){
        encrypt_block(rk_bwd,inter+b*bs,bs,result+b*bs,use_mix);
        derive_cascade_key(result+b*bs,bs,rk_bwd);
    }
    *out_len=plen; free(inter); free(padded);
    return result;
}

int main(int argc, char *argv[]) {
    size_t nbytes = 1024*1024; /* default 1MB */
    int use_mix = 1;
    if (argc >= 2) nbytes = (size_t)atol(argv[1]);
    if (argc >= 3) {
        if (strcmp(argv[2], "no-mix") == 0 || strcmp(argv[2], "nomix") == 0) use_mix = 0;
        else if (strcmp(argv[2], "mix") == 0) use_mix = 1;
        else {
            fprintf(stderr, "Usage: %s <bytes> [mix|no-mix]\n", argv[0]);
            return 1;
        }
    }

    init_ops();

    uint8_t key[KEY_SIZE];
    RAND_bytes(key, KEY_SIZE);

    uint8_t *plain = malloc(nbytes);
    RAND_bytes(plain, (int)nbytes);

    int bs = auto_block_size((int)nbytes);
    size_t ct_len;
        uint8_t *ct = cascade_encrypt_ecb(key, plain, nbytes, bs, &ct_len, use_mix);

    fwrite(ct, 1, ct_len, stdout);
        fprintf(stderr, "Зашифровано: %zu байт → %zu байт (block=%d, mode=%s)\n",
            nbytes, ct_len, bs, use_mix ? "mix" : "no-mix");

    free(ct); free(plain);
    return 0;
}
