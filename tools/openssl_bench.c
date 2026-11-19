/* Native OpenSSL EVP SLH-DSA-SHA2-128s verification throughput; no subprocess
 * per verify. One verification reuses a key but re-inits the EVP context.
 * Usage: ./openssl_bench PUBLICKEY.bin MESSAGE.bin SIGNATURE.bin ITERATIONS
 */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

static unsigned char *readfile(const char *path, size_t *len) {
    FILE *f=fopen(path,"rb"); if(!f){perror(path);exit(1);}
    if(fseek(f,0,SEEK_END)!=0){perror("seek");exit(1);}
    long size=ftell(f); if(size<0){perror("tell");exit(1);}
    rewind(f);
    unsigned char *buf=malloc((size_t)size+1);if(!buf){perror("malloc");exit(1);}
    if(fread(buf,1,(size_t)size,f)!=(size_t)size){perror("read");exit(1);}
    fclose(f);*len=(size_t)size;return buf;
}
static double clock_seconds(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)!=0){perror("clock_gettime");exit(1);}
    return (double)t.tv_sec+(double)t.tv_nsec*1e-9;
}
int main(int argc,char **argv) {
    if(argc!=5){fprintf(stderr,"usage: %s pk.bin msg.bin sig.bin iterations\n",argv[0]);return 2;}
    size_t klen=0,mlen=0,slen=0;
    unsigned char *pk=readfile(argv[1],&klen),*msg=readfile(argv[2],&mlen),*sig=readfile(argv[3],&slen);
    if(klen!=32 || slen!=7856){fprintf(stderr,"wrong key/signature sizes\n");return 2;}
    long count=strtol(argv[4],NULL,10);if(count<=0){fprintf(stderr,"iterations must be positive\n");return 2;}
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key_ex(NULL,"SLH-DSA-SHA2-128s",NULL,pk,klen);
    if(!key){ERR_print_errors_fp(stderr);return 2;}
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx){return 2;}
    double begin=clock_seconds();
    for(long i=0;i<count;i++) {
        if(EVP_DigestVerifyInit_ex(ctx,NULL,NULL,NULL,NULL,key,NULL)!=1 ||
           EVP_DigestVerify(ctx,sig,slen,msg,mlen)!=1){ERR_print_errors_fp(stderr);fprintf(stderr,"failed verification %ld\n",i);return 1;}
    }
    double elapsed=clock_seconds()-begin;
    printf("{\"algorithm\":\"SLH-DSA-SHA2-128s\",\"iterations\":%ld,\"seconds\":%.9f,\"verifications_per_second\":%.4f,\"average_verify_ms\":%.6f}\n",
        count,elapsed,count/elapsed,elapsed*1000.0/count);
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);free(pk);free(msg);free(sig);
    return 0;
}
