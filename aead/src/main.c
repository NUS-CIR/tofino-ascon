#include <stdio.h>

#include <stdlib.h>
#include "aead.h"
#define ASCON_PRINT_STATE

void main(){
    unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned char k[CRYPTO_KEYBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15};
    unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}; 

    unsigned char* out=malloc(33*sizeof(*out));
    unsigned char m[8]={0, 1, 2, 3, 4, 5, 6, 7};
    unsigned char c[32], h[32], t[32];
    unsigned long long alen = 0;
    // unsigned long long mlen = 8;
    unsigned long long clen = CRYPTO_ABYTES;
    unsigned long long mlen=8;
    // unsigned long long len= (unsigned long long)strlen(in);
    printf("the LENGTH is %llu bytes\n",mlen);

    int finish= crypto_aead_encrypt(c, &clen, m, mlen, a, alen, (void*)0, n, k);
    
    printf("\n finish encryption\n");

    printf("the ciphertext is \n");
    for (int i = 0; i < 24; i++)
    {
        printf("%02X ",c[i]);
    }
    printf("\n");
    // c[3]=0;
    int f=crypto_aead_decrypt(m, &mlen, (void*)0, c, clen, a, alen, n, k);

    printf("Result after decrypt is %d \n", f);

    printf("the adata is \n");
    for (int i = 0; i < alen; i++)
    {
        printf("%02X ",a[i]);
    }
    printf("the msg is \n");
    for (int i = 0; i < mlen; i++)
    {
        printf("%02X ",m[i]);
    }
    
    printf("\n");
    free(out);

}