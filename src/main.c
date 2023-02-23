#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#define ASCON_PRINT_STATE

void main(){
    unsigned char* out=malloc(33*sizeof(*out));
    unsigned char in[8]={0, 1, 2, 3, 4, 5, 6, 7};
    
    unsigned long long len=8;
    // unsigned long long len= (unsigned long long)strlen(in);
    printf("the LENGTH is %llu bytes\n",len);

    int finish= crypto_hash(out,in,len);
    
    out[32]=NULL; // to get the string in a printable form

    printf("the output string is \n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02X ",out[i]);
    }
    
    printf("\n");
    free(out);

}