#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
// #define ASCON_PRINT_STATE

void main(){
    unsigned char* out=malloc(33*sizeof(*out));
    const unsigned char* in="0000";
    // unsigned long long len=2;
    unsigned long long len= (unsigned long long)strlen(in);
    // printf("the LENGTH is %llu \n",len);

    int finish= crypto_hash(out,in,len);
    
    out[32]=NULL; // to get the string in a printable form

    printf("the output string is \n");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ",out[i]);
    }
    
    printf("\n");
    free(out);

}