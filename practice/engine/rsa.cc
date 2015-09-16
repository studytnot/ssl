/*
* rsa.cc
* - Show the usage of RSA encryption/decryption
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

int main(int argc, char** argv) {
    unsigned char* input_string;
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    int i;
    // check usage
    if (argc != 2) {
        fprintf(stderr, "%s <plain text>\n", argv[0]);
        exit(-1);
    }

    ENGINE *eng = ENGINE_new();
    if (NULL != eng) {
        printf("fail to create ENGINE\n");
    }

    // set the input string
    input_string = (unsigned char*)calloc(strlen(argv[1]) + 1,
            sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, argv[1], strlen(argv[1]));

    // Generate RSA parameters with 1024 bits (using exponent 3)
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        printf("fail to alloc for rsa\n");
        exit(-1);
    }

    BIGNUM  *bn_e = BN_new();
    int     bits  = 1024;
    unsigned long  e = RSA_F4;
    BN_set_word(bn_e, e);
    int ret = RSA_generate_key_ex(rsa, bits, bn_e, NULL);
    if (ret != 1) {
        printf("fail to generate key\n");
        exit(-1);
    }

    // set encryption RSA instance (with only n and e), to resemble
    // the key distribution process
    unsigned char* n_b = (unsigned char*)calloc(RSA_size(rsa),
            sizeof(unsigned char));
    unsigned char* e_b = (unsigned char*)calloc(RSA_size(rsa),
            sizeof(unsigned char));
    int n_size = BN_bn2bin(rsa->n, n_b);
    int b_size = BN_bn2bin(rsa->e, e_b);
    // assume the byte strings are sent over the network
    RSA* encrypt_rsa = RSA_new();
    encrypt_rsa->n = BN_bin2bn(n_b, n_size, NULL);
    encrypt_rsa->e = BN_bin2bn(e_b, b_size, NULL);

    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(RSA_size(encrypt_rsa),
            sizeof(unsigned char));
    if (encrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }

    // encrypt (return the size of the encrypted data)
    // note that if RSA_PKCS1_OAEP_PADDING is used,
    // flen must be < RSA_size - 41
    int encrypt_size = RSA_public_encrypt(strlen((char*)input_string),
            input_string, encrypt_string, encrypt_rsa, RSA_PKCS1_OAEP_PADDING);

    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(RSA_size(rsa),
            sizeof(unsigned char));
    if (decrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }

    // decrypt
    int decrypt_size = RSA_private_decrypt(encrypt_size,
            encrypt_string, decrypt_string, rsa, RSA_PKCS1_OAEP_PADDING);

    // print
    printf("input_string = %s\n", input_string);
    printf("encrypted string = ");
    for (i=0; i<encrypt_size; ++i) {
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf,
                encrypt_string[i] & 0xf);
    }
    printf("\n");
    printf("decrypted string (%d) = %s\n", decrypt_size, decrypt_string);

    return 0;
}
