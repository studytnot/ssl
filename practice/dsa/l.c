/**
 * ecdsa.c
 *  ECDSA Program for OpenSSL
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 */
#include <stdio.h>
#include <string.h>

#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#define EC_NAME "prime192v1"
#define EC_NID  NID_X9_62_prime192v1

static void
printHex(const char *title, const unsigned char *s, int len)
{
    int     n;

    printf("%s:", title);
    for (n = 0; n < len; ++n) {
        if ((n % 16) == 0) {
            printf("\n%04x", n);
        }
        printf(" %02x", s[n]);
    }
    printf("\n");
}

int
do_ecdsa(int nid)
{
    EC_KEY *eckey = NULL;
    EC_GROUP *group;
    unsigned char digest[20];
    unsigned char *signature = NULL;
    unsigned int sigLen;
    int     ret = 1;
    int     degree;

    /* fill digest values with some random data */
    if (!RAND_pseudo_bytes(digest, 20)) {
        fprintf(stderr, "ERROR: unable to get random data\n");
        goto err;
    }

    /* create new ecdsa key (== EC_KEY) */
    if ((eckey = EC_KEY_new()) == NULL) {
        goto err;
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        goto err;
    }
    if (EC_KEY_set_group(eckey, group) == 0) {
        goto err;
    }
    EC_GROUP_free(group);

    degree = EC_GROUP_get_degree(EC_KEY_get0_group(eckey));
    if (degree < 160) {
        fprintf(stderr, "Skip the curve %s (degree = %d)\n",
                OBJ_nid2sn(nid), degree);
        goto err;
    }
    /* create key */
    if (!EC_KEY_generate_key(eckey)) {
        fprintf(stderr, "EC_KEY_generate_key failed.\n");
        goto err;
    }

    /* check key */
    if (!EC_KEY_check_key(eckey)) {
        fprintf(stderr, "EC_KEY_check_key failed.\n");
        goto err;
    }

    /* create signature */
    sigLen = ECDSA_size(eckey);
    if ((signature = OPENSSL_malloc(sigLen)) == NULL) {
        goto err;
    }
    if (!ECDSA_sign(0, digest, 20, signature, &sigLen, eckey)) {
        fprintf(stderr, "ECDSA_sign failed.\n");
        goto err;
    }
    printHex("Sign", signature, sigLen);
    printf("sigLen = %d\n", sigLen);

    /* verify signature */
    if (ECDSA_verify(0, digest, 20, signature, sigLen, eckey) != 1) {
        fprintf(stderr, "ECDSA_verify failed.\n");
        goto err;
    }

    ret = 0;

  err:
    EC_KEY_free(eckey);
    OPENSSL_free(signature);

    return ret;
}

int
do_ecdsa_evp(int nid)
{
    int     ret = 1;

    EC_KEY *eckey = NULL;       /* EC key pair */
    EVP_PKEY *evp_key = NULL;   /* EVP private key */

    EVP_MD_CTX *evpx = NULL;    /* EVP_MD context */
    const EVP_MD *md = NULL;    /* Message Digest */

    unsigned char *mesg;
    unsigned int mesgLen = 32;
    unsigned char *signature = NULL;
    unsigned int sigLen = 0;

    eckey = EC_KEY_new_by_curve_name(nid);
    if (eckey == NULL) {
        goto err;
    }
    /* EC key pair */
    if (!EC_KEY_generate_key(eckey)) {
        goto err;
    }
    /* Private key */
    if ((evp_key = EVP_PKEY_new()) == NULL) {
        goto err;
    }
    if (!EVP_PKEY_set1_EC_KEY(evp_key, eckey)) {
        goto err;
    }

    /* EVP_MD context */
    if ((evpx = EVP_MD_CTX_create()) == NULL) {
        goto err;
    }

    /* EVP Message Digest type */
    if ((md = EVP_ecdsa()) == NULL) {
        goto err;
    }

    mesg = OPENSSL_malloc(mesgLen);
    if (sprintf(mesg, "s%", "123")) {
    //if (!RAND_pseudo_bytes(mesg, mesgLen)) {
        fprintf(stderr, "ERROR: unable to get random data\n");
        //goto err;
    }



    /* Signature area */
    sigLen = EVP_PKEY_size(evp_key);
    signature = (unsigned char *) OPENSSL_malloc(sigLen);
    if (signature == NULL) {
        goto err;
    }
    printf("sigLen  = %d\n", sigLen);
    printf("mesgLen = %d\n", mesgLen);

    /* Signature generation */
    /* Init */
    if (!EVP_SignInit_ex(evpx, md, NULL)) {
        fprintf(stderr, "EVP_SignInit error\n");
        goto err;
    }
    /* Update */
    if (!EVP_SignUpdate(evpx, mesg, mesgLen)) {
        fprintf(stderr, "EVP_SignUpdate error\n");
        goto err;
    }

    /* Final */
    if (!EVP_SignFinal(evpx, signature, &sigLen, evp_key)) {
        fprintf(stderr, "EVP_SignFinal error.\n");
        goto err;
    }
    printHex("Sign", signature, sigLen);
    printf("sigLen = %d\n", sigLen);

    /* Verify signature */
    /* Init */
    if (!EVP_VerifyInit_ex(evpx, md, NULL)) {
        fprintf(stderr, "EVP_VerifyInit error\n");
        goto err;
    }
    /* Update */
    if (!EVP_VerifyUpdate(evpx, mesg, mesgLen)) {
        fprintf(stderr, "EVP_VerifyUpdate error.\n");
        goto err;
    }
    /* Final */
    ret = EVP_VerifyFinal(evpx, signature, sigLen, evp_key);
    if (ret != 1) {
        fprintf(stderr, "EVP_VerifyFinal error.\n");
        goto err;
    }
    ret = 0;

 err:
    EVP_PKEY_free(evp_key);
    EC_KEY_free(eckey);
    EVP_MD_CTX_destroy(evpx);
    OPENSSL_free(mesg);
    OPENSSL_free(signature);

    return ret;
}

int
main(int argc, char *argv[])
{
    int     nid = EC_NID;
    int     ret;
    char *name = NULL;

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        printf("usage: ecdsa [nID [EC curve name]]\n");
        return 1;
    }
    if (argc >= 2) {
        nid = atoi(argv[1]);
    }
    if (argc == 3) {
        name = argv[2];
    }

    printf("< ECDSA Test >\n");
    printf("NID: %s\n", OBJ_nid2sn(nid));
    ret = do_ecdsa(nid);
    if (ret == 0) {
        printf("OK\n");
    } else {
        printf("NG (ret = %d)\n", ret);
    }
    printf("\n");

    printf("< ECDSA_EVP Test >\n");
    if (name == NULL ) {
        printf("NID: %s\n", EC_NAME);
        ret = do_ecdsa_evp(EC_NID);
    } else {
        ret = do_ecdsa_evp(OBJ_sn2nid(name));
    }
    if (ret == 0) {
        printf("OK\n");
    } else {
        printf("NG (ret = %d)\n", ret);
    }

    return 0;
}
