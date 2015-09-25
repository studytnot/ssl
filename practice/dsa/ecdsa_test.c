#include <stdio.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

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

int main()
{
    //int err;
    //int sig_len;
    //unsigned char sig_buf[4096];
    static char certfile[] = "cert.pem";
    static char keyfile[] = "k.pem";
    //static char data[] = "I owe you...";
    //EVP_MD_CTX md_ctx;
    EVP_PKEY *pkey;
    EC_KEY   *ec_k = NULL;
    FILE *fp;
    /*
     * Just load the crypto library error strings, SSL_load_error_strings()
     * loads the crypto AND the SSL ones
     */
    /* SSL_load_error_strings(); */
    ERR_load_crypto_strings();

    /* Read private key */

    fp = fopen(keyfile, "r");
    if (fp == NULL)
        exit(1);
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    ec_k = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec_k == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    //const EC_GROUP *group       = EC_KEY_get0_group(ec);
    const BIGNUM *tmp_priv_key  = EC_KEY_get0_private_key(ec_k);

    EC_KEY_set_private_key(ec, tmp_priv_key);
    EC_KEY_set_public_key(ec, EC_KEY_get0_public_key(ec_k));

    if (! EC_KEY_check_key(ec)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    const char digest[] = {"123"};
    uint8_t sig_len = ECDSA_size(ec);
    printf("signature len is:%u\n", sig_len);
    uint8_t *sig_buf = OPENSSL_malloc(sig_len);
    if (sig_buf == NULL) {
        fprintf(stderr, "fail to malloc for sig buf.\n");
        return -1;
    }
    memset(sig_buf, 0, sig_len);

    int i = 0, sign_num = 100000;
    struct timeval tv_s, tv_e;
    gettimeofday(&tv_s, NULL);
    while (i < sign_num) {
        ECDSA_SIG *sig = ECDSA_do_sign(digest, strlen(digest), ec);
        //if (!ECDSA_sign(0, digest, 20, sig_buf, &sig_len, ec)) {
        //    fprintf(stderr, "ECDSA_sign failed.\n");
        //}
        //i2d_ECDSA_SIG(sig, &sig_buf);

        //printHex("Sign", sig_buf, sig_len);

        if (1 != ECDSA_do_verify(digest, strlen(digest), sig, ec)) {
           // printf("signatrue verified failed\n");
        } else {
            //printf("Signature Verified Ok.\n");
        }
        i++;
    }
    gettimeofday(&tv_e, NULL);
    long e = (tv_e.tv_sec - tv_s.tv_sec)*1000000 + tv_e.tv_usec - tv_s.tv_usec;
    printf("ecdsa sing %d times ,spend %ld usec\n", sign_num, e);
    return (0);
}
