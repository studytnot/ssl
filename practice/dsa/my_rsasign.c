#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define FILE_LEN  64
#define RSA_KEY_SIZE 2048
#define SIGN_TEST_NUM  10000

static int do_sign_and_verify(RSA *pri_key, RSA *pub_key, const unsigned char *plain_txt, const int txt_len);
static int my_rsa_sign(const char *key_file, const char *input_file, const char *output_file);
static int my_rsa_verify(const char *key_file, const char *input_file, const char *output_file);
static void display_hex(const unsigned char *s, int len);

static long inline elapse_time(struct timeval s, struct timeval e)
{
    return (e.tv_sec - s.tv_sec) * 1000000  + e.tv_usec - s.tv_usec;
}

static int rsa_sign_verify_test()
{
    int ret;
    char err_buf[1024];
    RSA *prikey = NULL;
    RSA *pubkey = NULL;

    // generate key pair
    // note: RSA_generate_key is depricated
    BIGNUM *bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);
    if (ret != 1) {
        printf("fail to set word for e\n");
        return -1;
    }
    printf("begin to generate keys\n");
    int size = 2048;
    prikey = RSA_new();
    ret = RSA_generate_key_ex(prikey, size,  bne, NULL);
    if (ret == -1) {
        fprintf(stderr, "fail to generate rsa key pair. err:%s\n",
                ERR_error_string(ERR_get_error(), err_buf));
        return -1;
    }

    // make public key from key pair
    pubkey = RSA_new();
    if (NULL == pubkey) {
        fprintf(stderr, "fail to create public key, err:%s\n",
                ERR_error_string(ERR_get_error(), err_buf));
        return -1;
    }

    if (!pubkey->e && (pubkey->e = BN_new()) != NULL) {
        BN_copy(pubkey->e, prikey->e);
    }

    if (!pubkey->n && (pubkey->n = BN_new()) != NULL) {
        BN_copy(pubkey->n, prikey->n);
    }

    char *plain_txt = "hello world, the message should be signed with rsa";

    do_sign_and_verify(prikey, pubkey, plain_txt, strlen(plain_txt));

    RSA_free(prikey);
    RSA_free(pubkey);
}

static int do_sign_and_verify(RSA *pri_key, RSA *pub_key, const unsigned char *plain_txt, const int txt_len)
{
    if (NULL == pri_key || NULL == pub_key || NULL == plain_txt || txt_len <=0) {
        printf("wrong parameter\n");
        return -1;
    }

    int i = 0;
    int sign_len = 0;
    unsigned char sign_txt[256];
    unsigned char hash_txt[SHA256_DIGEST_LENGTH];
    struct timeval s, e, sha_s, sha_e, sign_s, sign_e, verify_e;
    long sign_time = 0;
    long verify_time = 0;
    long hash_time = 0;
    gettimeofday(&s, NULL);
    while (i < SIGN_TEST_NUM) {
        gettimeofday(&sha_s, NULL);
        SHA256(plain_txt, txt_len, hash_txt);
        gettimeofday(&sha_e, NULL);
        hash_time += elapse_time(sha_s, sha_e);
        int ret = RSA_sign(NID_sha256, hash_txt, SHA256_DIGEST_LENGTH, sign_txt, &sign_len, pri_key);
        gettimeofday(&sign_e, NULL);
        sign_time += elapse_time(sha_e, sign_e);
        if (ret != 1) {
            printf("fail to sign\n");
            exit(-1);
        }

        ret = RSA_verify(NID_sha256, hash_txt, SHA256_DIGEST_LENGTH, sign_txt, sign_len, pub_key);
        if (ret != 1) {
            printf("fail to verify\n");
            exit(-1);
        }

        gettimeofday(&verify_e, NULL);
        verify_time += elapse_time(sign_e, verify_e);

        i++;
    }

    gettimeofday(&e, NULL);
    printf("total %d time:%ld, sign time:%ld, verify time:%ld, hash time:%ld\n", SIGN_TEST_NUM, elapse_time(s, e), sign_time, verify_time, hash_time);

    return 0;
}

// sign input_file with private key , saved in key_file, then save the signature to output_file
static int my_rsa_sign(const char *key_file, const char *input_file, const char *output_file)
{
    RSA *pri_key = NULL:
    BIO *b = NULL, in_bio = NULL, out_bio = NULL;
    b = BIO_new_file(key_file, "r");

    pri_key = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);
    if (pri_key == NULL) {
        printf("fail to read rsa private key\n");
        return -1;
    }

    in_bio = BIO_new_file(input_file, "r");
    if (NULL == in_bio) {
         printf("fail to create new file:%s\n", input_file):
    }

    out_bio = BIO_new_file(output_file, "w+");
    if (NULL == out_bio) {
         printf("fail to create new file:%s\n", input_file):
    }


    return 0;
}

static int my_rsa_verify(const char *key_file, const char *input_file, const char *output_file)
{
    return 0;
}

static void display_hex(const unsigned char *s, int len)
{
    int i = 0;
    for(i = 0; i < len; i++) {
        printf("%02x", s[i]);
    }

    printf("\n");
}

int main (int argc, char **argv)
{
    static struct option long_options[] = {
      {"sign_test",  no_argument, 0, 't'},
      {"rsa_sign",  no_argument, 0, 's'},
      {"rsa_verify",  no_argument, 0, 'v'},
      {"key_file",    required_argument, 0, 'f'},
      {"output",    required_argument, 0, 'o'},
      {"input",    required_argument, 0, 'i'},
      {0, 0, 0, 0}
    };

    int c;
    int is_sign    = 0;
    int is_verify  = 0;
    int is_test    = 0;
    int option_index = 0;
    char key_file[FILE_LEN]       = {0};
    char input_file[FILE_LEN]     = {0};
    char output_file[FILE_LEN]    = {0};

    while ((c = getopt_long(argc, argv, "tsvi:o:f:", long_options, &option_index)) != -1) {
      /* getopt_long stores the option index here. */
        switch (c) {
            case 0:
              /* If this option set a flag, do nothing else now. */
              if (long_options[option_index].flag != 0)
                break;
            case 't':
              is_test = 1;
              break;
            case 's':
              is_sign = 1;
              break;
            case 'v':
              is_verify = 1;
              break;
            case 'f':
              fprintf(stdout, "option -f with optarg:%s\n", optarg);
              if (strlen(optarg) >= FILE_LEN) {
                   fprintf(stderr, "lengh of key file name is bigger than %d\n", FILE_LEN);
                   return -1;
              }
              strcpy(key_file, optarg);
              break;
            case 'i':
              fprintf(stdout, "option -i with optarg:%s\n", optarg);
              if (strlen(optarg) >= FILE_LEN) {
                   fprintf(stderr, "lengh of input file name is bigger than %d\n", FILE_LEN);
                   return -1;
              }
              strcpy(input_file, optarg);
              break;
            case 'o':
              fprintf(stdout, "option -o with optarg:%s\n", optarg);
              if (strlen(optarg) >= FILE_LEN) {
                   fprintf(stderr, "lengh of output file name is bigger than %d\n", FILE_LEN);
                   return -1;
              }
              strcpy(output_file, optarg);
              break;
            case '?':
              /* getopt_long already printed an error message. */
              break;

            default:
              abort ();
        }
    }

    if (is_test) {
         rsa_sign_verify_test();
         return 0;
    }

    if (is_sign) {
        my_rsa_sign(key_file, input_file, output_file);
    }

    if (is_verify) {
        my_rsa_verify(key_file, input_file, output_file);
    }

    exit (0);
}
