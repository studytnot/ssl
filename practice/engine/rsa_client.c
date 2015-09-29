#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "common.h"

int main()
{
    int ret = -1;
    RSA *k  = NULL;
    BIGNUM *bne = BN_new();
    char buf[4096];
    if (bne == NULL) {
        printf("fail to create bn\n");
        return -1;
    }

    ret = BN_set_word(bne, RSA_F4);
    if (ret != 1) {
        printf("fail to set word for bne\n");
        return -1;
    }

    k = RSA_new();
    ret = RSA_generate_key_ex(k, 2048, bne, NULL);
    if (ret == -1) {
        printf("fail to generate rsa key pair\n");
        return -1;
    }

    unsigned char *plain_txt = "hello lancelot";
    unsigned char encrypt_txt[1024];
    int en_len = RSA_public_encrypt(strlen(plain_txt), plain_txt, encrypt_txt, k, RSA_PKCS1_OAEP_PADDING);
    printf("encrypt len:%d\n", en_len);
    print_hex(encrypt_txt, en_len);

    unsigned char *key_buf = NULL;
    printf("key buf addr:%p\n", key_buf);
    int key_len  =  i2d_RSAPrivateKey(k, &key_buf);
    printf("key buf addr:%p\n", key_buf);


    printf("key_len:%d private key:%s\n", key_len, key_buf);
    sprintf(buf, "%d", key_len);
    memcpy(&buf[sizeof(int)], key_buf, key_len);
    memcpy(&buf[sizeof(int) + key_len], encrypt_txt, en_len);
    int len = sizeof(int) + key_len + en_len;

    int sock_fd = 0, n = 0;
    struct sockaddr_in serv_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         printf("fail to create socket\n");
         return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(10001);
    if ((inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)) < 0) {
        printf("fail to inet_pton\n");
        return -1;
    }

    if (connect(sock_fd, (const struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
         printf("fail to connect \n");
         return -1;
    }

    print_hex(key_buf, key_len);

    n = write(sock_fd, buf, len);
    printf("suc to send:%d bytes\n", n);

    return 0;
}
