#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "common.h"
#include "tls_message.pb-c.h"



int main()
{
    int ret = -1;
    RSA *k  = NULL;

    int sock_fd = 0, conn_fd = 0, n = 0;
    struct sockaddr_in serv_addr;
    unsigned char recv_buf[2048] = {0};

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         printf("fail to create socket\n");
         return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(10001);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sock_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
    listen(sock_fd, 100);
    int sum = 0;
    while(1) {
        conn_fd = accept(sock_fd, (struct sockaddr*)NULL, NULL);

        n = read(conn_fd, recv_buf, 2048);
        sum += n;
        if  (sum >= 10)
            break;
    }

    printf("suc to read:%d bytes\n", sum);
    void *buf = malloc(sum);
    RsaDecReq *req = NULL;
    if ((req = rsa_dec_req__unpack(NULL, sum, buf)) == NULL) {
        printf("fail to unpack rsa_dec_req\n");
    }
    printf("req id:%d req padding:%d max out:%d\n", req->id, req->padding, req->max_out);
    int k_len = 0;

    const unsigned char *p = &recv_buf[4];
    int keylen;

    k = d2i_RSAPrivateKey(NULL, &p, k_len);
    if (k == NULL) {
         printf("fail to d2i rsa private key\n");
         return -1;
    }

    unsigned char *crypt_txt = &recv_buf[4 + k_len];
    int crypt_len = sum - 4 - k_len;
    unsigned char decrypt[2048] = {0};
    int decrypt_len = RSA_private_decrypt(crypt_len ,crypt_txt, decrypt, k, RSA_PKCS1_OAEP_PADDING);
    printf("suc to decrypt:%s\n", decrypt);


    print_hex(recv_buf, sum);

    printf("rsa private key len:%d key:%s\n", k_len, recv_buf);

    return 0;
}
