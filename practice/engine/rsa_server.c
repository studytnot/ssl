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
        if  (sum >= 1091)
            break;
    }

    printf("suc to read:%d bytes\n", sum);

    const unsigned char *p = recv_buf;
    int keylen;
    k = d2i_RSAPrivateKey(NULL, &p, sum);
    if (k == NULL) {
         printf("fail to d2i rsa private key\n");
         return -1;
    }

    print_hex(recv_buf, sum);

    printf("rsa private key len:%d key:%s\n", sum, recv_buf);

    return 0;
}
