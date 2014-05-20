/***************************************************************************
 * 
 * Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
 * 
 **************************************************************************/
 
#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#include <sys/epoll.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
 
/**
 * @file myep.c
 * @author luocheng@baidu.com(com@baidu.com)
 * @date 2014/01/05 10:14:08
 * @brief 
 *  
 **/

typedef struct ssl_data_t {
    int fd;
    SSL *ssl;
} ssl_data, *ssl_data_ptr;

#define MAXEVENTS 64
static void lc_show_certs(SSL *ssl);
static u_char *hex_dump(u_char *dst, u_char *src, size_t len) 
{
    static u_char  hex[] = "0123456789abcdef";

    while (len--) {           
        *dst++ = hex[*src >> 4];       
        *dst++ = hex[*src++ & 0xf];    
    }  

    return dst;
}

static void lc_show_certs(SSL *ssl)
{
    X509 *cert;
    char *line;
    SSL_CIPHER  *cipher = NULL;
    char buf[129];
    cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        SSL_CIPHER_description(cipher, &buf[1], 128);
        printf("SSL:%s, cipher:%s\n", SSL_get_version(ssl), &buf[1]);
    }

    
    SSL_SESSION  *sess = SSL_get0_session(ssl);
    if (sess) {
        u_char dst[128];
        int len = sess->session_id_length;
        hex_dump(dst, sess->session_id, len);
        printf("id_len:%d session id:%s!!!!!!!!!!\n", len, dst);
    }
}


static int make_socket_non_block(int fd)
{
    if (fd <= 0) {
        fprintf(stderr, "fd can not be less than 0\n");
    }

    int flag = fcntl(fd, F_GETFL, 0);
    if (-1 == flag) {
        perror("fcntl");
        return -1;
    }

    flag |= O_NONBLOCK;

    flag = fcntl(fd, F_SETFL, flag);
    if (-1 == flag) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

static int create_and_bind(char *port)
{
    int s, sfd;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    printf("port is %s\n", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;

    s = getaddrinfo(NULL, port, &hints, &result);
    if ( 0 != s) {
        fprintf(stderr, "getaddrinfo: %s \n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (-1 == sfd) {
            continue;
        }
        
        int reuseaddr_on = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(reuseaddr_on));
        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (0 == s) {
            break;
        }

        close(sfd);
    }

    if (NULL == rp) {
        fprintf(stderr, "could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}


static int lc_load_cert_file(SSL_CTX *ctx, char *cert_file, char *key_file)
{
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }
}

int main(int argc, char** argv)
{
    if ( 2 != argc) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;

    SSL_CTX *ctx;
    SSL *ssl;
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
        printf("fail to initialize ssl ctx\n");
        exit(-1);
    }

    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE); 
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-SHA:AES128-SHA:RC4-SH");
    SSL_CTX_set_timeout(ctx, (long) 60);
    SSL_CTX_set_session_id_context(ctx, "HTTP", 4);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    
    //SSL_CTX_sess_set_new_cb(ctx, lc_ssl_new_session);
    
    if (-1 == lc_load_cert_file(ctx, "mycert.pem", "mycert.key")) {
        fprintf(stderr, "fail to load cert\n");
        exit(-1);
    }

    sfd = create_and_bind(argv[1]);
    if (-1 == sfd) {
        fprintf(stderr, "fail to create sfd\n");
        return -1;
    }

    s = make_socket_non_block(sfd);
    if (s == -1) {
        perror("fail to make nonblock");
        return -1;
    }

    s = listen(sfd, SOMAXCONN);
    if (-1 == s) {
        perror("listen");
        return -1;
    }

    efd = epoll_create(200);
    if (-1 == efd) {
        perror("epoll_create");
        return -1;
    }

    event.data.fd = sfd;
    event.events = EPOLLIN | EPOLLET;
    
    s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (-1 == s) {
        perror("epoll_ctl");
        return -1;
    }
    printf("add fd:%d \n", sfd);

    events = calloc(MAXEVENTS, sizeof(struct epoll_event));

    
    while (1) {
        int n, i;
        n = epoll_wait(efd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++) {
            struct epoll_event ev_i = events[i];
            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP)) {
                fprintf(stderr, "epoll error %u\n", events[i].events);
                close(events[i].data.fd);
                continue;
            } else if (sfd == events[i].data.fd) {
                while(1) {
                    struct sockaddr in_addr;
                    socklen_t  in_len;
                    int infd;
                    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                    in_len = sizeof(in_addr);
                    infd   = accept(sfd, &in_addr, &in_len);
                    if (-1 == infd) {
                        if ((errno == EAGAIN ||errno == EWOULDBLOCK)) {
                            break;
                        } else {
                            perror("accept");
                            break;
                        }
                    }
                   
                    s = getnameinfo(&in_addr, in_len, hbuf, sizeof hbuf, sbuf,
                                    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);
                    if (0 == s) {
                        time_t timep;
                        time(&timep);
                        printf("%s:Accepted connection on fd:%d (host=%s, port=%s)\n", ctime(&timep),infd, hbuf, sbuf);
                    }

                    s = make_socket_non_block(infd);
                    if (-1 == s) {
                        perror("fail to make nonblock");
                        abort();
                    }
                    
                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, infd);
                    SSL_set_accept_state(ssl);

                    if (SSL_do_handshake(ssl) != 1) {
                        int n;
                        int i = SSL_get_error(ssl, n);
                        printf("handshake error:%d\n", i);
                    } else {
                        printf("suc to handshake\n");
                    }

                    //lc_show_certs(ssl);
                SSL_SESSION  *sess = SSL_get0_session(ssl);
                if (sess) {
                    u_char dst[128];
                    int len = sess->session_id_length;
                    hex_dump(dst, sess->session_id, len);
                    printf("id_len:%d session id:%s!!!!!!!!!!\n", len, dst);
                }
                if (SSL_session_reused(ssl)) {
                    printf("SSL session reused!!!!!!!\n");
                }
                printf("after reuse test\n");
                    ssl_data_ptr accept_ssl_data  = (ssl_data_ptr) malloc(sizeof(ssl_data));
                    accept_ssl_data->ssl = ssl;
                    accept_ssl_data->fd = infd;

                    event.data.ptr = accept_ssl_data;
                    event.events  = EPOLLIN;
                    s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
                    if (-1 == s) {
                        perror("epoll_ctl add");
                        abort();
                    }
                }
                continue;
            } else if (ev_i.events & EPOLLIN){
                int done = 0;
                while (1) {
                    ssize_t count;
                    char buf[512];
                    printf("begin to  SSL_read\n");

                    SSL *ssl = ((ssl_data_ptr)ev_i.data.ptr)->ssl;
                    count = SSL_read(ssl, buf, sizeof(buf));
                    if (-1 == count) {
                        if (errno != EAGAIN) {
                            perror("read");
                            done = 1;
                        }
                        break;
                    } else if ( 0 == count) {
                        done = 1;
                        break;
                    }
                    if (SSL_session_reused(ssl)) {
                        printf("SSL session reused!!!!!!!\n");
                    }
                    
                    //s = write(1, buf, count);
                    if (-1 == s) {
                        perror("write");
                        abort();
                    }
                    event.data.ptr = ev_i.data.ptr;
                    event.events  = EPOLLOUT|EPOLLET ;
                    s = epoll_ctl(efd, EPOLL_CTL_MOD, ((ssl_data_ptr)ev_i.data.ptr)->fd, &event);
                    if (-1 == s) {
                        perror("epoll_ctl add");
                        abort();
                    }
                }
                if (done) {
                    printf("should closed connection on descriptor %d\n", ((ssl_data_ptr)events[i].data.ptr)->fd);
                    close(((ssl_data_ptr)events[i].data.ptr)->fd);
                }
            } else if (ev_i.events & EPOLLOUT) {
                char *w_buf = "HTTP/1.1 200 Ok\r\nUser-agent: luocheng\r\nContent-Length:4\r\nConnection: close\r\n\r\ntest";
                while (1) {
                    int s = SSL_write((SSL*)(((ssl_data_ptr)ev_i.data.ptr)->ssl), w_buf, strlen(w_buf));
                    if (s < 0) {
                        fprintf(stderr, "fail to write \n");
                    } else {
                        printf("suc to write %d data\n", s);
                        break;
                    }
                }
                    event.data.ptr = ev_i.data.ptr;
                    event.events  = EPOLLIN;
                    s = epoll_ctl(efd, EPOLL_CTL_MOD, ((ssl_data_ptr)ev_i.data.ptr)->fd, &event);
                    if (-1 == s) {
                        perror("epoll_ctl add");
                        abort();
                    }
            }
        }
    }
    free(events);
    close(sfd);
    return EXIT_SUCCESS;
}
/* vim: set expandtab ts=4 sw=4 sts=4 tw=100 */
