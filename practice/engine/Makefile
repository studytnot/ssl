CC=gcc
#CFLAGS=-Wall -g -O2
CFLAGS= -g -O0
LDFLAGS=../../boringssl/build/crypto/
INCFLAGS=-I../../boringssl/include -I../public/
#LIBS=-lcrypto
 
all: rsa_client rsa_server
	 
rsa_server: rsa_server.c
	$(CC) $(CFLAGS)  $(INCFLAGS) $< -o $@  ../public/common.o ${LDFLAGS}/libcrypto.a ../../boringssl/build/ssl/libssl.a -lpthread
		 
rsa_client: rsa_client.c
	$(CC) $(CFLAGS)  $(INCFLAGS) $< -o $@  ../public/common.o ${LDFLAGS}/libcrypto.a ../../boringssl/build/ssl/libssl.a -lpthread
clean:
	    @rm -f rsa_client rsa_server
