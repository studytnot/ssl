CC=g++
CFLAGS=-Wall -g -O2
LDFLAGS=../../boringssl/build/crypto/
INCFLAGS=-I../../boringssl/include
#LIBS=-lcrypto
 
all: rsa 
	 
rsa: rsa.cc
	$(CC) $(CFLAGS)  $(INCFLAGS) rsa.cc -o $@  ${LDFLAGS}/libcrypto.a ../../boringssl/build/ssl/libssl.a -lpthread
		 
clean:
	    @rm -f rsa
