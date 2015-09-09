CC=g++
CFLAGS=-Wall -g -O2
LIBS=-lcrypto
 
all: rsa 
	 
rsa: rsa.cc
	    $(CC) $(CFLAGS) rsa.cc -o $@ $(LIBS)
		 
clean:
	    @rm -f rsa
