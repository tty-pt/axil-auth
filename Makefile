all := libaxil-auth
SONAME-libaxil-auth := axil-auth

LDLIBS-libaxil-auth := -laxil -lqmap -lndx
LDLIBS-libaxil-auth-Linux := -lcrypt
LDFLAGS-libaxil-auth-Darwin := -undefined dynamic_lookup
LDFLAGS-libaxil-auth := -L$(shell cd .. && pwd)/axil/lib

CFLAGS += -I$(shell cd .. && pwd)/axil/include

-include ./../mk/include.mk

test:
	./test.sh
