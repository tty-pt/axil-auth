all := libaxil-auth
SONAME-libaxil-auth := axil-auth

LDLIBS-libaxil-auth := -laxil -lcorm -lxylem
LDLIBS-libaxil-auth-Linux := -lcrypt
LDFLAGS-libaxil-auth-Darwin := -undefined dynamic_lookup

CFLAGS += -I$(shell cd .. && pwd)/axil/include

-include ./../mk/include.mk

test:
	./test.sh
