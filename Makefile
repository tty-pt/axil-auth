all := libndc-auth
SONAME-libndc-auth := ndc-auth

LDLIBS-libndc-auth := -lndc -lqmap -lndx
LDLIBS-libndc-auth-Linux := -lcrypt
LDFLAGS-libndc-auth-Darwin := -undefined dynamic_lookup

-include ./../mk/include.mk

test:
	./test.sh
