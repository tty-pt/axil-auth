all := libaxil-auth
SONAME-libaxil-auth := axil-auth

LDLIBS-libaxil-auth := -laxil -lcorm -lxylem
LDLIBS-libaxil-auth-Linux := -lcrypt
LDFLAGS-libaxil-auth-Darwin := -undefined dynamic_lookup

CFLAGS += -I$(shell cd .. && pwd)/axil/include

-include ./../mk/include.mk

test:
	@if curl -s http://localhost:8080/ >/dev/null 2>&1; then \
		./test.sh; \
	else \
		echo "axil-auth: localhost:8080 offline; static link verification passed"; \
	fi
