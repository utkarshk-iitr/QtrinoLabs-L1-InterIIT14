CC       = gcc
WOLFSSL_INSTALL_DIR = /usr/local
CFLAGS   = -Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS     = -L$(WOLFSSL_INSTALL_DIR)/lib -lm

DYN_LIB         = -lwolfssl
STATIC_LIB      = $(WOLFSSL_INSTALL_DIR)/lib/libwolfssl.a
DEBUG_FLAGS     = -g3 -DDEBUG -O0
DEBUG_INC_PATHS = -MD
OPTIMIZE        = -Os

CFLAGS+=$(OPTIMIZE)
LIBS+=$(DYN_LIB)

TARGETS = server client

.PHONY: clean all install

all: $(TARGETS)

install: all

server: server_dtls.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

client: client_dtls.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGETS)
