# Tests host-side (sin ESP-IDF). Flags completos según docs/format/c-style.md:
# -std=c11 -Wall -Wextra -Wpedantic -Werror
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror
TSNODE = ../../components/tsnode
PROTO = $(TSNODE)/src/proto
CRYPTO = $(TSNODE)/src/crypto
WG = $(TSNODE)/src/wg
VECTORS = protocol_vectors

TESTS = test_h2 test_blake2s test_replay test_wg test_nacl_box

all: $(TESTS)

test_h2: test_h2.c $(PROTO)/h2.c $(PROTO)/tsnode_map.c $(TSNODE)/include/tsnode_err.h $(PROTO)/h2.h $(PROTO)/tsnode_map.h
	$(CC) $(CFLAGS) -I$(TSNODE)/include -I$(PROTO) -o $@ test_h2.c \
		$(PROTO)/h2.c $(PROTO)/tsnode_map.c

test_blake2s: test_blake2s.c $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h \
	$(TSNODE)/src/tsnode.c $(VECTORS)/blake2s_vectors.h \
	$(TSNODE)/include/tsnode_err.h
	$(CC) $(CFLAGS) -I$(TSNODE)/include -I$(CRYPTO) -I$(VECTORS) -o $@ $< \
		$(CRYPTO)/blake2s.c $(TSNODE)/src/tsnode.c

test_replay: test_replay.c $(WG)/replay.c $(WG)/replay.h
	$(CC) $(CFLAGS) -I$(WG) -o $@ $< $(WG)/replay.c

# POLY1305_32BIT fija la variante portable de poly1305-donna: la
# autodetección usaría unsigned __int128 (extensión GNU) que rompe
# -Wpedantic. TweetNaCl + chacha20poly1305 son test-only (producción =
# mbedTLS), ver vendor/README.
#
# TweetNaCl se compila aparte sin -Werror: código vendor upstream con
# sign-compare benignos en su macro FOR; no se parchea código de
# terceros para silenciar linters (política en vendor/README.md).
VENDORTW = vendor/tweetnacl.host.o

$(VENDORTW): vendor/tweetnacl.c vendor/tweetnacl.h
	$(CC) -std=c11 -Wall -Wextra -Wpedantic \
		-DPOLY1305_32BIT=1 -Ivendor -c $< -o $@

test_wg: test_wg.c $(WG)/wg.c $(WG)/wg.h $(WG)/replay.c \
	$(CRYPTO)/blake2s.c $(CRYPTO)/hmac_blake2s.c $(VECTORS)/wg_vectors.h \
	$(VENDORTW) vendor/poly1305-donna.c \
	vendor/poly1305-donna.h vendor/poly1305-donna-32.h \
	vendor/chacha20poly1305_rfc8439.c vendor/wg_crypto_host.c
	$(CC) $(CFLAGS) -DPOLY1305_32BIT=1 -I$(TSNODE) -I$(TSNODE)/include \
		-o $@ $< \
		$(WG)/wg.c $(WG)/replay.c $(CRYPTO)/blake2s.c \
		$(CRYPTO)/hmac_blake2s.c \
		vendor/poly1305-donna.c \
		vendor/chacha20poly1305_rfc8439.c vendor/wg_crypto_host.c \
		$(VENDORTW)

test_nacl_box: test_nacl_box.c $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
	../../third_party/salsa20poly1305/salsa20.c \
	../../third_party/salsa20poly1305/poly1305.c \
	$(TSNODE)/include/tsnode_err.h $(VENDORTW) vendor/tweetnacl.h
	$(CC) $(CFLAGS) -DPOLY1305_32BIT=1 \
		-I$(TSNODE)/src/crypto -I../../third_party/salsa20poly1305 \
		-I$(TSNODE)/include -Ivendor \
		-o $@ test_nacl_box.c \
		$(CRYPTO)/nacl_box.c \
		../../third_party/salsa20poly1305/salsa20.c \
		../../third_party/salsa20poly1305/poly1305.c \
		$(VENDORTW)

check: all
	./test_h2
	./test_blake2s
	./test_replay
	./test_wg
	./test_nacl_box

clean:
	rm -f $(TESTS)

.PHONY: all check clean
