# wifiparse: radiotap + 802.11 header parser.
#
#   make         optimized build        -> wifiparse
#   make debug   AddressSanitizer + UndefinedBehaviorSanitizer build -> wifiparse-debug
#   make clean
#
# Needs libpcap headers (Debian/Ubuntu: apt install libpcap-dev).

CC      ?= cc
# _DEFAULT_SOURCE: pcap.h uses BSD types (u_int, u_char) that glibc hides in strict C11 mode.
CPPFLAGS += -D_DEFAULT_SOURCE
WARN    := -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wconversion
CFLAGS  ?= -O2
CFLAGS  += -std=c11 $(WARN)
LDLIBS  += -lpcap

SRC  := wifiparse.c
HDRS := ieee80211.h radiotap.h

.PHONY: all debug clean

all: wifiparse

wifiparse: $(SRC) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

# -fno-sanitize-recover makes any sanitizer finding abort with a non-zero exit code.
debug: wifiparse-debug

wifiparse-debug: $(SRC) $(HDRS)
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -fno-sanitize-recover=all \
		-o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f wifiparse wifiparse-debug
