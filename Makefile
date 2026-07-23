CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11 -Isrc
PREFIX   ?= $(HOME)/.local
DIST     ?= dist

SRCS := src/util.c src/agent.c src/help.c src/lines.c src/redact.c src/fileio.c src/main.c
OBJS := $(SRCS:.c=.o)

# All release artifacts are built natively on the matching runner.
LINUX_AMD64_CC   ?= $(CC)
LINUX_ARM64_CC   ?= $(CC)
WINDOWS_AMD64_CC ?= gcc
WINDOWS_ARM64_CC ?= gcc
DARWIN_CC        ?= $(CC)

ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif
BIN := envctl$(EXE)

ART_LINUX_AMD64   := $(DIST)/envctl-linux-amd64
ART_LINUX_ARM64   := $(DIST)/envctl-linux-arm64
ART_DARWIN_AMD64  := $(DIST)/envctl-darwin-amd64
ART_DARWIN_ARM64  := $(DIST)/envctl-darwin-arm64
ART_WINDOWS_AMD64 := $(DIST)/envctl-windows-amd64.exe
ART_WINDOWS_ARM64 := $(DIST)/envctl-windows-arm64.exe

.PHONY: all clean install fmt format test
.PHONY: dist-linux-amd64 dist-linux-arm64 dist-darwin-amd64 dist-darwin-arm64
.PHONY: dist-windows-amd64 dist-windows-arm64 checksums

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

test: $(BIN)
	@bin=./$(BIN); \
	set -e; \
	$$bin -h >/dev/null; \
	printf 'FOO=one\nAPI_TOKEN=abcdefghij\nPASSWORD=short\n' > dotenv.test; \
	test "$$($$bin get dotenv.test FOO)" = "one"; \
	test "$$($$bin --redact get dotenv.test API_TOKEN)" = "<redacted>"; \
	test "$$($$bin --redact get dotenv.test PASSWORD)" = "<redacted>"; \
	test "$$($$bin --raw get dotenv.test API_TOKEN)" = "abcdefghij"; \
	test "$$($$bin --redact get dotenv.test FOO)" = "one"; \
	$$bin --dry-run set dotenv.test FOO two | grep -q '^FOO=two$$'; \
	$$bin --dry-run --redact set dotenv.test API_TOKEN x | grep -q 'API_TOKEN=<redacted>'; \
	$$bin set dotenv.test FOO two; \
	test "$$($$bin get dotenv.test FOO)" = "two"; \
	rm -f dotenv.test; \
	echo "test ok: $$bin"

# ---------------------------------------------------------------------------
# release artifacts — one compile of all sources per platform triple
# ---------------------------------------------------------------------------

$(DIST):
	mkdir -p $(DIST)

dist-linux-amd64: $(ART_LINUX_AMD64)
$(ART_LINUX_AMD64): $(SRCS) | $(DIST)
	$(LINUX_AMD64_CC) $(CFLAGS) -static -s -o $@ $(SRCS)

dist-linux-arm64: $(ART_LINUX_ARM64)
$(ART_LINUX_ARM64): $(SRCS) | $(DIST)
	$(LINUX_ARM64_CC) $(CFLAGS) -static -s -o $@ $(SRCS)

dist-darwin-amd64: $(ART_DARWIN_AMD64)
$(ART_DARWIN_AMD64): $(SRCS) | $(DIST)
	$(DARWIN_CC) $(CFLAGS) -o $@ $(SRCS)

dist-darwin-arm64: $(ART_DARWIN_ARM64)
$(ART_DARWIN_ARM64): $(SRCS) | $(DIST)
	$(DARWIN_CC) $(CFLAGS) -o $@ $(SRCS)

dist-windows-amd64: $(ART_WINDOWS_AMD64)
$(ART_WINDOWS_AMD64): $(SRCS) | $(DIST)
	$(WINDOWS_AMD64_CC) $(CFLAGS) -static -s -o $@ $(SRCS)

dist-windows-arm64: $(ART_WINDOWS_ARM64)
$(ART_WINDOWS_ARM64): $(SRCS) | $(DIST)
	$(WINDOWS_ARM64_CC) $(CFLAGS) -static -s -o $@ $(SRCS)

checksums:
	@cd $(DIST) && sha256sum envctl-* > SHA256SUMS && cat SHA256SUMS

install: $(BIN)
	mkdir -p $(PREFIX)/bin
	ln -sf $(CURDIR)/$(BIN) $(PREFIX)/bin/envctl

fmt format:
	dprint fmt

clean:
	rm -f envctl envctl.exe dotenv.test $(OBJS)
	rm -rf $(DIST)
