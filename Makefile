CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11
PREFIX   ?= $(HOME)/.local
SRC       = envctl.c
DIST     ?= dist

# All release artifacts are built natively on the matching runner.
LINUX_AMD64_CC   ?= $(CC)
LINUX_ARM64_CC   ?= $(CC)
WINDOWS_AMD64_CC ?= gcc
WINDOWS_ARM64_CC ?= gcc
DARWIN_CC        ?= $(CC)

# Host binary name (Windows → envctl.exe).
ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif
BIN := envctl$(EXE)

# Release artifact names.
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

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

# ---------------------------------------------------------------------------
# test — smoke checks against the host binary
# ---------------------------------------------------------------------------

test: $(BIN)
	@bin=./$(BIN); \
	set -e; \
	$$bin -h >/dev/null; \
	printf 'FOO=one\nAPI_TOKEN=abcdefghij\n' > dotenv.test; \
	test "$$($$bin get dotenv.test FOO)" = "one"; \
	test "$$($$bin --redact get dotenv.test API_TOKEN)" = "****ghij"; \
	test "$$($$bin --raw get dotenv.test API_TOKEN)" = "abcdefghij"; \
	$$bin --dry-run set dotenv.test FOO two | grep -q '^FOO=two$$'; \
	$$bin set dotenv.test FOO two; \
	test "$$($$bin get dotenv.test FOO)" = "two"; \
	rm -f dotenv.test; \
	echo "test ok: $$bin"

# ---------------------------------------------------------------------------
# release artifacts — one target per platform triple (CI calls these)
# ---------------------------------------------------------------------------

$(DIST):
	mkdir -p $(DIST)

dist-linux-amd64: $(ART_LINUX_AMD64)
$(ART_LINUX_AMD64): $(SRC) | $(DIST)
	$(LINUX_AMD64_CC) $(CFLAGS) -static -s -o $@ $<

dist-linux-arm64: $(ART_LINUX_ARM64)
$(ART_LINUX_ARM64): $(SRC) | $(DIST)
	$(LINUX_ARM64_CC) $(CFLAGS) -static -s -o $@ $<

dist-darwin-amd64: $(ART_DARWIN_AMD64)
$(ART_DARWIN_AMD64): $(SRC) | $(DIST)
	$(DARWIN_CC) $(CFLAGS) -o $@ $<

dist-darwin-arm64: $(ART_DARWIN_ARM64)
$(ART_DARWIN_ARM64): $(SRC) | $(DIST)
	$(DARWIN_CC) $(CFLAGS) -o $@ $<

dist-windows-amd64: $(ART_WINDOWS_AMD64)
$(ART_WINDOWS_AMD64): $(SRC) | $(DIST)
	$(WINDOWS_AMD64_CC) $(CFLAGS) -static -s -o $@ $<

dist-windows-arm64: $(ART_WINDOWS_ARM64)
$(ART_WINDOWS_ARM64): $(SRC) | $(DIST)
	$(WINDOWS_ARM64_CC) $(CFLAGS) -static -s -o $@ $<

# SHA256SUMS for everything currently in dist/ (run after artifacts exist).
checksums:
	@cd $(DIST) && sha256sum envctl-* > SHA256SUMS && cat SHA256SUMS

# ---------------------------------------------------------------------------
# install / fmt / clean
# ---------------------------------------------------------------------------

# Point the PATH symlink at this binary (default: ~/.local/bin/envctl).
install: $(BIN)
	mkdir -p $(PREFIX)/bin
	ln -sf $(CURDIR)/$(BIN) $(PREFIX)/bin/envctl

# Format sources via dprint (clang-format for C, shfmt for the shell script).
fmt format:
	dprint fmt

clean:
	rm -f envctl envctl.exe dotenv.test
	rm -rf $(DIST)
