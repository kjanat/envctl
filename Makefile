CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
PREFIX ?= $(HOME)/.local

envctl: envctl.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean install fmt format
clean:
	rm -f envctl

# Format sources via dprint (clang-format for C, shfmt for the shell script).
fmt format:
	dprint fmt

# Point the PATH symlink at this binary (default: ~/.local/bin/envctl).
install: envctl
	mkdir -p $(PREFIX)/bin
	ln -sf $(CURDIR)/envctl $(PREFIX)/bin/envctl
