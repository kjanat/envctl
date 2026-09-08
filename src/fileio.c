#define _GNU_SOURCE
#include "fileio.h"

#include "lines.h"
#include "redact.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static size_t put_span(FILE *out, const Lines *L, size_t i, size_t span, const char *prefix) {
	size_t k = 0;
	for (size_t j = 0; j < span && i + j < L->n; j++, k++) {
		if (!out)
			continue;
		fputs(prefix, out);
		fputs(L->v[i + j], out);
		fputc('\n', out);
	}
	return k;
}

size_t render_span(FILE *out, const Lines *L, size_t i, size_t span, const char *prefix,
                   int redact) {
	const char *line = L->v[i];

	if (!redact)
		return put_span(out, L, i, span, prefix);

	Assignment a;
	if (!parse_assignment(line, &a)) {
		if (is_pem_private(line)) {
			if (out) {
				fputs(prefix, out);
				fputs("# <redacted:private-key>\n", out);
			}
			return 1;
		}
		return put_span(out, L, i, span, prefix);
	}

	size_t kl = a.key_len;
	char *kbuf = xmalloc(kl + 1);
	memcpy(kbuf, a.key, kl);
	kbuf[kl] = '\0';

	char *val = join_span(L, i, span);
	char *decoded = decode_value(val);
	const char *masked = decoded && should_mask(kbuf, decoded) ? decoded : val;
	size_t n;
	if (should_mask(kbuf, masked)) {
		if (out) {
			fputs(prefix, out);
			fwrite(line, 1, (size_t)(a.value - line), out);
			fputs(redact_token(kbuf, masked), out);
			fputc('\n', out);
		}
		n = 1;
	} else {
		n = put_span(out, L, i, span, prefix);
	}
	free(decoded);
	free(val);
	free(kbuf);
	return n;
}

void emit(FILE *out, const Lines *L) {
	for (size_t i = 0; i < L->n; i++) {
		fputs(L->v[i], out);
		fputc('\n', out);
	}
}

static char *dir_of(const char *path) {
	const char *slash = NULL;

	for (const char *p = path; *p; p++) {
		if (*p == '/'
#ifdef _WIN32
		    || *p == '\\'
#endif
		)
			slash = p;
	}

	if (!slash)
		return xstrdup(".");

	size_t n = (size_t)(slash - path);
	if (n == 0)
		n = 1;

	char *d = xmalloc(n + 1);
	memcpy(d, path, n);
	d[n] = '\0';
	return d;
}

void commit_file(const char *file, Lines *out) {
	char *dir = dir_of(file);

#ifdef _WIN32
	char tmp[MAX_PATH];
	if (!GetTempFileNameA(dir, "env", 0, tmp))
		die("GetTempFileName failed");

	FILE *tf = fopen(tmp, "wb");
	if (!tf) {
		DeleteFileA(tmp);
		die("temp open failed");
	}

	emit(tf, out);
	if (fflush(tf) != 0 || fclose(tf) != 0) {
		DeleteFileA(tmp);
		die("write failed");
	}
	if (!MoveFileExA(tmp, file, MOVEFILE_REPLACE_EXISTING)) {
		DeleteFileA(tmp);
		die("replace failed");
	}
#else
	size_t tl = strlen(dir) + sizeof("/.envctl.XXXXXX");
	char *tmpl = xmalloc(tl);
	snprintf(tmpl, tl, "%s/.envctl.XXXXXX", dir);

	int fd = mkstemp(tmpl);
	if (fd < 0)
		die("mkstemp failed");

	FILE *tf = fdopen(fd, "wb");
	if (!tf) {
		unlink(tmpl);
		die("fdopen failed");
	}

	emit(tf, out);
	if (fflush(tf) != 0) {
		fclose(tf);
		unlink(tmpl);
		die("write failed");
	}

	struct stat st;
	if (stat(file, &st) == 0)
		(void)fchmod(fd, st.st_mode & 07777);

	if (fclose(tf) != 0) {
		unlink(tmpl);
		die("close failed");
	}
	if (rename(tmpl, file) != 0) {
		unlink(tmpl);
		die("rename failed");
	}
	free(tmpl);
#endif

	free(dir);
}
