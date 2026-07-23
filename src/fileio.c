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

static void emit_line(FILE *out, const char *line, int redact, int *suppress) {
	if (*suppress) {
		if (strstr(line, "-----END") ||
		    (line[0] == '"' || (strlen(line) && line[strlen(line) - 1] == '"')))
			*suppress = 0;
		return;
	}

	if (!redact) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	const char *p = skip_ws(line);
	if (*p == '#')
		p = skip_ws(p + 1);
	p = skip_export(p);

	const char *eq = strchr(p, '=');
	if (!eq) {
		if (is_pem_private(line)) {
			fputs("# <redacted:private-key>\n", out);
			if (!strstr(line, "-----END"))
				*suppress = 1;
			return;
		}
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	size_t kl = (size_t)(eq - p);
	if (!valid_keychars(p, kl)) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	char kbuf[256];
	size_t kn = kl < sizeof(kbuf) - 1 ? kl : sizeof(kbuf) - 1;
	memcpy(kbuf, p, kn);
	kbuf[kn] = '\0';
	const char *val = eq + 1;

	if (!should_mask(kbuf, val)) {
		fputs(line, out);
		fputc('\n', out);
		return;
	}

	fwrite(line, 1, (size_t)(eq - line) + 1, out);
	fputs(redact_token(kbuf, val), out);
	fputc('\n', out);

	if (is_pem_private(val) && !strstr(val, "-----END"))
		*suppress = 1;
	else if (val[0] == '"' && !strchr(val + 1, '"'))
		*suppress = 1;
}

void emit(FILE *out, Lines *L, int redact) {
	int suppress = 0;
	for (size_t i = 0; i < L->n; i++)
		emit_line(out, L->v[i], redact, &suppress);
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

	emit(tf, out, 0);
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

	emit(tf, out, 0);
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
