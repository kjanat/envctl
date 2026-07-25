#define _GNU_SOURCE
#include "filter.h"

#include "lines.h"
#include "mask.h"
#include "redact.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define FILTER_LABEL_MAX 64

int act_redact(const char *file) {
	MaskSet M;
	StreamLine sl = {0};
	char *lit = NULL, *scan = NULL;
	size_t lit_cap = 0, scan_cap = 0;
	char label[FILTER_LABEL_MAX] = {0};
	int pem_open = 0;

	maskset_init(&M);
	if (file) {
		Lines L = read_file(file);
		maskset_load_lines(&M, &L);
		for (size_t i = 0; i < L.n; i++)
			free(L.v[i]);
		free(L.v);
	}
	maskset_build(&M);

#ifdef _WIN32
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
#endif
	setvbuf(stdout, NULL, _IOLBF, 0);

	while (read_stream_line(stdin, &sl)) {
		size_t n = maskset_apply(&M, sl.buf, sl.len, &lit, &lit_cap);
		size_t k = 0;
		if (!scan_text_line(lit, n, &scan, &scan_cap, &k, &pem_open, label, sizeof(label)))
			continue;
		fwrite(scan, 1, k, stdout);
		if (sl.eol) {
			if (sl.crlf)
				fputc('\r', stdout);
			fputc('\n', stdout);
		}
	}

	streamline_free(&sl);
	maskset_free(&M);
	free(lit);
	free(scan);
	return 0;
}
