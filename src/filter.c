#define _GNU_SOURCE
#include "filter.h"

#include "lines.h"
#include "mask.h"
#include "redact.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

int act_redact(const char *file) {
	MaskSet M;
	MaskStream ms;
	StreamLine sl = {0};
	ScanState sst;
	char *lit = NULL, *scan = NULL;
	size_t lit_cap = 0, scan_cap = 0;
	int write_failed = 0;

	scan_state_init(&sst);
	maskset_init(&M);
	maskstream_init(&ms);
	if (file) {
		Lines L = read_file(file);
		maskset_load_lines(&M, &L);
		lines_free(&L);
	}
	maskset_build(&M);

	setvbuf(stdout, NULL, _IOLBF, 0);

	while (read_stream_line(stdin, &sl)) {
		const char *eol = sl.crlf ? "\r\n" : "\n";
		size_t eollen = sl.eol ? (sl.crlf ? 2u : 1u) : 0;
		size_t n = 0;
		if (!scan_text_line(sl.buf, sl.len, eol, eollen, &scan, &scan_cap, &n, &sst))
			continue;
		size_t k = maskstream_apply(&M, &ms, scan, n, 0, &lit, &lit_cap);
		if (k && fwrite(lit, 1, k, stdout) != k) {
			write_failed = 1;
			break;
		}
	}

	size_t n = 0;
	if (!write_failed && scan_text_finish(&scan, &scan_cap, &n, &sst)) {
		size_t k = maskstream_apply(&M, &ms, scan, n, 0, &lit, &lit_cap);
		if (k && fwrite(lit, 1, k, stdout) != k)
			write_failed = 1;
	}
	if (!write_failed) {
		size_t k = maskstream_apply(&M, &ms, NULL, 0, 1, &lit, &lit_cap);
		if (k && fwrite(lit, 1, k, stdout) != k)
			write_failed = 1;
	}

	streamline_free(&sl);
	scan_state_free(&sst);
	maskstream_free(&ms);
	maskset_free(&M);
	free(lit);
	free(scan);
	if (write_failed)
		die("write failed");
	stdout_flush_check();
	return 0;
}
