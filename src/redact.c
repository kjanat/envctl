#define _GNU_SOURCE
#include "redact.h"

#include "agent.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* Case-insensitive segment match: (^|_)seg(_|$). */
static int has_segment_ci(const char *k, const char *seg) {
	size_t n = strlen(seg);
	if (!n)
		return 0;
	for (const char *p = k; *p; p++) {
		size_t i = 0;
		for (; i < n; i++) {
			unsigned char a = (unsigned char)p[i], b = (unsigned char)seg[i];
			if (!a || toupper(a) != toupper(b))
				break;
		}
		if (i != n)
			continue;
		int left = (p == k) || (p[-1] == '_');
		int right = (p[n] == '\0') || (p[n] == '_');
		if (left && right)
			return 1;
	}
	return 0;
}

static int ends_with_ci(const char *k, const char *suf) {
	size_t kn = strlen(k), sn = strlen(suf);
	if (kn < sn)
		return 0;
	for (size_t i = 0; i < sn; i++) {
		if (toupper((unsigned char)k[kn - sn + i]) != toupper((unsigned char)suf[i]))
			return 0;
	}
	return 1;
}

static int pathish_key_suffix(const char *k) {
	return ends_with_ci(k, "_FILE") || ends_with_ci(k, "_PATH") || ends_with_ci(k, "_ENDPOINT") ||
	       ends_with_ci(k, "_NAME") || ends_with_ci(k, "_VERSION") || ends_with_ci(k, "_LENGTH") ||
	       ends_with_ci(k, "_DIR") || ends_with_ci(k, "_HOME");
}

static int strong_secret_key_name(const char *k) {
	if (pathish_key_suffix(k))
		return 0;
	if (has_segment_ci(k, "PASSWORD") || has_segment_ci(k, "PASSWD") || has_segment_ci(k, "PWD") ||
	    has_segment_ci(k, "PASS") || has_segment_ci(k, "SECRET") || has_segment_ci(k, "TOKEN") ||
	    has_segment_ci(k, "CREDENTIAL") || has_segment_ci(k, "CREDENTIALS") ||
	    has_segment_ci(k, "DSN") || has_segment_ci(k, "KEYSTORE") || has_segment_ci(k, "PKCS12") ||
	    has_segment_ci(k, "P12") || has_segment_ci(k, "PFX"))
		return 1;
	if ((has_segment_ci(k, "DATABASE") || has_segment_ci(k, "DB")) && has_segment_ci(k, "URL"))
		return 1;
	if (has_segment_ci(k, "CONNECTION") && has_segment_ci(k, "STRING"))
		return 1;
	if (has_segment_ci(k, "WEBHOOK") && has_segment_ci(k, "SECRET"))
		return 1;
	if (has_segment_ci(k, "KEY") &&
	    (has_segment_ci(k, "API") || has_segment_ci(k, "ACCESS") || has_segment_ci(k, "SECRET") ||
	     has_segment_ci(k, "PRIVATE") || has_segment_ci(k, "AUTH") ||
	     has_segment_ci(k, "SIGNING") || has_segment_ci(k, "ENCRYPTION") ||
	     has_segment_ci(k, "MASTER") || has_segment_ci(k, "CLIENT") ||
	     has_segment_ci(k, "SESSION") || has_segment_ci(k, "APP")))
		return 1;
	if (has_segment_ci(k, "PRIVATE") && has_segment_ci(k, "KEY"))
		return 1;
	return 0;
}

static int suspicious_key_name(const char *k) {
	if (pathish_key_suffix(k))
		return 0;
	if (strong_secret_key_name(k))
		return 1;
	return has_segment_ci(k, "KEY") || has_segment_ci(k, "API") || has_segment_ci(k, "AUTH") ||
	       has_segment_ci(k, "BEARER") || has_segment_ci(k, "ACCESS") ||
	       has_segment_ci(k, "CRED") || has_segment_ci(k, "PASS") || has_segment_ci(k, "JWT") ||
	       has_segment_ci(k, "OAUTH");
}

static int is_trivial_value(const char *v) {
	static const char *const trivial[] = {
	    "",          "0",         "1",          "true",        "false", "yes",     "no",   "on",
	    "off",       "debug",     "info",       "warn",        "error", "trace",   "null", "none",
	    "localhost", "127.0.0.1", "production", "development", "test",  "staging", NULL,
	};
	for (int i = 0; trivial[i]; i++) {
		const char *t = trivial[i];
		size_t n = strlen(t);
		int ok = 1;
		for (size_t j = 0; j < n; j++) {
			if (toupper((unsigned char)v[j]) != toupper((unsigned char)t[j])) {
				ok = 0;
				break;
			}
		}
		if (ok && v[n] == '\0')
			return 1;
	}
	if (*v) {
		const char *p = v;
		if (*p == '-' || *p == '+')
			p++;
		if (*p) {
			while (*p && isdigit((unsigned char)*p))
				p++;
			if (*p == '\0' && strlen(v) <= 6)
				return 1;
		}
	}
	return 0;
}

int is_pem_private(const char *v) { return strstr(v, "BEGIN") && strstr(v, "PRIVATE KEY"); }

static int is_pem_public_material(const char *v) {
	return strstr(v, "BEGIN CERTIFICATE") || strstr(v, "BEGIN CERTIFICATE REQUEST") ||
	       strstr(v, "BEGIN PUBLIC KEY") || strstr(v, "BEGIN RSA PUBLIC KEY") ||
	       strstr(v, "BEGIN EC PUBLIC KEY");
}

static int is_credentialed_url(const char *v) {
	const char *scheme = strstr(v, "://");
	if (!scheme)
		return 0;
	const char *userinfo = scheme + 3;
	const char *at = strchr(userinfo, '@');
	if (!at || at == userinfo)
		return 0;
	for (const char *p = userinfo; p < at; p++) {
		if (*p == ':')
			return 1;
	}
	return 0;
}

static int is_plain_path(const char *v) {
	if (!v || !*v || is_credentialed_url(v))
		return 0;
	if (v[0] == '/' || v[0] == '\\')
		return 1;
	if (v[0] == '.' &&
	    (v[1] == '/' || v[1] == '\\' || (v[1] == '.' && (v[2] == '/' || v[2] == '\\'))))
		return 1;
	if (((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) && v[1] == ':' &&
	    (v[2] == '\\' || v[2] == '/'))
		return 1;
	return 0;
}

static int is_b64url_char(unsigned char c) { return isalnum(c) || c == '-' || c == '_'; }

static int is_jwt_shape(const char *v) {
	int segs = 0;
	const char *p = v;
	while (*p) {
		const char *s = p;
		while (*p && *p != '.') {
			if (!is_b64url_char((unsigned char)*p))
				return 0;
			p++;
		}
		if (p == s)
			return 0;
		segs++;
		if (*p == '.')
			p++;
		else
			break;
	}
	return segs == 3 && *p == '\0' && strlen(v) >= 20;
}

static int prefix_match(const char *v, const char *pfx) {
	return strncmp(v, pfx, strlen(pfx)) == 0;
}

static int known_token_prefix(const char *v) {
	static const char *const pfx[] = {
	    "ghp_",        "gho_",     "ghu_",     "ghs_",     "ghr_",
	    "github_pat_", "glpat-",   "gpat-",    "sk-ant-",  "sk-proj-",
	    "sk-live-",    "sk_live_", "rk_live_", "sk_test_", "rk_test_",
	    "xoxb-",       "xoxp-",    "xoxa-",    "xoxr-",    "xoxs-",
	    "npm_",        "pypi-",    "dop_v1_",  "whsec_",   "AGE-SECRET-KEY-1",
	    "AKIA",        "ASIA",     "ABIA",     "ACCA",     "AIza",
	    "SG.",         NULL,
	};
	for (int i = 0; pfx[i]; i++) {
		if (prefix_match(v, pfx[i]))
			return 1;
	}
	if (prefix_match(v, "sk-") && strlen(v) >= 20)
		return 1;
	return 0;
}

static int is_uuid_shape(const char *v) {
	static const int dashes[] = {8, 13, 18, 23, -1};
	if (strlen(v) != 36)
		return 0;
	for (int i = 0; dashes[i] >= 0; i++) {
		if (v[dashes[i]] != '-')
			return 0;
	}
	for (size_t i = 0; v[i]; i++) {
		if (v[i] == '-')
			continue;
		if (!isxdigit((unsigned char)v[i]))
			return 0;
	}
	return 1;
}

static int random_looking(const char *v) {
	size_t n = strlen(v);
	if (n < 24 || is_uuid_shape(v))
		return 0;
	if (n == 40) {
		int hex = 1;
		for (size_t i = 0; i < n; i++) {
			if (!isxdigit((unsigned char)v[i])) {
				hex = 0;
				break;
			}
		}
		if (hex)
			return 0;
	}
	int seen[256] = {0}, uniq = 0, has_alpha = 0, has_digit = 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)v[i];
		if (!seen[c]++)
			uniq++;
		if (isalpha(c))
			has_alpha = 1;
		else if (isdigit(c))
			has_digit = 1;
	}
	return has_alpha && has_digit && uniq * 3 >= (int)n;
}

int should_mask(const char *key, const char *val) {
	if (!val)
		val = "";
	if (is_pem_private(val))
		return 1;
	if (known_token_prefix(val))
		return 1;
	if (is_credentialed_url(val))
		return 1;
	if (is_jwt_shape(val))
		return 1;
	if (is_pem_public_material(val))
		return 0;
	if (strong_secret_key_name(key)) {
		if (is_trivial_value(val) || is_plain_path(val))
			return 0;
		return 1;
	}
	if (suspicious_key_name(key) && random_looking(val))
		return 1;
	return 0;
}

const char *redact_token(const char *key, const char *val) {
	(void)key;
	if (is_pem_private(val))
		return "<redacted:private-key>";
	if (is_credentialed_url(val))
		return "<redacted:credentials>";
	return "<redacted>";
}

int want_redact(int flag_redact, int flag_raw) {
	if (flag_raw)
		return 0;
	if (flag_redact)
		return 1;
	return detect_agent() && stdout_isatty();
}

void print_value(const char *key, const char *val, int redact) {
	if (redact && should_mask(key, val))
		printf("%s\n", redact_token(key, val));
	else
		printf("%s\n", val);
}
