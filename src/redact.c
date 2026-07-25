#define _GNU_SOURCE
#include "redact.h"

#include "agent.h"
#include "entropy.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
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

static const char *mem_find(const char *h, size_t hn, const char *needle) {
	size_t nn = strlen(needle);
	if (!nn || hn < nn)
		return NULL;
	for (size_t i = 0; i + nn <= hn; i++) {
		if (memcmp(h + i, needle, nn) == 0)
			return h + i;
	}
	return NULL;
}

static int mem_prefix(const char *h, size_t hn, const char *pfx) {
	size_t pn = strlen(pfx);
	return hn >= pn && memcmp(h, pfx, pn) == 0;
}

static int mem_prefix_ci(const char *h, size_t hn, const char *pfx) {
	size_t pn = strlen(pfx);
	if (hn < pn)
		return 0;
	for (size_t i = 0; i < pn; i++) {
		if (toupper((unsigned char)h[i]) != toupper((unsigned char)pfx[i]))
			return 0;
	}
	return 1;
}

static int pathish_key_suffix(const char *k) {
	return ends_with_ci(k, "_FILE") || ends_with_ci(k, "_PATH") || ends_with_ci(k, "_ENDPOINT") ||
	       ends_with_ci(k, "_NAME") || ends_with_ci(k, "_VERSION") || ends_with_ci(k, "_LENGTH") ||
	       ends_with_ci(k, "_DIR") || ends_with_ci(k, "_HOME");
}

static int identifier_key_suffix(const char *k) { return ends_with_ci(k, "_ID"); }

static int webhook_key_name(const char *k) {
	return has_segment_ci(k, "WEBHOOK") && !identifier_key_suffix(k) && !ends_with_ci(k, "_NAME");
}

static int strong_secret_key_name(const char *k) {
	if (webhook_key_name(k))
		return 1;
	if (has_segment_ci(k, "PASSWORD") || has_segment_ci(k, "PASSWD") || has_segment_ci(k, "PWD") ||
	    has_segment_ci(k, "PASS") || has_segment_ci(k, "PASSPHRASE") ||
	    has_segment_ci(k, "SECRET") || has_segment_ci(k, "TOKEN") ||
	    has_segment_ci(k, "CREDENTIAL") || has_segment_ci(k, "CREDENTIALS") ||
	    has_segment_ci(k, "DSN") || has_segment_ci(k, "KEYSTORE") || has_segment_ci(k, "PKCS12") ||
	    has_segment_ci(k, "P12") || has_segment_ci(k, "PFX"))
		return 1;
	if ((has_segment_ci(k, "DATABASE") || has_segment_ci(k, "DB")) && has_segment_ci(k, "URL"))
		return 1;
	if (has_segment_ci(k, "CONNECTION") && has_segment_ci(k, "STRING"))
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
	if (strong_secret_key_name(k))
		return 1;
	if (identifier_key_suffix(k))
		return 0;
	return has_segment_ci(k, "KEY") || has_segment_ci(k, "API") || has_segment_ci(k, "AUTH") ||
	       has_segment_ci(k, "BEARER") || has_segment_ci(k, "ACCESS") ||
	       has_segment_ci(k, "CRED") || has_segment_ci(k, "PASS") || has_segment_ci(k, "JWT") ||
	       has_segment_ci(k, "OAUTH");
}

static int digestish_key_name(const char *k) {
	static const char *const words[] = {
	    "SHA",      "SHA1", "SHA256", "SHA512",   "HASH", "DIGEST",
	    "CHECKSUM", "ETAG", "COMMIT", "REVISION", "SRI",  NULL,
	};
	size_t kn = strlen(k);
	for (int i = 0; words[i]; i++) {
		size_t wn = strlen(words[i]);
		if (kn < wn || !ends_with_ci(k, words[i]))
			continue;
		if (kn == wn || k[kn - wn - 1] == '_')
			return 1;
	}
	return 0;
}

static int is_trivial_value(const char *v, size_t n) {
	static const char *const trivial[] = {
	    "",          "0",         "1",          "true",        "false", "yes",     "no",   "on",
	    "off",       "debug",     "info",       "warn",        "error", "trace",   "null", "none",
	    "localhost", "127.0.0.1", "production", "development", "test",  "staging", NULL,
	};
	for (int i = 0; trivial[i]; i++) {
		const char *t = trivial[i];
		if (strlen(t) != n)
			continue;
		size_t j = 0;
		for (; j < n; j++) {
			if (toupper((unsigned char)v[j]) != toupper((unsigned char)t[j]))
				break;
		}
		if (j == n)
			return 1;
	}
	if (n) {
		size_t i = 0;
		if (v[0] == '-' || v[0] == '+')
			i++;
		if (i < n) {
			size_t j = i;
			while (j < n && isdigit((unsigned char)v[j]))
				j++;
			if (j == n && n <= 6)
				return 1;
		}
	}
	return 0;
}

static int is_pem_private_n(const char *b, size_t bn) {
	return mem_find(b, bn, "BEGIN") != NULL && mem_find(b, bn, "PRIVATE KEY") != NULL;
}

int is_pem_private(const char *v) { return is_pem_private_n(v, strlen(v)); }

static int is_pem_public_material(const char *b, size_t bn) {
	return mem_find(b, bn, "BEGIN CERTIFICATE") || mem_find(b, bn, "BEGIN CERTIFICATE REQUEST") ||
	       mem_find(b, bn, "BEGIN PUBLIC KEY") || mem_find(b, bn, "BEGIN RSA PUBLIC KEY") ||
	       mem_find(b, bn, "BEGIN EC PUBLIC KEY");
}

static int is_credentialed_url(const char *b, size_t bn) {
	const char *scheme = mem_find(b, bn, "://");
	if (!scheme)
		return 0;
	const char *userinfo = scheme + 3;
	const char *end = b + bn;
	const char *at = NULL;
	for (const char *p = userinfo; p < end; p++) {
		if (*p == '@') {
			at = p;
			break;
		}
	}
	if (!at || at == userinfo)
		return 0;
	for (const char *p = userinfo; p < at; p++) {
		if (*p == ':')
			return 1;
	}
	return 0;
}

static int is_plain_path(const char *b, size_t bn) {
	if (!bn || is_credentialed_url(b, bn))
		return 0;
	if (b[0] == '/' || b[0] == '\\')
		return 1;
	if (b[0] == '.' && bn >= 2 &&
	    (b[1] == '/' || b[1] == '\\' || (b[1] == '.' && bn >= 3 && (b[2] == '/' || b[2] == '\\'))))
		return 1;
	if (bn >= 3 && ((b[0] >= 'A' && b[0] <= 'Z') || (b[0] >= 'a' && b[0] <= 'z')) && b[1] == ':' &&
	    (b[2] == '\\' || b[2] == '/'))
		return 1;
	return 0;
}

static int is_b64url_char(unsigned char c) { return isalnum(c) || c == '-' || c == '_'; }

static int is_jwt_shape(const char *b, size_t bn) {
	if (bn < 20)
		return 0;
	size_t i = 0;
	int segs = 0;
	while (i < bn) {
		size_t s = i;
		while (i < bn && b[i] != '.') {
			if (!is_b64url_char((unsigned char)b[i]))
				return 0;
			i++;
		}
		if (i == s)
			return 0;
		segs++;
		if (i < bn && b[i] == '.')
			i++;
		else
			break;
	}
	return segs == 3 && i == bn;
}

static int known_token_prefix(const char *b, size_t bn) {
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
		if (mem_prefix(b, bn, pfx[i]))
			return 1;
	}
	if (mem_prefix(b, bn, "sk-") && bn >= 20)
		return 1;
	return 0;
}

static int aws_access_key_shape(const char *b, size_t bn) {
	if (bn != 20 || !mem_prefix(b, bn, "A3T"))
		return 0;
	for (size_t i = 3; i < bn; i++) {
		unsigned char c = (unsigned char)b[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
			return 0;
	}
	return 1;
}

static int is_uuid_shape(const char *b, size_t bn) {
	static const int dashes[] = {8, 13, 18, 23, -1};
	if (bn != 36)
		return 0;
	for (int i = 0; dashes[i] >= 0; i++) {
		if (b[dashes[i]] != '-')
			return 0;
	}
	for (size_t i = 0; i < bn; i++) {
		if (b[i] == '-')
			continue;
		if (!isxdigit((unsigned char)b[i]))
			return 0;
	}
	return 1;
}

static int is_authz_char(unsigned char c) {
	return isalnum(c) || c == '+' || c == '/' || c == '=' || c == '.' || c == '_' || c == '-';
}

static int authorization_value(const char *b, size_t bn) {
	static const char *const scheme[] = {"Bearer", "Basic", NULL};
	size_t i = 0;
	if (mem_prefix_ci(b, bn, "Authorization:")) {
		i = strlen("Authorization:");
		while (i < bn && (b[i] == ' ' || b[i] == '\t'))
			i++;
	}
	for (int s = 0; scheme[s]; s++) {
		if (!mem_prefix_ci(b + i, bn - i, scheme[s]))
			continue;
		size_t j = i + strlen(scheme[s]);
		if (j >= bn || (b[j] != ' ' && b[j] != '\t'))
			continue;
		while (j < bn && (b[j] == ' ' || b[j] == '\t'))
			j++;
		size_t k = j;
		while (k < bn && is_authz_char((unsigned char)b[k]))
			k++;
		if (k - j >= 8)
			return 1;
	}
	return 0;
}

static int url_sensitive_param(const char *b, size_t bn) {
	static const char *const names[] = {
	    "token",
	    "api_key",
	    "apikey",
	    "access_token",
	    "refresh_token",
	    "id_token",
	    "signature",
	    "sig",
	    "key",
	    "secret",
	    "password",
	    "x-amz-signature",
	    "x-amz-credential",
	    "x-amz-security-token",
	    NULL,
	};
	if (!mem_find(b, bn, "://"))
		return 0;
	size_t start = 0;
	while (start < bn && b[start] != '?')
		start++;
	if (start == bn)
		return 0;
	for (start++; start < bn;) {
		size_t end = start;
		while (end < bn && b[end] != '&' && b[end] != ';')
			end++;
		size_t eq = start;
		while (eq < end && b[eq] != '=')
			eq++;
		if (eq < end) {
			size_t nn = eq - start, vn = end - eq - 1;
			for (int i = 0; names[i]; i++) {
				if (strlen(names[i]) != nn || !mem_prefix_ci(b + start, nn, names[i]))
					continue;
				if (vn >= 8 && !is_trivial_value(b + eq + 1, vn))
					return 1;
				break;
			}
		}
		start = end + 1;
	}
	return 0;
}

static int conn_string_at(const char *b, size_t bn, size_t i) {
	static const char *const names[] = {
	    "password=", "pwd=", "sslkey=", "sslpassword=", "accountkey=", "sharedaccesskey=", NULL,
	};
	for (int n = 0; names[n]; n++) {
		size_t ln = strlen(names[n]);
		if (mem_prefix_ci(b + i, bn - i, names[n]) && i + ln < bn)
			return 1;
	}
	return 0;
}

static int conn_string_secret(const char *b, size_t bn) {
	if (conn_string_at(b, bn, 0))
		return 1;
	for (size_t i = 0; i < bn; i++) {
		if (b[i] != ';')
			continue;
		size_t j = i + 1;
		while (j < bn && (b[j] == ' ' || b[j] == '\t'))
			j++;
		if (conn_string_at(b, bn, j))
			return 1;
	}
	return 0;
}

static int json_has_key(const char *b, size_t bn, const char *name) {
	size_t nn = strlen(name);
	for (size_t i = 0; i + nn + 2 <= bn; i++) {
		if (b[i] != '"' || b[i + nn + 1] != '"' || memcmp(b + i + 1, name, nn) != 0)
			continue;
		size_t j = i;
		while (j > 0 && isspace((unsigned char)b[j - 1]))
			j--;
		if (j == 0 || (b[j - 1] != '{' && b[j - 1] != ','))
			continue;
		size_t k = i + nn + 2;
		while (k < bn && isspace((unsigned char)b[k]))
			k++;
		if (k < bn && b[k] == ':')
			return 1;
	}
	return 0;
}

static int is_private_jwk(const char *b, size_t bn) {
	return json_has_key(b, bn, "kty") && (json_has_key(b, bn, "d") || json_has_key(b, bn, "k"));
}

static int private_key_material(const char *b, size_t bn) {
	return is_pem_private_n(b, bn) || mem_find(b, bn, "PuTTY-User-Key-File") != NULL ||
	       is_private_jwk(b, bn);
}

static int entropy_secret(const char *b, size_t bn) {
	if (bn < 16)
		return 0;
	if (is_uuid_shape(b, bn) || is_plain_path(b, bn) || mem_find(b, bn, "://"))
		return 0;
	int hex = 1, b64 = 1, tok = 1, slashes = 0;
	for (size_t i = 0; i < bn; i++) {
		unsigned char c = (unsigned char)b[i];
		if (isspace(c))
			return 0;
		if (c == '/' && ++slashes >= 2)
			return 0;
		if (!isxdigit(c))
			hex = 0;
		if (!is_authz_char(c))
			b64 = 0;
		if (!isprint(c) || c == ':')
			tok = 0;
	}
	uint32_t h = shannon_q16(b, bn);
	if (hex)
		return bn >= 32 && h > 196608u;
	if (b64)
		return bn >= 24 && h > 229376u;
	if (tok)
		return bn >= 16 && h > 229376u;
	return 0;
}

const char *value_body(const char *raw, size_t *len) {
	const char *p = raw ? raw : "";
	while (*p == ' ' || *p == '\t')
		p++;
	size_t n = strlen(p);
	if (n >= 2 && (p[0] == '"' || p[0] == '\'' || p[0] == '`') && p[n - 1] == p[0]) {
		if (len)
			*len = n - 2;
		return p + 1;
	}
	if (len)
		*len = n;
	return p;
}

static int is_text_delim(unsigned char c);
static int is_keychar(unsigned char c);
static char *key_run(const char *s, size_t n);
static int should_mask_body(const char *key, const char *b, size_t bn, int deep);

static size_t assign_split(const char *b, size_t bn, char **key) {
	size_t eq = 0;
	*key = NULL;
	while (eq < bn && b[eq] != '=')
		eq++;
	if (eq == bn || eq + 1 == bn)
		return 0;
	size_t ks = eq;
	while (ks > 0 && (isalnum((unsigned char)b[ks - 1]) || b[ks - 1] == '_'))
		ks--;
	*key = key_run(b + ks, eq - ks);
	return *key ? eq + 1 : 0;
}

static int assigned_secret(const char *b, size_t bn) {
	char *key;
	size_t vs = assign_split(b, bn, &key);
	if (!key)
		return 0;
	int hit = should_mask_body(key, b + vs, bn - vs, 0);
	free(key);
	return hit;
}

static int embedded_secret_token(const char *b, size_t bn) {
	size_t p = 0;
	while (p < bn) {
		while (p < bn && is_text_delim((unsigned char)b[p]))
			p++;
		size_t s = p;
		while (p < bn && !is_text_delim((unsigned char)b[p]))
			p++;
		size_t te = p;
		while (te > s && strchr(".,;:)]}\"'", b[te - 1]))
			te--;
		if (te > s && (size_t)(te - s) < bn &&
		    (should_mask_token(b + s, te - s) || assigned_secret(b + s, te - s)))
			return 1;
	}
	return 0;
}

static int should_mask_body(const char *key, const char *b, size_t bn, int deep) {
	if (private_key_material(b, bn))
		return 1;
	if (known_token_prefix(b, bn) || aws_access_key_shape(b, bn))
		return 1;
	if (is_credentialed_url(b, bn))
		return 1;
	if (url_sensitive_param(b, bn))
		return 1;
	if (authorization_value(b, bn))
		return 1;
	if (conn_string_secret(b, bn))
		return 1;
	if (is_jwt_shape(b, bn))
		return 1;
	if (is_pem_public_material(b, bn))
		return 0;
	if (digestish_key_name(key))
		return 0;
	if (webhook_key_name(key) || (strong_secret_key_name(key) && !pathish_key_suffix(key)))
		return !(is_trivial_value(b, bn) || is_plain_path(b, bn));
	if (deep && (assigned_secret(b, bn) || embedded_secret_token(b, bn)))
		return 1;
	if (!suspicious_key_name(key))
		return 0;
	return entropy_secret(b, bn);
}

int should_mask(const char *key, const char *val) {
	if (!val)
		val = "";
	size_t bn;
	const char *b = value_body(val, &bn);
	return should_mask_body(key, b, bn, 1);
}

const char *redact_token_n(const char *b, size_t bn) {
	if (private_key_material(b, bn))
		return "<redacted:private-key>";
	if (is_credentialed_url(b, bn) || url_sensitive_param(b, bn) || conn_string_secret(b, bn))
		return "<redacted:credentials>";
	return "<redacted>";
}

const char *redact_token(const char *key, const char *val) {
	(void)key;
	if (!val)
		val = "";
	size_t bn;
	const char *b = value_body(val, &bn);
	return redact_token_n(b, bn);
}

#define TOKEN_MIN 12

static int all_lower_alpha(const char *b, size_t bn) {
	for (size_t i = 0; i < bn; i++) {
		if (b[i] < 'a' || b[i] > 'z')
			return 0;
	}
	return 1;
}

static int short_secret_shape(const char *b, size_t bn) {
	int lower = 0, upper = 0, digit = 0, other = 0;
	for (size_t i = 0; i < bn; i++) {
		unsigned char c = (unsigned char)b[i];
		if (islower(c))
			lower = 1;
		else if (isupper(c))
			upper = 1;
		else if (isdigit(c))
			digit = 1;
		else
			other = 1;
	}
	if (lower + upper + digit + other < 2)
		return 0;
	return shannon_q16(b, bn) >= (5u << 15);
}

int literal_maskable(const char *key, const char *val) {
	if (!val)
		return 0;
	size_t bn;
	const char *b = value_body(val, &bn);
	if (bn < 6)
		return 0;
	if (bn < 8 && !short_secret_shape(b, bn))
		return 0;
	if (is_trivial_value(b, bn) || is_plain_path(b, bn))
		return 0;
	if (bn < 16 && all_lower_alpha(b, bn))
		return 0;
	return should_mask(key, val);
}

int should_mask_token(const char *s, size_t n) {
	if (n < TOKEN_MIN)
		return 0;
	return private_key_material(s, n) || known_token_prefix(s, n) || aws_access_key_shape(s, n) ||
	       is_credentialed_url(s, n) || url_sensitive_param(s, n) || authorization_value(s, n) ||
	       conn_string_secret(s, n) || is_jwt_shape(s, n);
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

#define PEM_BEGIN "-----BEGIN "
#define PRIVKEY_TOKEN "<redacted:private-key>"
#define PEM_CARRY_MAX 512

static int pem_begin_label(const char *in, size_t n, char *label, size_t cap, size_t *begin_off,
                           size_t *begin_end) {
	const char *p = mem_find(in, n, PEM_BEGIN);
	if (!p)
		return 0;
	const char *s = p + sizeof(PEM_BEGIN) - 1;
	size_t left = (size_t)((in + n) - s);
	const char *e = mem_find(s, left, "-----");
	if (!e || e == s)
		return 0;
	if (begin_off)
		*begin_off = (size_t)(p - in);
	if (begin_end)
		*begin_end = (size_t)(e + 5 - in);
	size_t ln = (size_t)(e - s);
	if (ln >= cap) {
		label[0] = '\0';
		return mem_find(s, ln, "PRIVATE KEY") ? 2 : 0;
	}
	memcpy(label, s, ln);
	label[ln] = '\0';
	return 1;
}

/* RFC 7468 section 3: a pre-encapsulation boundary ends its line. */
static int pem_begin_ends_line(const char *in, size_t n, size_t begin_end) {
	for (size_t i = begin_end; i < n; i++) {
		if (!isspace((unsigned char)in[i]))
			return 0;
	}
	return 1;
}

static const char *pem_end_at(const char *in, size_t n, const char *label) {
	if (!*label) {
		const char *p = mem_find(in, n, "-----END ");
		if (!p)
			return NULL;
		size_t left = (size_t)((in + n) - p);
		const char *e = mem_find(p + 9, left - 9, "-----");
		if (!e || !mem_find(p + 9, (size_t)(e - (p + 9)), "PRIVATE KEY"))
			return NULL;
		return e + 5;
	}
	char end[256];
	int k = snprintf(end, sizeof(end), "-----END %s-----", label);
	if (k < 0 || (size_t)k >= sizeof(end))
		return NULL;
	const char *p = mem_find(in, n, end);
	return p ? p + k : NULL;
}

static int is_text_delim(unsigned char c) {
	return isspace(c) || c == ',' || c == ';' || c == '\'' || c == '"' || c == '(' || c == ')' ||
	       c == '[' || c == ']' || c == '{' || c == '}' || c == '<' || c == '>' || c == '`';
}

static int is_keychar(unsigned char c) { return isalnum(c) || c == '_' || c == '-'; }

static size_t lead_ws_n(const char *in, size_t n) {
	size_t i = 0;
	while (i < n && (in[i] == ' ' || in[i] == '\t'))
		i++;
	return i;
}

static int pem_body_line(const char *in, size_t n) {
	while (n > 0 && (in[n - 1] == '\r' || in[n - 1] == '\n'))
		n--;
	size_t i = lead_ws_n(in, n);
	if (n - i < 16)
		return 0;
	for (size_t j = i; j < n; j++) {
		unsigned char c = (unsigned char)in[j];
		if (!isalnum(c) && c != '+' && c != '/' && c != '=')
			return 0;
	}
	return 1;
}

static int eq_ci_n(const char *s, size_t n, const char *lit) {
	if (strlen(lit) != n)
		return 0;
	for (size_t i = 0; i < n; i++) {
		if (toupper((unsigned char)s[i]) != toupper((unsigned char)lit[i]))
			return 0;
	}
	return 1;
}

static int authz_run(const char *s, size_t n) {
	if (n < 20)
		return 0;
	for (size_t i = 0; i < n; i++) {
		if (!is_authz_char((unsigned char)s[i]))
			return 0;
	}
	return 1;
}

static int unbalanced_closer(const char *v, size_t n) {
	long curly = 0, square = 0;
	for (size_t i = 0; i < n; i++) {
		if (v[i] == '{')
			curly++;
		else if (v[i] == '}')
			curly--;
		else if (v[i] == '[')
			square++;
		else if (v[i] == ']')
			square--;
	}
	return curly < 0 || square < 0;
}

static int mask_assignment(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len) {
	size_t i = lead_ws_n(in, inlen);
	int quoted_key = 0;
	if (i < inlen && in[i] == '"') {
		quoted_key = 1;
		i++;
	}

	size_t ks = i;
	while (i < inlen && is_keychar((unsigned char)in[i]))
		i++;
	size_t ke = i;
	if (ke == ks)
		return 0;
	if (quoted_key) {
		if (i >= inlen || in[i] != '"')
			return 0;
		i++;
	}

	if (i >= inlen)
		return 0;
	if (in[i] == '=') {
		if (quoted_key)
			return 0;
		i++;
	} else if (in[i] == ':') {
		if (!quoted_key && !(i + 1 < inlen && (in[i + 1] == ' ' || in[i + 1] == '\t')))
			return 0;
		i++;
	} else {
		return 0;
	}

	size_t vs = i;
	while (vs < inlen && (in[vs] == ' ' || in[vs] == '\t'))
		vs++;

	size_t ve = inlen;
	for (int trimmed = 1; trimmed && ve > vs;) {
		trimmed = 0;
		while (ve > vs && (in[ve - 1] == ' ' || in[ve - 1] == '\t' || in[ve - 1] == '\r')) {
			ve--;
			trimmed = 1;
		}
		if (ve > vs && in[ve - 1] == ',') {
			ve--;
			trimmed = 1;
			continue;
		}
		if (ve > vs && (in[ve - 1] == '}' || in[ve - 1] == ']') &&
		    unbalanced_closer(in + vs, ve - vs)) {
			ve--;
			trimmed = 1;
		}
	}
	if (ve == vs)
		return 0;

	size_t kl = ke - ks;
	char *kbuf = xmalloc(kl + 1);
	for (size_t j = 0; j < kl; j++)
		kbuf[j] = in[ks + j] == '-' ? '_' : in[ks + j];
	kbuf[kl] = '\0';

	size_t vl = ve - vs;
	char *vbuf = xmalloc(vl + 1);
	memcpy(vbuf, in + vs, vl);
	vbuf[vl] = '\0';

	int q = vl >= 2 && (vbuf[0] == '"' || vbuf[0] == '\'') && vbuf[vl - 1] == vbuf[0];
	int spaced = memchr(vbuf, ' ', vl) != NULL || memchr(vbuf, '\t', vl) != NULL;
	int masked = (spaced && !q) ? authorization_value(vbuf, vl) : should_mask(kbuf, vbuf);

	if (masked) {
		buf_put(out, outcap, len, in, vs);
		if (q)
			buf_put(out, outcap, len, vbuf, 1);
		const char *tok = redact_token(kbuf, vbuf);
		buf_put(out, outcap, len, tok, strlen(tok));
		if (q)
			buf_put(out, outcap, len, vbuf, 1);
		buf_put(out, outcap, len, in + ve, inlen - ve);
	}

	free(vbuf);
	free(kbuf);
	return masked;
}

static char *key_run(const char *s, size_t n) {
	if (!n)
		return NULL;
	if (!isalpha((unsigned char)s[0]) && s[0] != '_')
		return NULL;
	for (size_t i = 0; i < n; i++) {
		if (!is_keychar((unsigned char)s[i]))
			return NULL;
	}
	char *k = xmalloc(n + 1);
	for (size_t i = 0; i < n; i++)
		k[i] = s[i] == '-' ? '_' : s[i];
	k[n] = '\0';
	return k;
}

static int keyed_mask(const char *key, const char *v, size_t vn) {
	char *vbuf = xmalloc(vn + 1);
	memcpy(vbuf, v, vn);
	vbuf[vn] = '\0';
	int hit = should_mask(key, vbuf);
	free(vbuf);
	return hit;
}

static void mask_tokens(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len) {
	size_t p = 0;
	int scheme = 0;
	char *pend = NULL;

	while (p < inlen) {
		if (is_text_delim((unsigned char)in[p])) {
			buf_put(out, outcap, len, in + p, 1);
			p++;
			continue;
		}

		size_t s = p;
		while (p < inlen && !is_text_delim((unsigned char)in[p]))
			p++;
		size_t e = p, te = e;
		while (te > s && strchr(".,;:)]}\"'", in[te - 1]))
			te--;

		size_t eq = s;
		while (eq < te && in[eq] != '=')
			eq++;

		char *key = eq < te ? key_run(in + s, eq - s) : NULL;
		size_t ms = key ? eq + 1 : s;
		const char *kn = key ? key : pend;
		int bare = key && te == ms;

		int hit = kn && te > ms && keyed_mask(kn, in + ms, te - ms);
		if (!hit) {
			ms = s;
			hit = te > s &&
			      (should_mask_token(in + s, te - s) || (scheme && authz_run(in + s, te - s)));
		}
		if (!hit && !key && te > s) {
			char *tail;
			size_t vs = assign_split(in + s, te - s, &tail);
			if (tail) {
				hit = keyed_mask(tail, in + s + vs, te - s - vs);
				if (hit)
					ms = s + vs;
				free(tail);
			}
		}

		if (hit) {
			const char *tok = redact_token_n(in + ms, te - ms);
			buf_put(out, outcap, len, in + s, ms - s);
			buf_put(out, outcap, len, tok, strlen(tok));
			buf_put(out, outcap, len, in + te, e - te);
		} else {
			buf_put(out, outcap, len, in + s, e - s);
		}

		scheme = !hit && (eq_ci_n(in + s, te - s, "Bearer") || eq_ci_n(in + s, te - s, "Basic"));
		free(pend);
		pend = NULL;
		if (!hit && bare) {
			pend = key;
			key = NULL;
		}
		free(key);
	}

	free(pend);
}

int scan_text_line(const char *in, size_t inlen, char **out, size_t *outcap, size_t *outlen,
                   int *pem_open, char *pem_label, size_t pem_label_cap) {
	size_t len = 0;
	*outlen = 0;

	if (*pem_open) {
		if (*pem_open <= PEM_CARRY_MAX)
			++(*pem_open);
		const char *tail = pem_end_at(in, inlen, pem_label);
		if (tail) {
			*pem_open = 0;
			size_t tn = (size_t)(in + inlen - tail);
			if (tn == 0)
				return 0;
			buf_put(out, outcap, &len, tail, tn);
			buf_need(out, outcap, len + 1);
			(*out)[len] = '\0';
			*outlen = len;
			return 1;
		}
		if (*pem_open > PEM_CARRY_MAX && !pem_body_line(in, inlen))
			*pem_open = 0;
		return 0;
	}

	size_t w = lead_ws_n(in, inlen);
	size_t boff = 0, bend = 0;
	int lab = pem_begin_label(in, inlen, pem_label, pem_label_cap, &boff, &bend);
	int begins = lab == 2 || (lab == 1 && strstr(pem_label, "PRIVATE KEY") != NULL);

	if (begins) {
		const char *tail = pem_end_at(in + bend, inlen - bend, pem_label);
		if (!tail && pem_begin_ends_line(in, inlen, bend))
			*pem_open = 1;
		buf_put(out, outcap, &len, in, boff);
		buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
		if (tail)
			buf_put(out, outcap, &len, tail, (size_t)(in + inlen - tail));
	} else if (mem_prefix(in + w, inlen - w, "PuTTY-User-Key-File")) {
		buf_put(out, outcap, &len, in, w);
		buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
	} else if (!mask_assignment(in, inlen, out, outcap, &len)) {
		mask_tokens(in, inlen, out, outcap, &len);
	}

	buf_need(out, outcap, len + 1);
	(*out)[len] = '\0';
	*outlen = len;
	return 1;
}
