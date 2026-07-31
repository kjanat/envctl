#define _GNU_SOURCE
#include "redact.h"

#include "agent.h"
#include "entropy.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Segment boundaries are '_' and the lower-to-upper transition of camelCase,
 * so secretAccessKey and SECRET_ACCESS_KEY split the same way. */
static int seg_break_before(const char *k, const char *p) {
	if (p == k || p[-1] == '_')
		return 1;
	return isupper((unsigned char)p[0]) && !isupper((unsigned char)p[-1]);
}

static int seg_break_after(const char *p, size_t n) {
	if (p[n] == '\0' || p[n] == '_')
		return 1;
	return isupper((unsigned char)p[n]) && !isupper((unsigned char)p[n - 1]);
}

static int paranoid;

void redact_set_paranoid(int on) { paranoid = on; }

/* Case-insensitive segment match: (^|_|camel)seg(_|camel|$). */
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
		if (seg_break_before(k, p) && seg_break_after(p, n))
			return 1;
	}
	return 0;
}

/* Trailing segment with something before it: the camelCase twin of "_SEG". */
static int final_segment_ci(const char *k, const char *seg) {
	size_t kn = strlen(k), n = strlen(seg);
	if (!n || kn <= n)
		return 0;
	const char *p = k + kn - n;
	for (size_t i = 0; i < n; i++) {
		if (toupper((unsigned char)p[i]) != toupper((unsigned char)seg[i]))
			return 0;
	}
	return seg_break_before(k, p);
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
	return final_segment_ci(k, "FILE") || final_segment_ci(k, "PATH") ||
	       final_segment_ci(k, "ENDPOINT") || final_segment_ci(k, "NAME") ||
	       final_segment_ci(k, "VERSION") || final_segment_ci(k, "LENGTH") ||
	       final_segment_ci(k, "DIR") || final_segment_ci(k, "HOME");
}

static int identifier_key_suffix(const char *k) { return final_segment_ci(k, "ID"); }

static int webhook_key_name(const char *k) {
	return has_segment_ci(k, "WEBHOOK") && !identifier_key_suffix(k) &&
	       !final_segment_ci(k, "NAME");
}

static int strong_secret_key_name(const char *k) {
	if (webhook_key_name(k))
		return 1;
	if (has_segment_ci(k, "PASSWORD") || has_segment_ci(k, "PASSWD") || has_segment_ci(k, "PWD") ||
	    has_segment_ci(k, "PASS") || has_segment_ci(k, "PASSPHRASE") ||
	    has_segment_ci(k, "SECRET") || has_segment_ci(k, "TOKEN") ||
	    has_segment_ci(k, "CREDENTIAL") || has_segment_ci(k, "CREDENTIALS") ||
	    has_segment_ci(k, "DSN") || has_segment_ci(k, "KEYSTORE") || has_segment_ci(k, "PKCS12") ||
	    has_segment_ci(k, "P12") || has_segment_ci(k, "PFX") || has_segment_ci(k, "MNEMONIC"))
		return 1;
	if ((has_segment_ci(k, "DATABASE") || has_segment_ci(k, "DB")) && has_segment_ci(k, "URL"))
		return 1;
	if (has_segment_ci(k, "CONNECTION") && has_segment_ci(k, "STRING"))
		return 1;
	if (has_segment_ci(k, "SEED") && has_segment_ci(k, "PHRASE"))
		return 1;
	if (has_segment_ci(k, "KEY") &&
	    (has_segment_ci(k, "API") || has_segment_ci(k, "ACCESS") || has_segment_ci(k, "SECRET") ||
	     has_segment_ci(k, "PRIVATE") || has_segment_ci(k, "AUTH") ||
	     has_segment_ci(k, "SIGNING") || has_segment_ci(k, "ENCRYPTION") ||
	     has_segment_ci(k, "MASTER") || has_segment_ci(k, "CLIENT") ||
	     has_segment_ci(k, "SESSION") || has_segment_ci(k, "APP")))
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
	       has_segment_ci(k, "OAUTH") || has_segment_ci(k, "SESSION") ||
	       has_segment_ci(k, "COOKIE");
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
		if (kn == wn || seg_break_before(k, k + kn - wn))
			return 1;
	}
	return 0;
}

static int is_trivial_word(const char *v, size_t n) {
	static const char *const trivial[] = {
	    "",           "0",           "1",    "true",    "false",     "yes",
	    "no",         "on",          "off",  "debug",   "info",      "warn",
	    "error",      "trace",       "null", "none",    "localhost", "127.0.0.1",
	    "production", "development", "test", "staging", "changeme",  NULL,
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
	return 0;
}

static int is_trivial_value(const char *v, size_t n) {
	if (is_trivial_word(v, n))
		return 1;
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

static size_t lead_ws_n(const char *in, size_t n);

static int standalone_public_pem(const char *b, size_t bn) {
	static const char *const pub[] = {
	    "CERTIFICATE REQUEST", "CERTIFICATE", "PUBLIC KEY", "RSA PUBLIC KEY", "EC PUBLIC KEY", NULL,
	};
	size_t i = lead_ws_n(b, bn);
	if (!mem_prefix(b + i, bn - i, "-----BEGIN "))
		return 0;
	const char *s = b + i + 11;
	size_t left = bn - i - 11;
	const char *e = mem_find(s, left, "-----");
	if (!e)
		return 0;
	size_t ln = (size_t)(e - s);
	for (int k = 0; pub[k]; k++) {
		if (strlen(pub[k]) != ln || memcmp(s, pub[k], ln) != 0)
			continue;
		char end[64];
		int m = snprintf(end, sizeof(end), "-----END %s-----", pub[k]);
		return m > 0 && (size_t)m < sizeof(end) && mem_find(e, (size_t)(b + bn - e), end) != NULL;
	}
	return 0;
}

/* Go's DSN grammar wraps the host in a protocol instead of a scheme:
 * user:pass@tcp(host:port)/db. */
static int go_dsn_host(const char *b, size_t bn, const char *at) {
	size_t left = (size_t)(b + bn - (at + 1));
	return mem_prefix(at + 1, left, "tcp(") || mem_prefix(at + 1, left, "unix(");
}

static int is_credentialed_url(const char *b, size_t bn) {
	const char *scheme = mem_find(b, bn, "://");
	const char *userinfo;
	int schemed = scheme != NULL, relative = 0;
	if (schemed) {
		userinfo = scheme + 3;
	} else if (mem_prefix(b, bn, "//")) {
		relative = 1;
		userinfo = b + 2;
	} else {
		userinfo = b;
	}
	const char *end = b + bn;
	const char *at = NULL;
	int colon = 0;
	for (const char *p = userinfo; p < end; p++) {
		if (*p == '/')
			break;
		if (*p == '@') {
			at = p;
			break;
		}
		if (*p == ':')
			colon = 1;
	}
	if (!at || at == userinfo)
		return 0;
	if (colon)
		return schemed || relative || go_dsn_host(b, bn, at);
	/* Token-as-username: git remotes print PAT-embedded URLs this way. A real
	 * login name before '@' is short and rarely worth masking. */
	size_t un = (size_t)(at - userinfo);
	return schemed && un >= 8 && !is_trivial_value(userinfo, un);
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
	    "SG.",         "LS0tLS1",  NULL,
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

static int authorization_value(const char *b, size_t bn, int explicit_key) {
	static const char *const scheme[] = {"Bearer", "Basic", NULL};
	size_t i = 0;
	int explicit = explicit_key;
	if (mem_prefix_ci(b, bn, "Authorization:")) {
		explicit = 1;
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
		size_t min = explicit ? (s == 1 ? 4u : 1u) : 8u;
		if (k - j >= min)
			return 1;
	}
	return 0;
}

/* A webhook whose URL is itself the credential. The trailing secret segment
 * must be present, so a bare host stays visible. */
static int is_webhook_url_shape(const char *b, size_t bn) {
	static const char *const hosts[] = {
	    "hooks.slack.com/services/",
	    "discord.com/api/webhooks/",
	    "discordapp.com/api/webhooks/",
	    NULL,
	};
	for (int i = 0; hosts[i]; i++) {
		const char *p = mem_find(b, bn, hosts[i]);
		if (!p)
			continue;
		const char *tail = p + strlen(hosts[i]);
		const char *end = tail;
		while (end < b + bn && *end != '?' && *end != '#')
			end++;
		const char *last = NULL;
		for (const char *q = tail; q < end; q++) {
			if (*q == '/')
				last = q;
		}
		if (last && last != tail && (size_t)(end - last - 1) >= 8)
			return 1;
	}
	return 0;
}

/* Query pairs with no scheme and no '?' to anchor on; Azure SAS tokens are
 * handed around in this form. */
static int query_string_shape(const char *b, size_t bn) {
	size_t i = 0;
	int pairs = 0;
	while (i < bn) {
		size_t ns = i;
		while (i < bn && b[i] != '=' && b[i] != '&' && b[i] != ';')
			i++;
		if (i == bn || b[i] != '=' || i == ns)
			return 0;
		for (size_t j = ns; j < i; j++) {
			unsigned char c = (unsigned char)b[j];
			if (!isalnum(c) && c != '_' && c != '-' && c != '.')
				return 0;
		}
		while (i < bn && b[i] != '&' && b[i] != ';')
			i++;
		pairs++;
		if (i < bn)
			i++;
	}
	return pairs > 0;
}

static int url_sensitive_param(const char *b, size_t bn) {
	static const struct {
		const char *name;
		int bare; /* matchable with no scheme to anchor on */
	} names[] = {
	    {"token", 1},
	    {"api_key", 1},
	    {"apikey", 1},
	    {"access_token", 1},
	    {"refresh_token", 1},
	    {"id_token", 1},
	    {"signature", 1},
	    {"sig", 1},
	    {"key", 0},
	    {"secret", 1},
	    {"password", 1},
	    {"x-amz-signature", 1},
	    {"x-amz-credential", 1},
	    {"x-amz-security-token", 1},
	    {NULL, 0},
	};
	int schemed = mem_find(b, bn, "://") != NULL;
	size_t start = 0;
	if (schemed) {
		while (start < bn && b[start] != '?')
			start++;
		if (start == bn)
			return 0;
		start++;
	} else if (!query_string_shape(b, bn)) {
		return 0;
	}
	while (start < bn) {
		size_t end = start;
		while (end < bn && b[end] != '&' && b[end] != ';')
			end++;
		size_t eq = start;
		while (eq < end && b[eq] != '=')
			eq++;
		if (eq < end) {
			size_t nn = eq - start, vn = end - eq - 1;
			for (int i = 0; names[i].name; i++) {
				if (!schemed && !names[i].bare)
					continue;
				if (strlen(names[i].name) != nn || !mem_prefix_ci(b + start, nn, names[i].name))
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

static int json_private_object(const char *in, size_t n);

static int is_private_jwk(const char *b, size_t bn) { return json_private_object(b, bn); }

static int private_key_material(const char *b, size_t bn) {
	return is_pem_private_n(b, bn) || mem_find(b, bn, "PuTTY-User-Key-File") != NULL ||
	       is_private_jwk(b, bn);
}

/* Strict padded base64: '+/' alphabet only, 4-byte alignment, and one or two
 * '=' confined to the tail. Distinguishes encoded data from path-like values. */
static int strict_b64_padded(const char *b, size_t bn) {
	if (bn < 4 || bn % 4 || b[bn - 1] != '=')
		return 0;
	size_t body = bn - 1;
	if (b[body - 1] == '=')
		body--;
	for (size_t i = 0; i < body; i++) {
		unsigned char c = (unsigned char)b[i];
		if (!isalnum(c) && c != '+' && c != '/')
			return 0;
	}
	return 1;
}

/* Unpadded standard base64. Length must be one base64 can emit, and separator
 * slashes must be too sparse to be a path: they fall at 1-in-64 by chance
 * here, against roughly 1-in-7 in a directory path. Adjacent slashes cannot
 * be separators, so a run counts for nothing. */
static int strict_b64_unpadded(const char *b, size_t bn) {
	if (bn < 24 || bn % 4 == 1)
		return 0;
	size_t seps = 0;
	for (size_t i = 0; i < bn; i++) {
		unsigned char c = (unsigned char)b[i];
		if (!isalnum(c) && c != '+' && c != '/')
			return 0;
		if (c == '/' && (i == 0 || b[i - 1] != '/') && (i + 1 == bn || b[i + 1] != '/'))
			seps++;
	}
	return seps * 16 <= bn;
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
		if (c == '/')
			slashes++;
		if (!isxdigit(c))
			hex = 0;
		if (!is_authz_char(c))
			b64 = 0;
		if (!isprint(c) || c == ':')
			tok = 0;
	}
	/* Slashes read as a relative path unless the value is strict base64. */
	if (slashes >= 2 && !strict_b64_padded(b, bn) && !strict_b64_unpadded(b, bn))
		return 0;
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
	if (url_sensitive_param(b, bn) || is_webhook_url_shape(b, bn))
		return 1;
	int authz_key = strlen(key) == strlen("Authorization") && ends_with_ci(key, "Authorization");
	if (authorization_value(b, bn, authz_key))
		return 1;
	if (conn_string_secret(b, bn))
		return 1;
	if (is_jwt_shape(b, bn))
		return 1;
	if (digestish_key_name(key))
		return 0;
	if (webhook_key_name(key) || (strong_secret_key_name(key) && !pathish_key_suffix(key)))
		return !(is_trivial_value(b, bn) || is_plain_path(b, bn));
	if (standalone_public_pem(b, bn))
		return 0;
	if (deep && (assigned_secret(b, bn) || embedded_secret_token(b, bn)))
		return 1;
	if (!suspicious_key_name(key) && !paranoid)
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
	if (is_credentialed_url(b, bn) || url_sensitive_param(b, bn) || conn_string_secret(b, bn) ||
	    is_webhook_url_shape(b, bn))
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
	if (bn < 16 && all_lower_alpha(b, bn) && !strong_secret_key_name(key))
		return 0;
	return should_mask(key, val);
}

/* A KEY=VALUE token was already judged with its key in hand, so the keyless
 * floor must not overrule the digest and path guards that spared it. */
static int assignment_shaped(const char *b, size_t bn) {
	char *key = NULL;
	assign_split(b, bn, &key);
	int shaped = key != NULL;
	free(key);
	return shaped;
}

int should_mask_token(const char *s, size_t n) {
	if (n < TOKEN_MIN)
		return 0;
	return private_key_material(s, n) || known_token_prefix(s, n) || aws_access_key_shape(s, n) ||
	       is_credentialed_url(s, n) || url_sensitive_param(s, n) || authorization_value(s, n, 0) ||
	       conn_string_secret(s, n) || is_jwt_shape(s, n) || is_webhook_url_shape(s, n) ||
	       (paranoid && !assignment_shaped(s, n) && entropy_secret(s, n));
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

static int authz_run(const char *s, size_t n, size_t min) {
	if (n < min)
		return 0;
	for (size_t i = 0; i < n; i++) {
		if (!is_authz_char((unsigned char)s[i]))
			return 0;
	}
	return 1;
}

static int unbalanced_closer(const char *v, size_t n) {
	long curly = 0, square = 0;
	int string = 0, escape = 0;
	for (size_t i = 0; i < n; i++) {
		if (string) {
			if (escape)
				escape = 0;
			else if (v[i] == '\\')
				escape = 1;
			else if (v[i] == '"')
				string = 0;
			continue;
		}
		if (v[i] == '"')
			string = 1;
		else if (v[i] == '{')
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

static const char *unescaped_quote(const char *s, size_t n, char quote, int *backslash) {
	int odd = backslash ? *backslash : 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '\\') {
			odd = !odd;
			continue;
		}
		if (s[i] == quote && !odd) {
			if (backslash)
				*backslash = 0;
			return s + i;
		}
		odd = 0;
	}
	if (backslash)
		*backslash = odd;
	return NULL;
}

static int mask_assignment(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len,
                           ScanState *st) {
	size_t i = lead_ws_n(in, inlen);
	int quoted_key = 0;
	int colon_separator = 0;
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

	size_t gap = i;
	while (gap < inlen && (in[gap] == ' ' || in[gap] == '\t'))
		gap++;
	if (gap < inlen && in[gap] == '=')
		i = gap;

	if (i >= inlen)
		return 0;
	if (in[i] == '=') {
		if (quoted_key)
			return 0;
		i++;
	} else if (in[i] == ':') {
		if (!quoted_key && !(i + 1 < inlen && (in[i + 1] == ' ' || in[i + 1] == '\t')))
			return 0;
		colon_separator = 1;
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
	if (colon_separator && !quoted_key && eq_ci_n(kbuf, kl, "Authorization") &&
	    mem_prefix_ci(in + vs, ve - vs, "Basic ")) {
		free(kbuf);
		return 0;
	}

	size_t vl = ve - vs;
	char *vbuf = xmalloc(vl + 1);
	memcpy(vbuf, in + vs, vl);
	vbuf[vl] = '\0';

	int quoted = vbuf[0] == '"' || vbuf[0] == '\'';
	int parity = 0;
	const char *close =
	    quoted && vl > 1 ? unescaped_quote(vbuf + 1, vl - 1, vbuf[0], &parity) : NULL;
	int q = close == vbuf + vl - 1;
	int uq = quoted && !close;
	int spaced = memchr(vbuf, ' ', vl) != NULL || memchr(vbuf, '\t', vl) != NULL;
	int masked = should_mask(kbuf, vbuf);
	(void)spaced;

	if (masked && uq && st) {
		buf_put(out, outcap, len, in, vs + 1);
		const char *tok = redact_token(kbuf, vbuf);
		buf_put(out, outcap, len, tok, strlen(tok));
		buf_put(out, outcap, len, vbuf, 1);
		st->quote_ch = vbuf[0];
		st->quote_n = 0;
		st->quote_backslash = parity;
	} else if (masked) {
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

static int hex_value(unsigned char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static char *json_key_decode(const char *s, size_t n, size_t *decoded_len) {
	char *decoded = xmalloc(n + 1);
	size_t out = 0;
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)s[i++];
		if (c > 0x7f || c < 0x20) {
			free(decoded);
			return NULL;
		}
		if (c == '\\') {
			if (i >= n) {
				free(decoded);
				return NULL;
			}
			c = (unsigned char)s[i++];
			switch (c) {
			case '"':
			case '\\':
			case '/':
				break;
			case 'b':
				c = '\b';
				break;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case 'u': {
				if (i + 4 > n) {
					free(decoded);
					return NULL;
				}
				unsigned value = 0;
				for (size_t j = 0; j < 4; j++) {
					int digit = hex_value((unsigned char)s[i + j]);
					if (digit < 0) {
						free(decoded);
						return NULL;
					}
					value = value * 16u + (unsigned)digit;
				}
				if (value > 0x7fu) {
					free(decoded);
					return NULL;
				}
				c = (unsigned char)value;
				i += 4;
				break;
			}
			default:
				free(decoded);
				return NULL;
			}
		}
		decoded[out++] = (char)c;
	}
	decoded[out] = '\0';
	*decoded_len = out;
	return decoded;
}

static int json_whitespace(unsigned char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int mask_json_pair(const char *in, size_t inlen, size_t *p, char **out, size_t *outcap,
                          size_t *len) {
	if (in[*p] != '"')
		return 0;
	int parity = 0;
	const char *key_end = unescaped_quote(in + *p + 1, inlen - *p - 1, '"', &parity);
	if (!key_end)
		return 0;
	size_t ke = (size_t)(key_end - in);
	size_t colon = ke + 1;
	while (colon < inlen && json_whitespace((unsigned char)in[colon]))
		colon++;
	if (colon >= inlen || in[colon] != ':')
		return 0;
	size_t quote = colon + 1;
	while (quote < inlen && json_whitespace((unsigned char)in[quote]))
		quote++;
	if (quote >= inlen || in[quote] != '"')
		return 0;

	size_t decoded_len = 0;
	char *decoded = json_key_decode(in + *p + 1, ke - *p - 1, &decoded_len);
	if (!decoded)
		return 0;
	char *key = key_run(decoded, decoded_len);
	free(decoded);
	if (!key)
		return 0;
	parity = 0;
	const char *value_end = unescaped_quote(in + quote + 1, inlen - quote - 1, '"', &parity);
	if (!value_end) {
		free(key);
		return 0;
	}
	size_t ve = (size_t)(value_end - in);
	int hit = ve > quote + 1 && keyed_mask(key, in + quote + 1, ve - quote - 1);
	free(key);
	if (!hit)
		return 0;

	buf_put(out, outcap, len, in + *p, quote + 1 - *p);
	const char *tok = redact_token_n(in + quote + 1, ve - quote - 1);
	buf_put(out, outcap, len, tok, strlen(tok));
	buf_put(out, outcap, len, "\"", 1);
	*p = ve + 1;
	return 1;
}

static void mask_tokens(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len,
                        ScanState *st) {
	size_t p = 0;
	size_t scheme = 0;
	char *pend = NULL;

	while (p < inlen) {
		if (mask_json_pair(in, inlen, &p, out, outcap, len)) {
			free(pend);
			pend = NULL;
			scheme = 0;
			continue;
		}
		if (is_text_delim((unsigned char)in[p])) {
			if (pend && (in[p] == '"' || in[p] == '\'')) {
				char qc = in[p];
				const char *cl = p + 1 < inlen ? memchr(in + p + 1, qc, inlen - p - 1) : NULL;
				if (cl) {
					size_t is = p + 1, ie = (size_t)(cl - in);
					if (ie > is && keyed_mask(pend, in + is, ie - is)) {
						const char *tok = redact_token_n(in + is, ie - is);
						buf_put(out, outcap, len, &qc, 1);
						buf_put(out, outcap, len, tok, strlen(tok));
						buf_put(out, outcap, len, &qc, 1);
						p = ie + 1;
						free(pend);
						pend = NULL;
						scheme = 0;
						continue;
					}
				} else {
					size_t is = p + 1;
					int hot = is < inlen ? keyed_mask(pend, in + is, inlen - is)
					                     : strong_secret_key_name(pend);
					if (hot) {
						const char *tok =
						    is < inlen ? redact_token_n(in + is, inlen - is) : "<redacted>";
						buf_put(out, outcap, len, &qc, 1);
						buf_put(out, outcap, len, tok, strlen(tok));
						buf_put(out, outcap, len, &qc, 1);
						if (st) {
							st->quote_ch = qc;
							st->quote_n = 0;
						}
						free(pend);
						pend = NULL;
						p = inlen;
						continue;
					}
				}
			}
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
		/* A parsed assignment whose value is a placeholder word stays plain
		 * prose: without this, PASSWORD=changeme re-enters the shape
		 * detectors as one token and conn_string_secret masks it. Word
		 * placeholders only — a short numeric may be a real PIN. */
		int trivial_kv = key && te > ms && is_trivial_word(in + ms, te - ms);
		if (!hit && !trivial_kv) {
			ms = s;
			hit = te > s && (should_mask_token(in + s, te - s) ||
			                 (scheme && authz_run(in + s, te - s, scheme)));
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

		int authz_ctx = pend && eq_ci_n(pend, strlen(pend), "Authorization");
		int bearer = eq_ci_n(in + s, te - s, "Bearer");
		int basic = eq_ci_n(in + s, te - s, "Basic");
		scheme = !hit && (bearer || basic) ? (authz_ctx ? (basic ? 4 : 8) : 20) : 0;
		free(pend);
		pend = NULL;
		if (!hit && bare) {
			pend = key;
			key = NULL;
		} else if (!hit && !key && e == te + 1 && in[te] == ':') {
			pend = key_run(in + s, te - s);
		}
		free(key);
	}

	free(pend);
}

static int find_private_begin(const char *in, size_t n, char *label, size_t cap, size_t *boff,
                              size_t *bend) {
	size_t from = 0;
	while (from < n) {
		size_t o = 0, e = 0;
		int lab = pem_begin_label(in + from, n - from, label, cap, &o, &e);
		if (!lab)
			return 0;
		if (lab == 2 || strstr(label, "PRIVATE KEY") != NULL) {
			*boff = from + o;
			*bend = from + e;
			return 1;
		}
		from += o + 1;
	}
	return 0;
}

#define JSON_CARRY_MAX (1024u * 1024u)
#define JSON_LINE_MAX 512u
#define PUTTY_RECOVERY_MAX 512u

enum {
	PUTTY_NONE,
	PUTTY_PUBLIC,
	PUTTY_PUBLIC_BODY,
	PUTTY_EXPECT_PRIVATE,
	PUTTY_PRIVATE,
	PUTTY_EXPECT_MAC,
};

static size_t json_object_end(const char *in, size_t n, size_t start) {
	long depth = 0;
	int string = 0, escape = 0;
	for (size_t i = start; i < n; i++) {
		if (string) {
			if (escape)
				escape = 0;
			else if (in[i] == '\\')
				escape = 1;
			else if (in[i] == '"')
				string = 0;
			continue;
		}
		if (in[i] == '"')
			string = 1;
		else if (in[i] == '{')
			depth++;
		else if (in[i] == '}' && depth > 0 && --depth == 0)
			return i + 1;
	}
	return 0;
}

static int json_string_eq(const char *s, size_t n, const char *name) {
	size_t decoded_len = 0;
	char *decoded = json_key_decode(s, n, &decoded_len);
	if (!decoded)
		return 0;
	size_t name_len = strlen(name);
	int equal = decoded_len == name_len && memcmp(decoded, name, name_len) == 0;
	free(decoded);
	return equal;
}

static int json_private_object(const char *in, size_t n) {
	long depth = 0;
	int kty = 0, private_part = 0;
	for (size_t i = 0; i < n;) {
		if (in[i] == '{') {
			depth++;
			i++;
			continue;
		}
		if (in[i] == '}') {
			depth--;
			i++;
			continue;
		}
		if (in[i] != '"') {
			i++;
			continue;
		}
		int parity = 0;
		const char *end = unescaped_quote(in + i + 1, n - i - 1, '"', &parity);
		if (!end)
			break;
		size_t e = (size_t)(end - in);
		size_t colon = e + 1;
		while (colon < n && json_whitespace((unsigned char)in[colon]))
			colon++;
		if (depth >= 1 && colon < n && in[colon] == ':') {
			if (json_string_eq(in + i + 1, e - i - 1, "kty"))
				kty = 1;
			else if (json_string_eq(in + i + 1, e - i - 1, "d") ||
			         json_string_eq(in + i + 1, e - i - 1, "k"))
				private_part = 1;
		}
		i = e + 1;
	}
	return kty && private_part;
}

static int json_candidate(const char *in, size_t n, size_t start) {
	size_t i = start + 1;
	while (i < n && json_whitespace((unsigned char)in[i]))
		i++;
	return i == n || in[i] == '"' || in[i] == '}';
}

static int pem_serialization_suffix(const char *in, size_t n) {
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];
		if (isspace(c) || c == '"' || c == '\'' || c == '`' || c == ',' || c == ';' || c == ']' ||
		    c == '}' || c == ')')
			continue;
		if (c == '\\' && i + 1 < n && (in[i + 1] == 'n' || in[i + 1] == 'r')) {
			i++;
			continue;
		}
		return 0;
	}
	return 1;
}

static int pem_block_prefix(const char *in, size_t n) {
	while (n > 0 && isspace((unsigned char)in[n - 1]))
		n--;
	if (!n)
		return 1;
	return strchr("=:[({|>\"'`", in[n - 1]) != NULL;
}

static void json_feed(ScanState *st, const char *in, size_t n, size_t *close) {
	*close = 0;
	for (size_t i = 0; i < n; i++) {
		if (st->json_string) {
			if (st->json_escape)
				st->json_escape = 0;
			else if (in[i] == '\\')
				st->json_escape = 1;
			else if (in[i] == '"')
				st->json_string = 0;
			continue;
		}
		if (in[i] == '"')
			st->json_string = 1;
		else if (in[i] == '{')
			st->json_depth++;
		else if (in[i] == '}' && st->json_depth > 0 && --st->json_depth == 0) {
			*close = i + 1;
			return;
		}
	}
}

static void json_reset(ScanState *st) {
	st->json_len = 0;
	st->json_lines = 0;
	st->json_depth = 0;
	st->json_string = 0;
	st->json_escape = 0;
	st->json_drop = 0;
}

static int json_append(ScanState *st, const char *in, size_t n) {
	if (n > JSON_CARRY_MAX - st->json_len)
		return 0;
	buf_put(&st->json_buf, &st->json_cap, &st->json_len, in, n);
	return 1;
}

static void scan_plain(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len,
                       ScanState *st, int stream_json) {
	if (mask_assignment(in, inlen, out, outcap, len, st))
		return;
	size_t pos = 0, from = 0;
	while (from < inlen) {
		const char *ob = memchr(in + from, '{', inlen - from);
		if (!ob)
			break;
		size_t os = (size_t)(ob - in);
		size_t oe = json_object_end(in, inlen, os);
		if (oe && json_private_object(in + os, oe - os)) {
			mask_tokens(in + pos, os - pos, out, outcap, len, NULL);
			buf_put(out, outcap, len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
			pos = from = oe;
		} else if (!oe && stream_json && json_candidate(in, inlen, os)) {
			mask_tokens(in + pos, os - pos, out, outcap, len, NULL);
			json_reset(st);
			size_t close = 0;
			json_feed(st, in + os, inlen - os, &close);
			if (!json_append(st, in + os, inlen - os)) {
				st->json_drop = 1;
				buf_put(out, outcap, len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
			}
			return;
		} else {
			from = os + 1;
		}
	}
	mask_tokens(in + pos, inlen - pos, out, outcap, len, pos == 0 ? st : NULL);
}

static void scan_segments(const char *in, size_t inlen, char **out, size_t *outcap, size_t *len,
                          ScanState *st) {
	size_t pos = 0;
	while (pos < inlen) {
		size_t boff = 0, bend = 0;
		if (!find_private_begin(in + pos, inlen - pos, st->pem_label, sizeof(st->pem_label), &boff,
		                        &bend))
			break;
		boff += pos;
		bend += pos;
		scan_plain(in + pos, boff - pos, out, outcap, len, st, 0);
		buf_put(out, outcap, len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
		const char *tail = pem_end_at(in + bend, inlen - bend, st->pem_label);
		if (tail) {
			pos = (size_t)(tail - in);
			continue;
		}
		size_t suffix = inlen - bend;
		int block = pem_block_prefix(in, boff);
		if (block && (!suffix || pem_body_line(in + bend, suffix))) {
			st->pem_open = 1;
			return;
		}
		if (block && pem_serialization_suffix(in + bend, suffix)) {
			scan_plain(in + bend, suffix, out, outcap, len, st, 0);
			st->pem_open = 1;
			return;
		}
		pos = bend;
	}
	if (pos < inlen)
		scan_plain(in + pos, inlen - pos, out, outcap, len, st, 1);
}

static size_t putty_count(const char *in, size_t n, size_t start, int *valid) {
	size_t m = 0;
	*valid = 0;
	while (start < n && (in[start] == ' ' || in[start] == '\t'))
		start++;
	size_t first = start;
	while (start < n && isdigit((unsigned char)in[start])) {
		size_t digit = (size_t)(in[start++] - '0');
		if (m > ((size_t)-1 - digit) / 10)
			return (size_t)-1;
		m = m * 10 + digit;
	}
	while (start < n && isspace((unsigned char)in[start]))
		start++;
	*valid = start == n && start > first;
	return m;
}

static int putty_public_field(const char *in, size_t n) {
	static const char *const fields[] = {
	    "Encryption:",     "Comment:",
	    "Key-Derivation:", "Argon2-Memory:",
	    "Argon2-Passes:",  "Argon2-Parallelism:",
	    "Argon2-Salt:",    NULL,
	};
	for (int i = 0; fields[i]; i++) {
		if (mem_prefix_ci(in, n, fields[i]))
			return 1;
	}
	return 0;
}

static void putty_mac(const char *in, size_t inlen, size_t w, char **out, size_t *outcap,
                      size_t *len, ScanState *st) {
	const char *c = memchr(in + w, ':', inlen - w);
	if (c) {
		size_t h = (size_t)(c - in) + 1;
		buf_put(out, outcap, len, in, h);
		buf_put(out, outcap, len, " <redacted>", strlen(" <redacted>"));
	}
	st->putty_phase = PUTTY_NONE;
	st->putty_lines = 0;
	st->putty_recovery = 0;
	st->putty_emit = 0;
	st->putty_declared = 0;
}

void scan_state_init(ScanState *st) { memset(st, 0, sizeof(*st)); }

int scan_text_line(const char *in, size_t inlen, const char *eol, size_t eollen, char **out,
                   size_t *outcap, size_t *outlen, ScanState *st) {
	size_t len = 0;
	*outlen = 0;

	if (st->json_depth > 0) {
		st->json_lines++;
		size_t close = 0;
		json_feed(st, in, inlen, &close);
		size_t take = close ? close : inlen;
		if (!st->json_drop && (st->json_lines > JSON_LINE_MAX || !json_append(st, in, take))) {
			st->json_drop = 1;
			st->json_len = 0;
			buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
		}
		if (!close) {
			if (!st->json_drop && eollen && !json_append(st, eol, eollen)) {
				st->json_drop = 1;
				st->json_len = 0;
				buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
			}
			if (st->json_drop && len && eollen)
				buf_put(out, outcap, &len, eol, eollen);
			goto emit;
		}
		if (!st->json_drop) {
			if (json_private_object(st->json_buf, st->json_len))
				buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
			else
				scan_plain(st->json_buf, st->json_len, out, outcap, &len, st, 0);
		}
		json_reset(st);
		if (close < inlen)
			scan_segments(in + close, inlen - close, out, outcap, &len, st);
		goto done;
	}

	if (st->pem_open) {
		if (st->pem_open <= PEM_CARRY_MAX)
			st->pem_open++;
		const char *tail = pem_end_at(in, inlen, st->pem_label);
		if (tail) {
			st->pem_open = 0;
			size_t tn = (size_t)(in + inlen - tail);
			if (!tn)
				return 0;
			scan_segments(tail, tn, out, outcap, &len, st);
			goto done;
		}
		if (st->pem_open > PEM_CARRY_MAX && !pem_body_line(in, inlen))
			st->pem_open = 0;
		else
			return 0;
	}

	if (st->quote_ch) {
		st->quote_n++;
		const char *cl = unescaped_quote(in, inlen, st->quote_ch, &st->quote_backslash);
		if (cl) {
			st->quote_ch = 0;
			st->quote_backslash = 0;
			size_t after = (size_t)(cl - in) + 1;
			if (after >= inlen)
				return 0;
			scan_segments(in + after, inlen - after, out, outcap, &len, st);
			goto done;
		}
		if (st->quote_n > PEM_CARRY_MAX) {
			st->quote_ch = 0;
			st->quote_backslash = 0;
		} else {
			return 0;
		}
	}

	size_t w = lead_ws_n(in, inlen);
	int private_mac = mem_prefix_ci(in + w, inlen - w, "Private-MAC:") ||
	                  mem_prefix_ci(in + w, inlen - w, "Private-Hash:");
	int private_lines = mem_prefix_ci(in + w, inlen - w, "Private-Lines:");

	if (st->putty_phase == PUTTY_EXPECT_MAC) {
		if (private_mac) {
			putty_mac(in, inlen, w, out, outcap, &len, st);
			goto done;
		}
		if (pem_body_line(in, inlen))
			return 0;
		st->putty_phase = PUTTY_NONE;
		st->putty_lines = 0;
		st->putty_recovery = 0;
		st->putty_emit = 0;
		st->putty_declared = 0;
	}

	if (st->putty_phase != PUTTY_NONE && st->putty_phase != PUTTY_PRIVATE && private_mac) {
		putty_mac(in, inlen, w, out, outcap, &len, st);
		goto done;
	}

	if (st->putty_phase != PUTTY_NONE && st->putty_phase != PUTTY_PRIVATE && private_lines) {
		int valid = 0;
		st->putty_lines = putty_count(in, inlen, w + strlen("Private-Lines:"), &valid);
		st->putty_phase = valid && !st->putty_lines ? PUTTY_EXPECT_MAC : PUTTY_PRIVATE;
		st->putty_emit = !valid || st->putty_lines > 0;
		st->putty_recovery = 0;
		st->putty_declared = valid;
		buf_put(out, outcap, &len, in, inlen);
		goto done;
	}

	if (st->putty_phase == PUTTY_PUBLIC_BODY) {
		buf_put(out, outcap, &len, in, inlen);
		if (st->putty_lines > 0)
			st->putty_lines--;
		if (!st->putty_lines)
			st->putty_phase = PUTTY_EXPECT_PRIVATE;
		goto done;
	}

	if (st->putty_phase == PUTTY_PUBLIC || st->putty_phase == PUTTY_EXPECT_PRIVATE) {
		if (mem_prefix_ci(in + w, inlen - w, "Public-Lines:")) {
			int valid = 0;
			st->putty_lines = putty_count(in, inlen, w + strlen("Public-Lines:"), &valid);
			st->putty_phase =
			    !valid ? PUTTY_NONE : (st->putty_lines ? PUTTY_PUBLIC_BODY : PUTTY_EXPECT_PRIVATE);
			buf_put(out, outcap, &len, in, inlen);
			goto done;
		}
		if (putty_public_field(in + w, inlen - w) ||
		    (st->putty_phase == PUTTY_EXPECT_PRIVATE && pem_body_line(in, inlen))) {
			buf_put(out, outcap, &len, in, inlen);
			goto done;
		}
		st->putty_phase = PUTTY_NONE;
	}

	if (st->putty_phase == PUTTY_PRIVATE) {
		if (private_mac) {
			putty_mac(in, inlen, w, out, outcap, &len, st);
			goto done;
		}
		if (pem_body_line(in, inlen)) {
			if (st->putty_lines > 0)
				st->putty_lines--;
			if (st->putty_recovery < PUTTY_RECOVERY_MAX)
				st->putty_recovery++;
			if (st->putty_declared && !st->putty_lines)
				st->putty_phase = PUTTY_EXPECT_MAC;
			if (st->putty_emit) {
				st->putty_emit = 0;
				buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
				goto done;
			}
			return 0;
		}
		if (!st->putty_declared) {
			st->putty_phase = PUTTY_NONE;
			st->putty_lines = 0;
			st->putty_recovery = 0;
			st->putty_emit = 0;
			st->putty_declared = 0;
		} else {
			st->putty_recovery++;
			if (st->putty_recovery <= PUTTY_RECOVERY_MAX)
				return 0;
			st->putty_phase = PUTTY_NONE;
			st->putty_lines = 0;
			st->putty_emit = 0;
			st->putty_declared = 0;
		}
	}

	if (mem_prefix(in + w, inlen - w, "PuTTY-User-Key-File")) {
		buf_put(out, outcap, &len, in, w);
		buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
		st->putty_phase = PUTTY_PUBLIC;
		goto done;
	}

	scan_segments(in, inlen, out, outcap, &len, st);
	if (st->json_depth > 0) {
		st->json_lines = 1;
		if (!st->json_drop && eollen && !json_append(st, eol, eollen)) {
			st->json_drop = 1;
			st->json_len = 0;
			buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
			buf_put(out, outcap, &len, eol, eollen);
		} else if (st->json_drop && len && eollen)
			buf_put(out, outcap, &len, eol, eollen);
		goto emit;
	}

done:
	if (eollen)
		buf_put(out, outcap, &len, eol, eollen);
emit:
	buf_need(out, outcap, len + 1);
	(*out)[len] = '\0';
	*outlen = len;
	return len > 0;
}

int scan_text_finish(char **out, size_t *outcap, size_t *outlen, ScanState *st) {
	size_t len = 0;
	if (st->json_len) {
		if (json_private_object(st->json_buf, st->json_len))
			buf_put(out, outcap, &len, PRIVKEY_TOKEN, strlen(PRIVKEY_TOKEN));
		else
			scan_plain(st->json_buf, st->json_len, out, outcap, &len, st, 0);
	}
	json_reset(st);
	buf_need(out, outcap, len + 1);
	(*out)[len] = '\0';
	*outlen = len;
	return len > 0;
}

void scan_state_free(ScanState *st) {
	free(st->json_buf);
	st->json_buf = NULL;
	st->json_cap = 0;
	json_reset(st);
}
