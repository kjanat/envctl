#define _GNU_SOURCE
#include "agent.h"

#include <stdlib.h>
#include <string.h>

static int env_set(const char *k) {
	const char *v = getenv(k);
	return v && *v;
}

int detect_agent(void) {
	const char *v;
	static const char *const keys[] = {
	    "AI_AGENT",   /* explicit override */
	    "CLAUDECODE", /* claude */
	    "CLAUDE_CODE",
	    "REPL_ID",       /* replit */
	    "GEMINI_CLI",    /* gemini */
	    "CODEX_SANDBOX", /* codex */
	    "CODEX_THREAD_ID",
	    "OPENCODE",       /* opencode */
	    "AUGMENT_AGENT",  /* auggie */
	    "GOOSE_PROVIDER", /* goose */
	    "JUNIE_DATA",     /* junie */
	    "JUNIE_SHIM_PATH",
	    "CURSOR_AGENT", /* cursor */
	    NULL,
	};

	for (int i = 0; keys[i]; i++) {
		if (env_set(keys[i]))
			return 1;
	}

	if ((v = getenv("PATH")) && (strstr(v, ".pi/agent") || strstr(v, ".pi\\agent")))
		return 1; /* pi */
	if ((v = getenv("EDITOR")) && strstr(v, "devin"))
		return 1; /* devin */
	if ((v = getenv("TERM_PROGRAM")) && strstr(v, "kiro"))
		return 1; /* kiro; redaction still requires a TTY via want_redact */

	return 0;
}
