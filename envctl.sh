#!/usr/bin/env bash
# envctl — manage keys in env files
#
# Edits a single KEY in place without disturbing order, comments, spacing, or
# any other line. Writes atomically (temp file + mv) and preserves the target's
# permissions, so a crash mid-write can never leave a half-written env file.
#
#   envctl set     <file> <KEY> [VALUE]   set/replace KEY (uncomments if needed)
#   envctl get     <file> <KEY>           print active value, exit 1 if unset
#   envctl disable <file> <KEY>           comment KEY out, keep its value
#   envctl enable  <file> <KEY>           uncomment KEY
#   envctl delete  <file> <KEY>           remove KEY entirely (active + commented)
#   envctl list    <file> [--values] [--all]   list active keys; --all also shows
#                                              disabled ones tagged "(disabled)"
# Aliases: ls = list, rm = delete.
# Bare form (no command): first arg is the file.
#   envctl <file> <KEY>           == get
#   envctl <file> <KEY> <VALUE>   == set
# A command name always wins over a same-named file.
#
# Flags: --dry-run  print the resulting file to stdout, write nothing.
#
# "Active"    = ^ (export )? KEY = ...
# "Commented" = ^ [ws] # [ws] (export )? KEY = ...
# set: updates the first active line in place; extra active duplicates get
# commented out; if none active, the first commented line is revived; else it
# is appended. Re-running with the same args is a no-op on content.

set -euo pipefail

die() {
	printf 'envctl: %s\n' "$1" >&2
	exit 2
}

valid_key() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid key: '$1'"; }

# Emit the transformed file to stdout. All logic lives in awk, keyed off env
# vars (ENVIRON) so shell metacharacters in VALUE are never re-interpreted.
render() {
	local file=$1 action=$2 key=$3
	ENVCTL_ACTION="${action}" ENVCTL_KEY="${key}" awk '
		function is_def(line, commented,   s, rest) {
			s = line
			if (commented) {
				if (s !~ /^[ \t]*#/) return 0
				sub(/^[ \t]*#[ \t]*/, "", s)
			} else {
				if (s ~ /^[ \t]*#/) return 0
			}
			sub(/^export[ \t]+/, "", s)
			rest = substr(s, 1, length(K) + 1)
			return (rest == K "=")
		}
		BEGIN { K = ENVIRON["ENVCTL_KEY"]; A = ENVIRON["ENVCTL_ACTION"]
		        V = ENVIRON["ENVCTL_VAL"]; done = 0 }
		{ lines[NR] = $0 }
		END {
			# locate first active + first commented definition
			fa = 0; fc = 0
			for (i = 1; i <= NR; i++) {
				if (!fa && is_def(lines[i], 0)) fa = i
				if (!fc && is_def(lines[i], 1)) fc = i
			}
			for (i = 1; i <= NR; i++) {
				line = lines[i]; drop = 0
				if (A == "set") {
					if (fa) {
						if (i == fa)        line = K "=" V
						else if (is_def(line, 0)) line = "# " line   # dedupe extras
					} else if (fc && i == fc) line = K "=" V
				} else if (A == "disable") {
					if (is_def(line, 0)) line = "# " line
				} else if (A == "enable") {
					if (fa) { } # already active, leave all as-is
					else if (fc && i == fc) sub(/^[ \t]*#[ \t]*/, "", line)
				} else if (A == "delete") {
					if (is_def(line, 0) || is_def(line, 1)) drop = 1  # active or commented
				}
				if (!drop) out[++n] = line
			}
			if (A == "set" && !fa && !fc) out[++n] = K "=" V
			for (i = 1; i <= n; i++) print out[i]
		}
	' "${file}"
}

commit() { # $1=file  $2=rendered-content
	local file=$1 tmp
	tmp=$(mktemp "$(dirname -- "${file}")/.envctl.XXXXXX") || die "mktemp failed"
	trap 'rm -f "${tmp}"' EXIT
	printf '%s\n' "$2" >"${tmp}"
	chmod --reference="${file}" "${tmp}" 2>/dev/null || true
	mv -f "${tmp}" "${file}"
	trap - EXIT
}

main() {
	local dry=0 args=()
	for a in "$@"; do [[ "${a}" == --dry-run ]] && dry=1 || args+=("${a}"); done
	set -- "${args[@]}"
	[[ $# -ge 2 ]] || die "usage: envctl [<cmd>] <file> <KEY> [VALUE]  (cmd: set get disable enable delete list; aliases ls=list rm=delete)"
	local action file
	case "$1" in
		set | get | disable | enable | delete | list | ls | rm)
			# explicit command form: envctl <cmd> <file> [KEY] [VALUE]
			action=$1 file=$2
			shift 2
			;;
		*)
			# bare form: first arg is the file. 1 trailing arg = get, 2 = set.
			# (a command name always wins over a same-named file; rename such a file.)
			file=$1
			shift
			case $# in
				1) action="get" ;;
				2) action="set" ;;
				*) die "usage: envctl <file> <KEY> [VALUE]  or  envctl <cmd> <file> ..." ;;
			esac
			;;
	esac
	[[ "${action}" == ls ]] && action="list"
	[[ "${action}" == rm ]] && action="delete"
	[[ -f "${file}" ]] || die "no such file: ${file}"

	case "${action}" in
		get)
			[[ $# -ge 1 ]] || die "get needs KEY"
			valid_key "$1"
			local v
			v=$(ENVCTL_KEY="$1" awk '
			BEGIN { K = ENVIRON["ENVCTL_KEY"] }
			/^[ \t]*#/ { next }
			{ s = $0; sub(/^export[ \t]+/, "", s)
			  if (substr(s,1,length(K)+1) == K "=") { print substr(s,length(K)+2); found=1; exit } }
			END { exit(found ? 0 : 1) }' "${file}") || return 1
			printf '%s\n' "${v}"
			;;
		set)
			[[ $# -ge 1 ]] || die "set needs KEY"
			valid_key "$1"
			local out
			out=$(ENVCTL_VAL="${2-}" render "${file}" set "$1")
			if [[ "${dry}" -eq 1 ]]; then printf '%s\n' "${out}"; else commit "${file}" "${out}"; fi
			;;
		disable | enable | delete)
			[[ $# -ge 1 ]] || die "${action} needs KEY"
			valid_key "$1"
			local out
			out=$(render "${file}" "${action}" "$1")
			if [[ "${dry}" -eq 1 ]]; then printf '%s\n' "${out}"; else commit "${file}" "${out}"; fi
			;;
		list)
			local values=0 all=0
			for f in "$@"; do
				[[ "${f}" == --values ]] && values=1
				[[ "${f}" == --all ]] && all=1
			done
			awk -v show="${values}" -v all="${all}" '
			{ s = $0; commented = 0
			  if (s ~ /^[ \t]*#/) { if (!all) next; commented = 1; sub(/^[ \t]*#[ \t]*/, "", s) }
			  sub(/^export[ \t]+/, "", s)
			  eq = index(s, "="); if (eq < 2) next
			  k = substr(s, 1, eq - 1)
			  if (k !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
			  tag = commented ? " (disabled)" : ""
			  if (!show) { print k tag; next }
			  v = substr(s, eq + 1)
			  if (k ~ /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API)/ && length(v) > 4)
			      v = "****" substr(v, length(v) - 3)
			  print k "=" v tag }' "${file}"
			;;
		*) die "unknown action: ${action}" ;;
	esac
}

main "$@"
