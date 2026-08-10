#!/usr/bin/env bash
# Asks each shell what it would offer, and the binary whether that is valid.
# Reading the generated scripts cannot catch an emitter that puts correct data
# in a place the shell applies too widely, which is the defect this exists for.
set -u

bin=${1:-}
[[ -n ${bin} ]] || {
	echo 'usage: completions.sh <path-to-envctl>' >&2
	exit 2
}
[[ ${bin} == /* ]] || bin=${PWD}/${bin}
[[ -x ${bin} ]] || {
	echo "not executable: ${bin}" >&2
	exit 2
}
readonly bin

work=$(mktemp -d) || exit 2
trap 'rm -rf "${work}"' EXIT INT TERM

declare -i failed=0
declare -a skipped=()

fail() {
	printf '  FAIL  %s\n' "$*"
	failed+=1
}

# ---------------------------------------------------------------------------
# What exists, from the binary's own help
# ---------------------------------------------------------------------------

readonly help_out=${work}/help
"${bin}" --help >"${help_out}" 2>&1

mapfile -t commands < <(awk '
	/^Commands:/ { in_cmd = 1; next }
	/^$/         { in_cmd = 0 }
	in_cmd && /^  [a-z]/ { print $1 }
' "${help_out}")

mapfile -t flags < <(awk '
	/^Flags:/ { in_flag = 1; next }
	/^$/      { in_flag = 0 }
	in_flag && /^  --/ { print $1 }
' "${help_out}")

declare -A alias_of=()
while read -r a _ c; do
	[[ -n ${a} ]] && alias_of[${a}]=${c}
done < <(sed -n 's/^Aliases: //p' "${help_out}" | tr ',' '\n' | tr -d ' ' | sed 's/=/ = /')

((${#commands[@]} >= 5)) || {
	echo "could not read the command list from --help" >&2
	exit 2
}
((${#flags[@]} >= 5)) || {
	echo "could not read the flag list from --help" >&2
	exit 2
}

# ---------------------------------------------------------------------------
# The oracle: ask the parser itself
# ---------------------------------------------------------------------------

parser_accepts() {
	local out
	out=$("${bin}" "$1" "$2" 2>&1 >/dev/null)
	[[ ${out} != *"is only valid for"* ]]
}

valid_flags_for() {
	local cmd=$1 f
	for f in "${flags[@]}"; do
		parser_accepts "${cmd}" "${f}" && printf '%s\n' "${f}"
	done
}

# ---------------------------------------------------------------------------
# Drivers, one per shell
# ---------------------------------------------------------------------------

bash_offers() {
	local script=$1 line=$2
	bash --norc --noprofile -c '
		source "$1" >/dev/null 2>&1
		COMP_LINE=$2
		COMP_POINT=${#COMP_LINE}
		read -ra COMP_WORDS <<<"$2"
		[[ $2 == *" " ]] && COMP_WORDS+=("")
		COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
		COMPREPLY=()
		_envctl >/dev/null 2>&1
		printf "%s\n" ${COMPREPLY+"${COMPREPLY[@]}"}
	' _ "${script}" "${line}" 2>/dev/null
}

fish_offers() {
	local script=$1 line=$2
	fish -c "source ${script}; complete -C ${line@Q}" 2>/dev/null | cut -f 1
}

zsh_render() {
	local script=$1 line=$2
	zsh -f -c "
		zmodload zsh/zpty || exit 1
		zpty c 'zsh -f -i'
		zpty -w c \"PS1=''; autoload -Uz compinit; compinit -u -d ${work}/zcompdump; source ${script}; echo MARK\"
		buf=
		for i in {1..100}; do
			zpty -r c line 2>/dev/null && buf+=\$line
			[[ \$buf == *MARK* ]] && break
			sleep 0.1
		done
		[[ \$buf == *MARK* ]] || { print -u2 'zpty setup failed'; exit 1 }
		zpty -w -n c ${line@Q}\$'\t'
		sleep 1
		buf=
		while zpty -r -t c line 2>/dev/null; do buf+=\$line; done
		zpty -d c
		print -r -- \$buf
	" 2>/dev/null | sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' -e 's/\x1b[<>=]//g' -e 's/\r//g'
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

# A candidate set must contain every valid flag and no invalid one.
check_exact() {
	local shell=$1 context=$2 cmd=$3 got=$4 want f
	want=$(valid_flags_for "${cmd}")
	for f in "${flags[@]}"; do
		if grep -qxF -- "${f}" <<<"${want}"; then
			grep -qxF -- "${f}" <<<"${got}" \
				|| fail "${shell}: [${context}] does not offer ${f}, which ${cmd} accepts"
		else
			grep -qxF -- "${f}" <<<"${got}" \
				&& fail "${shell}: [${context}] offers ${f}, which ${cmd} rejects"
		fi
	done
}

# zsh renders a menu rather than a list, so assert the property that broke:
# nothing invalid appears, and something valid does.
check_rendered() {
	local shell=$1 context=$2 cmd=$3 got=$4 want f seen=0
	want=$(valid_flags_for "${cmd}")
	for f in "${flags[@]}"; do
		if grep -qxF -- "${f}" <<<"${want}"; then
			grep -qw -- "${f}" <<<"${got}" && seen=1
		else
			grep -qw -- "${f}" <<<"${got}" \
				&& fail "${shell}: [${context}] offers ${f}, which ${cmd} rejects"
		fi
	done
	((seen)) || fail "${shell}: [${context}] offered none of ${cmd}'s flags"
}

run_shell() {
	local shell=$1 script=${work}/script.$1 cmd first ctx got
	command -v "${shell}" >/dev/null 2>&1 || {
		skipped+=("${shell} (not installed)")
		return
	}
	"${bin}" completions "${shell}" >"${script}" || {
		fail "${shell}: generating the script failed"
		return
	}

	for cmd in "${commands[@]}"; do
		first=$(valid_flags_for "${cmd}" | head -n 1)

		for ctx in "${bin##*/} ${cmd} -" "${bin##*/} ${cmd} ${first} -"; do
			[[ ${ctx} == *" - " ]] && continue
			[[ -z ${first} && ${ctx} == *"${cmd}  -" ]] && continue
			case ${shell} in
				bash) got=$(bash_offers "${script}" "${ctx}") ;;
				fish) got=$(fish_offers "${script}" "${ctx}") ;;
			esac
			case ${shell} in
				bash | fish) check_exact "${shell}" "${ctx}" "${cmd}" "${got}" ;;
			esac
		done
	done

	if [[ ${shell} == zsh ]]; then
		for cmd in "${commands[@]}"; do
			first=$(valid_flags_for "${cmd}" | head -n 1)
			for ctx in "envctl ${cmd} -" "envctl ${cmd} ${first} -"; do
				[[ -z ${first} && ${ctx} == *"${cmd}  -" ]] && continue
				got=$(zsh_render "${script}" "${ctx}")
				check_rendered zsh "${ctx}" "${cmd}" "${got}"
			done
		done
	fi
}

for shell in bash fish zsh; do
	run_shell "${shell}"
done

printf '\n'
if ((${#skipped[@]})); then
	printf '%d skipped:\n' "${#skipped[@]}"
	printf '  %s\n' "${skipped[@]}"
fi
if ((failed == 0)); then
	printf 'completions consistent with the parser\n'
	exit 0
fi
printf '%d completion mismatches\n' "${failed}"
exit 1
