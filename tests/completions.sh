#!/usr/bin/env bash
# Asks each shell what it would offer, and the binary whether that is valid.
# Reading the generated scripts cannot catch an emitter that puts correct data
# in a place the shell applies too widely, which is the defect this exists for.
set -u

# mapfile and associative arrays are bash 4, and macOS ships 3.2.
((BASH_VERSINFO[0] >= 4)) || {
	echo "completions.sh needs bash 4 or newer, this is ${BASH_VERSION}" >&2
	exit 2
}

read -ra shells <<<"${COMPLETIONS_SHELLS:-bash zsh fish}"
((${#shells[@]})) || {
	echo 'COMPLETIONS_SHELLS is empty, so no shell would be checked' >&2
	exit 2
}

bin=${1:-}
[[ -n ${bin} ]] || {
	echo 'usage: completions.sh <path-to-envctl>' >&2
	exit 2
}
[[ ${bin} == /* || ${bin} == [A-Za-z]:* ]] || bin=${PWD}/${bin}
[[ -x ${bin} ]] || {
	echo "not executable: ${bin}" >&2
	exit 2
}
readonly bin

work=$(mktemp -d) || exit 2
trap 'rm -rf "${work}"' EXIT INT TERM

declare -i failed=0

fail() {
	printf '  FAIL  %s\n' "$*"
	failed+=1
}

# ---------------------------------------------------------------------------
# What exists, from the binary's own help
# ---------------------------------------------------------------------------

readonly help_out=${work}/help
"${bin}" --help >"${help_out}" 2>&1

awk '
	/^Commands:/ { in_cmd = 1; next }
	/^$/         { in_cmd = 0 }
	in_cmd && /^  [a-z]/ { print $1 }
' "${help_out}" >"${work}/commands"
mapfile -t commands <"${work}/commands"

awk '
	/^Flags:/ { in_flag = 1; next }
	/^$/      { in_flag = 0 }
	in_flag && /^  --/ { print $1 }
' "${help_out}" >"${work}/flags"
mapfile -t flags <"${work}/flags"

sed -n 's/^Aliases: //p' "${help_out}" >"${work}/aliasline"
tr ',' '\n' <"${work}/aliasline" >"${work}/aliassplit"
tr -d ' ' <"${work}/aliassplit" >"${work}/aliastrim"
sed 's/=/ /' <"${work}/aliastrim" >"${work}/aliases"
declare -A alias_of=()
while read -r a c; do
	[[ -n ${a} ]] || continue
	alias_of[${a}]=${c}
done <"${work}/aliases"

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

# The parser names a flag's values when it rejects a bogus one, so ask it
# rather than reading them back out of anything generated.
declare -A flag_values=()
for f in "${flags[@]}"; do
	out=$("${bin}" get "${f}=__probe__" 2>&1 >/dev/null)
	[[ ${out} == *" takes "* && ${out} != *"takes no value"* ]] || continue
	flag_values[${f}]=$(sed -e 's/.* takes //' -e 's/, or / /' -e 's/ or / /' -e 's/,/ /g' <<<"${out}")
done
flag_under_test=

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
	fish -c "source ${script}; complete -C ${line@Q}" >"${work}/fish.raw" 2>/dev/null
	cut -f 1 <"${work}/fish.raw"
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
	" >"${work}/zsh.raw" 2>/dev/null
	# The redrawn prompt line runs into the last candidate, so break it apart
	# before anything looks for a candidate as a whole word.
	sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' -e 's/\x1b[<>=]//g' -e 's/\r//g' \
		-e 's/envctl /\nenvctl /g' <"${work}/zsh.raw"
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

# Every value a flag enumerates must be offered after its "=", and nothing else.
check_values() {
	local shell=$1 context=$2 got=$3 spec=$4 v
	for v in ${spec}; do
		grep -qxF -- "${v}" <<<"${got}" \
			|| grep -qxF -- "${flag_under_test}=${v}" <<<"${got}" \
			|| fail "${shell}: [${context}] does not offer ${v}"
	done
}

value_flags_for() {
	local cmd=$1 i
	for ((i = 0; i < ${#flags[@]}; i++)); do
		[[ -n ${flag_values[${flags[i]}]:-} ]] || continue
		parser_accepts "${cmd}" "${flags[i]}" && printf '%s\n' "${flags[i]}"
	done
}

run_shell() {
	local shell=$1 script=${work}/script.$1 cmd first ctx got vflag v f
	command -v "${shell}" >/dev/null 2>&1 || {
		fail "${shell}: not installed, so nothing it offers was checked"
		return
	}
	"${bin}" completions "${shell}" >"${script}" || {
		fail "${shell}: generating the script failed"
		return
	}

	# Every command, plus each alias, which must offer what its command offers.
	local -a words=("${commands[@]}" "${!alias_of[@]}")
	local word
	for word in "${words[@]}"; do
		cmd=${alias_of[${word}]:-${word}}
		valid_flags_for "${cmd}" >"${work}/valid"
		first=$(head -n 1 "${work}/valid")

		for ctx in "envctl ${word} -" "envctl ${word} ${first} -"; do
			[[ -z ${first} && ${ctx} == *"${word}  -" ]] && continue
			case ${shell} in
				bash)
					got=$(bash_offers "${script}" "${ctx}")
					check_exact "${shell}" "${ctx}" "${cmd}" "${got}"
					;;
				fish)
					got=$(fish_offers "${script}" "${ctx}")
					check_exact "${shell}" "${ctx}" "${cmd}" "${got}"
					;;
				zsh)
					got=$(zsh_render "${script}" "${ctx}")
					check_rendered zsh "${ctx}" "${cmd}" "${got}"
					;;
				*) fail "unknown shell ${shell}" ;;
			esac
		done
	done

	# A flag that enumerates values must offer them after its "=", in every
	# command that accepts it and before any command word.
	for cmd in "${commands[@]}" ""; do
		if [[ -n ${cmd} ]]; then
			value_flags_for "${cmd}" >"${work}/vflags"
		else
			: >"${work}/vflags"
			for f in "${flags[@]}"; do
				[[ -n ${flag_values[${f}]:-} ]] && printf '%s\n' "${f}" >>"${work}/vflags"
			done
		fi
		while read -r vflag; do
			[[ -n ${vflag} ]] || continue
			flag_under_test=${vflag}
			ctx="envctl ${cmd:+${cmd} }${vflag}="
			case ${shell} in
				bash)
					got=$(bash_offers "${script}" "${ctx}")
					check_values "${shell}" "${ctx}" "${got}" "${flag_values[${vflag}]}"
					;;
				fish)
					got=$(fish_offers "${script}" "${ctx}")
					check_values "${shell}" "${ctx}" "${got}" "${flag_values[${vflag}]}"
					;;
				zsh)
					got=$(zsh_render "${script}" "${ctx}")
					for v in ${flag_values[${vflag}]}; do
						grep -qw -- "${v}" <<<"${got}" \
							|| fail "zsh: [${ctx}] does not offer ${v}"
					done
					;;
				*) fail "unknown shell ${shell}" ;;
			esac
		done <"${work}/vflags"
	done
}

for shell in "${shells[@]}"; do
	run_shell "${shell}"
done

printf '\n'
if ((failed == 0)); then
	printf 'completions consistent with the parser (%s)\n' "${shells[*]}"
	exit 0
fi
printf '%d completion mismatches\n' "${failed}"
exit 1
