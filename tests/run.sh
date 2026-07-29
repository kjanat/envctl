#!/usr/bin/env bash
set -u

bin=${1:-}
[[ -n ${bin} ]] || {
	echo 'usage: run.sh <path-to-envctl>' >&2
	exit 2
}
[[ ${bin} == /* || ${bin} == [A-Za-z]:* ]] || bin=${PWD}/${bin}
[[ -x ${bin} ]] || {
	echo "not executable: ${bin}" >&2
	exit 2
}
readonly bin

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly root fx=${root}/fixtures

work=$(mktemp -d) || exit 2
trap 'cd /; rm -rf "${work}"' EXIT INT TERM

readonly clean_path=/usr/bin:/bin

# GNU script takes the command as one string, BSD script takes it as argv.
# Neither exists on Windows, where pty cases report as skipped.
pty_kind=none
if command -v script >/dev/null 2>&1; then
	if script --version >/dev/null 2>&1; then
		pty_kind=gnu
	else
		pty_kind=bsd
	fi
fi
readonly pty_kind

nosigpipe=no
if env --ignore-signal=PIPE true >/dev/null 2>&1; then
	nosigpipe=yes
fi
readonly nosigpipe

epipe_open=no
if command -v mkfifo >/dev/null 2>&1 \
	&& mkfifo "${work}/.epipe-open-probe" >/dev/null 2>&1; then
	epipe_open=yes
fi
# MSYS fifos cannot feed a native binary's stdin.
case $(uname -s) in
	MINGW* | MSYS* | CYGWIN*) epipe_open=no ;;
esac
readonly epipe_open

declare -i passed=0
declare -a failures=()
declare -a skipped=()

fail_case() {
	local name=$1 known
	for known in ${failures[@]+"${failures[@]}"}; do
		[[ ${known} == "${name}" ]] && return
	done
	failures+=("${name}")
	printf '  FAIL  %s\n' "${name}"
}

validate_sections() {
	local file=$1 name=$2 line marker
	local -i bad=0
	while IFS= read -r line || [[ -n ${line} ]]; do
		[[ ${line} == '%% '* ]] || continue
		marker=${line#'%% '}
		case ${marker} in
			args | stdout | env | stdin-file | stdin | setenv | stdout-file | file | stderr | exit | mode) ;;
			*)
				fail_case "${name}"
				printf '        unknown section: %s\n' "${marker}"
				bad=1
				;;
		esac
	done <"${file}"
	return "${bad}"
}

# A section runs to the next "%% " marker.
#
# The blank line that separates it from that marker is layout,
# so exactly one trailing blank is dropped.
#
# Write two to end a section with a real blank line.
section() {
	awk -v want="$2" '
		/^%% / { sec = substr($0, 4); next }
		sec == want { buf[n++] = $0 }
		END {
			if (n > 0 && buf[n - 1] == "")
				n--
			for (i = 0; i < n; i++)
				print buf[i]
		}
	' "$1"
}

has_section() {
	grep -qx "%% $2" "$1"
}

# Expectations are byte-exact, so every diff option that ignores whitespace, case,
# blank lines or trailing CR is off limits here; -a keeps a readable diff when a
# fixture looks binary, and -T keeps tab stops honest against the +/- column.
readonly -a diff_opts=(
	-a
	-T
	-u
	-L want
	-L got
)

compare() {
	local name=$1 what=$2 want=$3 got=$4 shown total
	if [[ ! -e ${want} ]]; then
		fail_case "${name}"
		printf '        missing %s expectation\n' "${what}"
		return 1
	fi
	if [[ ! -e ${got} ]]; then
		fail_case "${name}"
		printf '        missing %s result\n' "${what}"
		return 1
	fi
	if cmp -s "${want}" "${got}"; then
		return 0
	fi
	fail_case "${name}"
	printf '        %s differs\n' "${what}"
	cmp "${want}" "${got}" >"${got}.cmp" 2>&1 || true
	sed \
		-e 's/^.*differ: /first difference at /' \
		-e 's/^cmp: EOF on .* which is empty$/EOF on one input which is empty/' \
		-e 's/^cmp: EOF on .* after byte /EOF after byte /' \
		-e 's/^cmp: EOF on .*$/EOF on one input/' \
		-e 's/^cmp: .*/comparison failed/' \
		-e 's/^/        /' \
		"${got}.cmp"
	diff "${diff_opts[@]}" "${want}" "${got}" >"${got}.diff" 2>&1 || true
	total=$(wc -l <"${got}.diff")
	head -n 14 "${got}.diff" >"${got}.head" || true
	sed 's/^/        /' "${got}.head"
	shown=$(wc -l <"${got}.head")
	if ((total > shown)); then
		printf '        ... %d more diff lines\n' "$((total - shown))"
	fi
	return 1
}

run_case() {
	local file=$1 name dir rc want_rc target
	name=$(basename "${file}" .case) || return
	validate_sections "${file}" "${name}" || return
	dir=${work}/${name}
	mkdir -p "${dir}" || return

	local -a argv=() envv=()
	local line
	section "${file}" args >"${dir}/.argv"
	section "${file}" setenv >"${dir}/.setenv"
	while IFS= read -r line; do argv+=("${line}"); done <"${dir}/.argv"
	while IFS= read -r line; do envv+=("${line}"); done <"${dir}/.setenv"

	local base=
	if has_section "${file}" env; then
		target=$(section "${file}" env)
		base=$(basename "${target}")
		cp "${fx}/${target}" "${dir}/${base}"
	fi

	local stdin=/dev/null
	if has_section "${file}" stdin; then
		section "${file}" stdin >"${dir}/.stdin"
		stdin=${dir}/.stdin
	elif has_section "${file}" stdin-file; then
		local rel
		rel=$(section "${file}" stdin-file)
		stdin=${fx}/${rel}
	fi

	local mode=plain
	if has_section "${file}" mode; then
		mode=$(section "${file}" mode)
	fi
	want_rc=0
	if has_section "${file}" exit; then
		want_rc=$(section "${file}" exit)
	fi

	if [[ ${mode} == pty && ${pty_kind} == none ]]; then
		skipped+=("${name} (no pty available)")
		return
	fi
	if [[ ${mode} == pty ]] && { has_section "${file}" stdin || has_section "${file}" stdin-file; }; then
		fail_case "${name}"
		printf '        pty mode does not support configured stdin\n'
		return
	fi
	if [[ ${mode} == pty && ${want_rc} =~ ^[0-9]+$ ]] && ((want_rc >= 128)); then
		fail_case "${name}"
		printf '        pty signal-style exit expectation is not portable: %s\n' "${want_rc}"
		return
	fi
	if [[ ${mode} == nosigpipe && ${nosigpipe} == no ]]; then
		skipped+=("${name} (no env --ignore-signal)")
		return
	fi
	if [[ ${mode} == epipe-open && ${epipe_open} == no ]]; then
		skipped+=("${name} (no usable fifo)")
		return
	fi
	local first='' second='' third=''
	local -i epipe_input_ok=1
	if [[ ${mode} == epipe-open ]]; then
		{
			IFS= read -r first || epipe_input_ok=0
			if ((epipe_input_ok)); then
				IFS= read -r second || epipe_input_ok=0
			fi
			if ((epipe_input_ok)) && { IFS= read -r third || [[ -n ${third} ]]; }; then
				epipe_input_ok=0
			fi
		} <"${stdin}"
		if ((!epipe_input_ok)); then
			fail_case "${name}"
			printf '        epipe-open stdin needs exactly two newline-terminated lines\n'
			return
		fi
	fi

	# Agent detection reads the environment, so cases run from a clean one and
	# opt into agent behaviour through setenv.
	local -a launch=(env -i "PATH=${clean_path}" ${envv[@]+"${envv[@]}"} "${bin}" ${argv[@]+"${argv[@]}"})
	local cmdstr
	case ${mode} in
		plain)
			(cd "${dir}" && "${launch[@]}") \
				<"${stdin}" >"${dir}/.stdout" 2>"${dir}/.stderr"
			rc=$?
			;;
		pty)
			# The line discipline appends CR to every line, and BSD script
			# echoes the EOF it reads from /dev/null as caret-D plus two
			# erasing backspaces. Strip all of it before comparing;
			# byte-exact line endings are covered by filter-crlf. Keep child
			# and script diagnostics outside the pseudo-terminal.
			: >"${dir}/.stderr"
			if [[ ${pty_kind} == gnu ]]; then
				cmdstr=$(printf '%q ' "${launch[@]}")
				cmdstr+='2>>.stderr'
				(cd "${dir}" && SHELL=${BASH} script -q -e -E never -c "${cmdstr}" /dev/null) \
					<"${stdin}" >"${dir}/.raw" 2>>"${dir}/.stderr"
			else
				(cd "${dir}" && script -q /dev/null \
					/bin/sh -c 'exec 2>>.stderr; exec "$@"' sh "${launch[@]}") \
					<"${stdin}" >"${dir}/.raw" 2>>"${dir}/.stderr"
			fi
			rc=$?
			tr -d '\r\b' <"${dir}/.raw" \
				| sed -e '1s/^\^D//' -e $'1s/^\x04//' >"${dir}/.stdout"
			;;
		nosigpipe)
			# A reader that closes early, with SIGPIPE ignored, so the write
			# fails with EPIPE instead of the signal killing the process.
			(
				cd "${dir}" || exit 2
				mkfifo .fifo || exit 2
				env --ignore-signal=PIPE "${launch[@]:1}" \
					<"${stdin}" >.fifo 2>.stderr &
				producer=$!
				head -1 <.fifo >.stdout || true
				wait "${producer}"
				producer_rc=$?
				exit "${producer_rc}"
			)
			rc=$?
			;;
		epipe-open)
			# Keep stdin open after the second line. A per-write EPIPE check exits;
			# an EOF-only check blocks until the watchdog kills the producer.
			(
				cd "${dir}" || exit 2
				mkfifo .stdin-fifo .stdout-fifo || exit 2
				(
					trap '' PIPE
					exec "${launch[@]}"
				) <.stdin-fifo >.stdout-fifo 2>.stderr &
				producer=$!
				exec 3>.stdin-fifo
				(
					sleeper=
					trap '
						trap - TERM INT
						if [[ -n ${sleeper} ]]; then
							kill "${sleeper}" 2>/dev/null || true
							wait "${sleeper}" 2>/dev/null || true
						fi
						exit 0
					' TERM INT
					sleep 5 &
					sleeper=$!
					wait "${sleeper}" || exit 0
					sleeper=
					if kill -0 "${producer}" 2>/dev/null; then
						: >.watchdog-fired
						kill -TERM "${producer}" 2>/dev/null || true
						sleep 1 &
						sleeper=$!
						wait "${sleeper}" || exit 0
						sleeper=
						kill -KILL "${producer}" 2>/dev/null || true
					fi
				) 3>&- &
				watchdog=$!
				printf '%s\n' "${first}" >&3 || true
				head -n 1 <.stdout-fifo >.stdout || true
				printf '%s\n' "${second}" >&3 2>/dev/null || true
				wait "${producer}"
				producer_rc=$?
				exec 3>&-
				kill -TERM "${watchdog}" 2>/dev/null || true
				wait "${watchdog}" 2>/dev/null || true
				printf '%s\n' "${producer_rc}" >.producer-status
				[[ ! -e .watchdog-fired ]] || exit 124
				exit "${producer_rc}"
			)
			rc=$?
			;;
		*)
			fail_case "${name}"
			printf '        unknown mode: %s\n' "${mode}"
			return
			;;
	esac

	local ok=1
	if [[ -e ${dir}/.watchdog-fired ]]; then
		fail_case "${name}"
		printf '        epipe-open watchdog killed blocked producer (status %s)\n' \
			"$(<"${dir}/.producer-status")"
		ok=0
	fi
	if [[ ${rc} != "${want_rc}" ]]; then
		fail_case "${name}"
		printf '        exit want %s got %s\n' "${want_rc}" "${rc}"
		ok=0
	fi

	local want_stdout=${dir}/.want
	: >"${want_stdout}"
	if has_section "${file}" stdout; then
		section "${file}" stdout >"${dir}/.want"
	elif has_section "${file}" stdout-file; then
		local wf
		wf=$(section "${file}" stdout-file)
		want_stdout=${fx}/${wf}
	fi
	compare "${name}" stdout "${want_stdout}" "${dir}/.stdout" || ok=0
	: >"${dir}/.want-err"
	if has_section "${file}" stderr; then
		section "${file}" stderr >"${dir}/.want-err"
	fi
	compare "${name}" stderr "${dir}/.want-err" "${dir}/.stderr" || ok=0
	if has_section "${file}" file; then
		section "${file}" file >"${dir}/.want-file"
		compare "${name}" "edited file" "${dir}/.want-file" "${dir}/${base}" || ok=0
	fi

	if ((ok)); then
		((++passed))
		[[ -z ${V:-} ]] || printf '  ok    %s\n' "${name}"
	fi
}

for case_file in "${root}"/cases/*.case; do
	run_case "${case_file}"
done

printf '\n'
if ((${#skipped[@]})); then
	printf '%d skipped:\n' "${#skipped[@]}"
	printf '  %s\n' "${skipped[@]}"
fi
if ((${#failures[@]} == 0)); then
	printf '%d passed\n' "${passed}"
	exit 0
fi
printf '%d passed, %d FAILED:\n' "${passed}" "${#failures[@]}"
printf '  %s\n' "${failures[@]}"
exit 1
