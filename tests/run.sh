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

declare -i passed=0
declare -a failures=()
declare -a skipped=()

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
	--text
	--initial-tab
	--suppress-blank-empty
	--unified
	--label want
	--label got
	--color=auto
)

compare() {
	local name=$1 what=$2 want=$3 got=$4 shown total
	if [[ ! -e ${want} ]]; then
		failures+=("${name}")
		printf '  FAIL  %s\n' "${name}"
		printf '        missing expectation: %s\n' "${want}"
		return 1
	fi
	if cmp -s "${want}" "${got}"; then
		return 0
	fi
	failures+=("${name}")
	printf '  FAIL  %s\n' "${name}"
	printf '        %s differs\n' "${what}"
	cmp "${want}" "${got}" >"${got}.cmp" 2>&1 || true
	sed 's/^.*differ: /        first difference at /' "${got}.cmp"
	diff "${diff_opts[@]}" "${want}" "${got}" >"${got}.diff" || true
	total=$(grep -c '' "${got}.diff") || true
	head -14 "${got}.diff" >"${got}.head" || true
	sed 's/^/        /' "${got}.head"
	shown=$(grep -c '' "${got}.head") || true
	if ((total > shown)); then
		printf '        ... %d more diff lines\n' "$((total - shown))"
	fi
	return 1
}

run_case() {
	local file=$1 name dir rc want_rc target
	name=$(basename "${file}" .case) || return
	dir=${work}/${name}
	mkdir -p "${dir}" || return

	local -a argv=() envv=()
	section "${file}" args >"${dir}/.argv"
	section "${file}" setenv >"${dir}/.setenv"
	mapfile -t argv <"${dir}/.argv"
	mapfile -t envv <"${dir}/.setenv"

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

	if [[ ${mode} == pty && ${pty_kind} == none ]]; then
		skipped+=("${name} (no pty available)")
		return
	fi
	if [[ ${mode} == nosigpipe && ${nosigpipe} == no ]]; then
		skipped+=("${name} (no env --ignore-signal)")
		return
	fi

	# Agent detection reads the environment, so cases run from a clean one and
	# opt into agent behaviour through setenv.
	local -a launch=(env -i "PATH=${clean_path}" "${envv[@]}" "${bin}" "${argv[@]}")
	local cmdstr
	case ${mode} in
		plain)
			(cd "${dir}" && "${launch[@]}") \
				<"${stdin}" >"${dir}/.stdout" 2>"${dir}/.stderr"
			rc=$?
			;;
		pty)
			# The line discipline appends CR to every line. Strip it before
			# comparing; byte-exact line endings are covered by filter-crlf.
			if [[ ${pty_kind} == gnu ]]; then
				cmdstr=$(printf '%q ' "${launch[@]}")
				(cd "${dir}" && script -qec "${cmdstr}" /dev/null) \
					<"${stdin}" >"${dir}/.raw" 2>"${dir}/.stderr"
			else
				(cd "${dir}" && script -q /dev/null "${launch[@]}") \
					<"${stdin}" >"${dir}/.raw" 2>"${dir}/.stderr"
			fi
			rc=$?
			tr -d '\r' <"${dir}/.raw" >"${dir}/.stdout"
			;;
		nosigpipe)
			# A reader that closes early, with SIGPIPE ignored, so the write
			# fails with EPIPE instead of the signal killing the process.
			(
				cd "${dir}" || exit 2
				mkfifo .fifo || exit 2
				env --ignore-signal=PIPE "${launch[@]:1}" >.fifo 2>.stderr &
				producer=$!
				head -1 <.fifo >.stdout || true
				wait "${producer}"
			)
			rc=$?
			;;
		*)
			failures+=("${name}")
			printf '  FAIL  %s\n' "${name}"
			printf '        unknown mode: %s\n' "${mode}"
			return
			;;
	esac

	want_rc=0
	if has_section "${file}" exit; then
		want_rc=$(section "${file}" exit)
	fi
	if [[ ${rc} != "${want_rc}" ]]; then
		failures+=("${name}")
		printf '  FAIL  %s\n' "${name}"
		printf '        exit want %s got %s\n' "${want_rc}" "${rc}"
		return
	fi

	local ok=1
	if has_section "${file}" stdout; then
		section "${file}" stdout >"${dir}/.want"
		compare "${name}" stdout "${dir}/.want" "${dir}/.stdout" || ok=0
	elif has_section "${file}" stdout-file; then
		local wf
		wf=$(section "${file}" stdout-file)
		compare "${name}" stdout "${fx}/${wf}" "${dir}/.stdout" || ok=0
	fi
	if ((ok)) && has_section "${file}" stderr; then
		section "${file}" stderr >"${dir}/.want-err"
		compare "${name}" stderr "${dir}/.want-err" "${dir}/.stderr" || ok=0
	fi
	if ((ok)) && has_section "${file}" file; then
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
