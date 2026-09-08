#!/usr/bin/env bash
set -euo pipefail

bin=${1:?usage: roundtrip.sh <path-to-envctl>}
[[ ${bin} == /* || ${bin} == [A-Za-z]:* ]] || bin=${PWD}/${bin}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
touch "${work}/values.env"

count=0
for want in "${root}"/fixtures/expected/get-decoded-*.out \
	"${root}"/fixtures/expected/get-quoted-padded.out; do
	# Preserve trailing newlines in the value, removing only get's final newline.
	value=$(
		cat "${want}"
		printf '.'
	)
	value=${value%.}
	value=${value%$'\n'}
	"${bin}" --dry-run set "${work}/values.env" VALUE -- "${value}" >"${work}/preview"
	"${bin}" set "${work}/values.env" VALUE -- "${value}"
	"${bin}" --raw get "${work}/values.env" VALUE >"${work}/got"
	if ! cmp -s "${want}" "${work}/got"; then
		printf 'FAIL set/get round trip: %s\n' "$(basename "${want}")" >&2
		exit 1
	fi
	"${bin}" --dry-run set "${work}/values.env" VALUE -- "${value}" \
		>"${work}/preview" 2>"${work}/error"
	[[ ! -s ${work}/preview ]] || {
		printf 'FAIL repeated set changes %s\n' "$(basename "${want}")" >&2
		exit 1
	}
	for action in disable enable; do
		"${bin}" --dry-run "${action}" "${work}/values.env" VALUE >"${work}/preview"
		"${bin}" "${action}" "${work}/values.env" VALUE
	done
	"${bin}" --raw get "${work}/values.env" VALUE >"${work}/got"
	if ! cmp -s "${want}" "${work}/got"; then
		printf 'FAIL disable/enable round trip: %s\n' "$(basename "${want}")" >&2
		exit 1
	fi
	count=$((count + 1))
done
printf '%d set/get and disable/enable round trips passed\n' "${count}"
