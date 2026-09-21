#!/usr/bin/env sh
set -eu

repo=kjanat/envctl
dir=${ENVCTL_INSTALL_DIR:-${HOME}/.local/bin}
version=${ENVCTL_VERSION:-latest}

sys=$(uname -s)
machine=$(uname -m)

case ${sys} in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	FreeBSD) os=freebsd ;;
	MINGW* | MSYS* | CYGWIN*) os=windows ;;
	*)
		echo "unsupported OS: ${sys}" >&2
		exit 1
		;;
esac

case ${machine} in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*)
		echo "unsupported architecture: ${machine}" >&2
		exit 1
		;;
esac

ext=
[ "${os}" = windows ] && ext=.exe
asset="envctl-${os}-${arch}${ext}"

if [ "${version}" = latest ]; then
	base="https://github.com/${repo}/releases/latest/download"
else
	base="https://github.com/${repo}/releases/download/${version}"
fi

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT INT TERM

download() {
	if command -v curl >/dev/null; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null; then
		wget -qO "$2" "$1"
	elif command -v fetch >/dev/null; then
		fetch -o "$2" "$1"
	else
		echo "need curl, wget, or fetch" >&2
		exit 1
	fi
}

download "${base}/${asset}" "${tmp}/${asset}"
download "${base}/SHA256SUMS" "${tmp}/SHA256SUMS"

grep " ${asset}\$" "${tmp}/SHA256SUMS" >"${tmp}/expected"
(
	cd "${tmp}"
	if command -v sha256sum >/dev/null; then
		sha256sum -c expected >/dev/null
	elif command -v shasum >/dev/null; then
		shasum -a 256 -c expected >/dev/null
	elif command -v sha256 >/dev/null; then
		read -r checksum _ <expected \
			&& sha256 -c "${checksum}" "${asset}" >/dev/null
	else
		echo "need sha256sum, shasum, or sha256 for checksum verification" >&2
		exit 1
	fi
) || {
	echo "checksum verification failed for ${asset}" >&2
	exit 1
}

if [ -n "${ENVCTL_ATTEST:-}" ]; then
	if ! command -v gh >/dev/null; then
		echo "ENVCTL_ATTEST is set but gh is not installed" >&2
		exit 1
	fi
	if ! gh attestation verify "${tmp}/${asset}" -R "${repo}" >/dev/null; then
		echo "attestation verification failed for ${asset}" >&2
		exit 1
	fi
	echo "attestation verified: built by ${repo} CI"
fi

mkdir -p "${dir}"
install -m 755 "${tmp}/${asset}" "${dir}/envctl${ext}"
echo "installed ${asset} ${version} -> ${dir}/envctl${ext}"

case :${PATH}: in
	*:${dir}:*) ;;
	*) echo "note: ${dir} is not in PATH" >&2 ;;
esac
