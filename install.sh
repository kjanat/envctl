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

build_from_source() {
	if [ -n "${ENVCTL_ATTEST:-}" ]; then
		echo "binary unavailable; ENVCTL_ATTEST requires an attested release binary" >&2
		exit 1
	fi
	source_method=git
	if ! command -v git >/dev/null; then
		source_method=archive
	fi
	for tool in install mkdir cp cmp mv sed cat; do
		if ! command -v "${tool}" >/dev/null; then
			echo "source build requires ${tool}; install it and retry" >&2
			exit 1
		fi
	done
	if [ "${source_method}" = archive ]; then
		for tool in tar gzip; do
			if ! command -v "${tool}" >/dev/null; then
				echo "source build without Git requires ${tool}; install it and retry" >&2
				exit 1
			fi
		done
	fi
	build_make=
	for candidate in gmake make mingw32-make; do
		if make_version=$("${candidate}" --version 2>/dev/null); then
			case ${make_version} in
				*'GNU Make'*)
					build_make=${candidate}
					break
					;;
				*) ;;
			esac
		fi
	done
	if [ -z "${build_make}" ]; then
		echo "source build requires GNU make (gmake, make, or mingw32-make)" >&2
		exit 1
	fi
	compiler=
	for candidate in cc clang gcc; do
		if command -v "${candidate}" >/dev/null; then
			compiler=${candidate}
			break
		fi
	done
	if [ -z "${compiler}" ]; then
		echo "source build requires a C11 compiler (cc, clang, or gcc)" >&2
		exit 1
	fi
	cat >"${tmp}/check.c" <<'EOF'
#include <stdio.h>
_Static_assert(sizeof(char) == 1, "C11 required");
int main(void) { return puts("C11 compiler works") < 0; }
EOF
	if ! "${compiler}" -std=c11 -o "${tmp}/check${ext}" "${tmp}/check.c"; then
		echo "source build requires working C11 headers and linker" >&2
		exit 1
	fi
	if [ "${version}" = latest ]; then
		download "https://api.github.com/repos/${repo}/releases/latest" "${tmp}/release.json"
		version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${tmp}/release.json")
	fi
	case ${version} in
		'' | *[!a-zA-Z0-9._+-]*)
			echo "cannot resolve a valid release tag for the source build" >&2
			exit 1
			;;
		*) ;;
	esac
	echo "building envctl ${version} from source"
	if [ "${source_method}" = git ]; then
		git clone --depth 1 --filter=blob:none --single-branch --no-checkout \
			--branch "${version}" "https://github.com/${repo}.git" "${tmp}/source"
		# stdin avoids MSYS rewriting the sparse patterns as Windows paths.
		printf '/Makefile\n/src/\n' | git -C "${tmp}/source" sparse-checkout set --no-cone --stdin
		git -C "${tmp}/source" checkout --detach "refs/tags/${version}"
	else
		download "https://github.com/${repo}/archive/refs/tags/${version}.tar.gz" "${tmp}/source.tar.gz"
		tar -tzf "${tmp}/source.tar.gz" >"${tmp}/archive-files"
		archive_root=$(sed -n '1{s:/$::;p;}' "${tmp}/archive-files")
		case ${archive_root} in
			'' | . | .. | *[!a-zA-Z0-9._+-]*)
				echo "invalid source archive root" >&2
				exit 1
				;;
			*) ;;
		esac
		mkdir -p "${tmp}/source"
		tar -xzf "${tmp}/source.tar.gz" -C "${tmp}/source" --strip-components=1 \
			"${archive_root}/Makefile" "${archive_root}/src"
	fi
	"${build_make}" -C "${tmp}/source" all "VERSION=${version}" "CC=${compiler}" "EXE=${ext}"
	built_version=$("${tmp}/source/envctl${ext}" --version)
	if [ "${built_version}" != "${version}" ]; then
		echo "source build version mismatch: expected ${version}, got ${built_version}" >&2
		exit 1
	fi
	cp "${tmp}/source/envctl${ext}" "${tmp}/${asset}"
}

# A failed download selects the source fallback; download returns the client's status.
# shellcheck disable=SC2310
if download "${base}/${asset}" "${tmp}/${asset}"; then
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

else
	echo "release binary ${asset} unavailable; checking source-build requirements" >&2
	build_from_source
fi

mkdir -p "${dir}"
install -m 755 "${tmp}/${asset}" "${dir}/envctl${ext}"
echo "installed ${asset} ${version} -> ${dir}/envctl${ext}"

case :${PATH}: in
	*:${dir}:*) ;;
	*) echo "note: ${dir} is not in PATH" >&2 ;;
esac
