import { platform, setup, verifyArchitecture } from "#action";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const commit = "a".repeat(40);

function executable(os, arch) {
	const bytes = Buffer.alloc(128);
	if (os === "linux") {
		Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]).copy(bytes);
		bytes.writeUInt16LE(arch === "amd64" ? 0x3e : 0xb7, 18);
	} else if (os === "darwin") {
		bytes.writeUInt32LE(0xfeedfacf);
		bytes.writeUInt32LE(arch === "amd64" ? 0x01000007 : 0x0100000c, 4);
	} else {
		bytes.write("MZ");
		bytes.writeUInt32LE(64, 60);
		bytes.writeUInt32LE(0x4550, 64);
		bytes.writeUInt16LE(arch === "amd64" ? 0x8664 : 0xaa64, 68);
	}
	return bytes;
}

function fixture(t, changes = {}) {
	const root = mkdtempSync(join(tmpdir(), "envctl-action-test-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const target = changes.target || { os: "linux", arch: "amd64" };
	const binary = changes.binary || executable(target.os, target.arch);
	const name = `envctl-${target.os}-${target.arch}${target.os === "windows" ? ".exe" : ""}`;
	const sums = Buffer.from(changes.sums ?? `${digest(binary)}  ${name}\n`);
	const release = {
		tag_name: "v0.7.0",
		draft: false,
		prerelease: false,
		assets: [
			{ id: 1, name, state: "uploaded", digest: `sha256:${digest(binary)}` },
			{ id: 2, name: "SHA256SUMS", state: "uploaded", digest: `sha256:${digest(sums)}` },
		],
		...changes.release,
	};
	const environment = {
		RUNNER_TEMP: root,
		GITHUB_PATH: join(root, "path"),
		GITHUB_OUTPUT: join(root, "output"),
		RUNNER_OS: { linux: "Linux", darwin: "macOS", windows: "Windows" }[target.os],
		RUNNER_ARCH: { amd64: "X64", arm64: "ARM64" }[target.arch],
		INPUT_TOKEN: "test-token",
		...changes.environment,
	};
	const calls = [];
	const execute = (command, args, options) => {
		calls.push({ command, args });
		if (command !== "gh") {
			assert.deepEqual(args, ["--version"]);
			assert.equal(calls.at(-2).args[0], "attestation", "verify provenance before execution");
			return changes.reported || "v0.7.0\n";
		}
		assert.equal(options.env.GH_TOKEN, "test-token");
		assert.equal(options.env.GH_REPO, "kjanat/envctl");
		assert.ok(!args.includes("--repo"));
		if (args[0] === "attestation") {
			assert.deepEqual(args.slice(3), /* dprint-ignore */ [
				"--owner", "kjanat", "--source-ref", "refs/tags/v0.7.0",
				"--source-digest", commit, "--signer-workflow", "kjanat/envctl/.github/workflows/release.yml",
			]);
			if (changes.attestationFails) throw new Error("Attestation verification failed");
			return "";
		}
		assert.equal(args[0], "api");
		const endpoint = args[1];
		assert.ok(endpoint.startsWith("repos/{owner}/{repo}/"));
		if (endpoint.endsWith("releases/latest") || endpoint.endsWith("releases/tags/v0.7.0")) {
			return JSON.stringify(release);
		}
		if (endpoint.endsWith("commits/v0.7.0")) {
			return JSON.stringify({ sha: commit, commit: { verification: { verified: !changes.unsigned } } });
		}
		assert.deepEqual(args.slice(2), ["-H", "Accept: application/octet-stream"]);
		if (endpoint.endsWith("releases/assets/1")) return changes.downloaded || binary;
		if (endpoint.endsWith("releases/assets/2")) return sums;
		throw new Error(`Unexpected endpoint: ${endpoint}`);
	};
	return { root, environment, execute, calls };
}

for (const os of ["linux", "darwin", "windows"]) {
	for (const arch of ["amd64", "arm64"]) {
		test(`install verified ${os}-${arch} and expose it to later steps`, t => {
			const f = fixture(t, { target: { os, arch } });
			const installed = setup(f.environment, f.execute);
			assert.equal(installed.version, "v0.7.0");
			assert.ok(existsSync(installed.path));
			assert.equal(readFileSync(f.environment.GITHUB_OUTPUT, "utf8"), `version=v0.7.0\npath=${installed.path}\n`);
			assert.equal(readFileSync(f.environment.GITHUB_PATH, "utf8"), `${dirname(installed.path)}\n`);
			assert.equal(f.calls.filter(call => call.args[1]?.endsWith("releases/latest")).length, 1);
		});
	}
}

const failures = /* dprint-ignore */ [
	["modified download", { downloaded: Buffer.from("modified") }, /digest mismatch/],
	["wrong checksum", { sums: `${"0".repeat(64)}  envctl-linux-amd64\n` }, /SHA256SUMS mismatch/],
	["duplicate checksum", { sums: `${"0".repeat(64)}  envctl-linux-amd64\n${"0".repeat(64)}  envctl-linux-amd64\n` }, /SHA256SUMS mismatch/],
	["missing asset", { release: { assets: [] } }, /exactly one uploaded/],
	["unsigned source commit", { unsigned: true }, /verified signed commit/],
	["failed provenance", { attestationFails: true }, /Attestation verification failed/],
	["mislabeled Windows ARM64", { target: { os: "windows", arch: "arm64" }, binary: executable("windows", "amd64") }, /does not match windows-arm64/],
	["incorrect embedded version", { reported: "v0.6.1\n" }, /expected v0.7.0/],
	["draft release", { release: { draft: true } }, /unexpected release/],
	["latest resolves to prerelease", { release: { prerelease: true } }, /unexpected release/],
	["invalid tag input", { environment: { INPUT_VERSION: "--repo=attacker/repo" } }, /exact release tag/],
	["unsupported architecture", { environment: { RUNNER_ARCH: "ARM" } }, /Unsupported runner/],
	["newline in installation path", { environment: { RUNNER_TEMP: "/tmp/invalid\npath" } }, /valid RUNNER_TEMP/],
];
for (const [name, changes, error] of failures) {
	test(`refuse ${name} without changing PATH or leaving an installation`, t => {
		const f = fixture(t, changes);
		assert.throws(() => setup(f.environment, f.execute), error);
		assert.ok(!existsSync(f.environment.GITHUB_PATH));
		assert.ok(!existsSync(f.environment.GITHUB_OUTPUT));
		assert.deepEqual(readdirSync(f.root), []);
	});
}

test("an exact version resolves directly without looking up latest", t => {
	const f = fixture(t, { environment: { INPUT_VERSION: "v0.7.0" } });
	setup(f.environment, f.execute);
	assert.equal(f.calls[0].args[1], "repos/{owner}/{repo}/releases/tags/v0.7.0");
});

test("malformed PE headers are rejected without reading outside the file", () => {
	const bytes = executable("windows", "arm64");
	bytes.writeUInt32LE(0xffffffff, 60);
	assert.throws(() => verifyArchitecture(bytes, { os: "windows", arch: "arm64" }), /does not match/);
	assert.throws(() => verifyArchitecture(Buffer.alloc(0), { os: "windows", arch: "arm64" }), /does not match/);
});

test("runner architecture selects the artifact even under an emulated shell", () => {
	assert.deepEqual(platform("Windows", "ARM64"), { os: "windows", arch: "arm64" });
});
