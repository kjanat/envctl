import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, chmodSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const repo = "kjanat/envctl";
const workflow = `${repo}/.github/workflows/release.yml`;
const tagPattern = /^v\d+\.\d+\.\d+(?:-[\da-zA-Z.-]+)?$/;

export function platform(os, architecture) {
	const targetOS = { Linux: "linux", macOS: "darwin", Windows: "windows" }[os];
	const arch = { X64: "amd64", ARM64: "arm64" }[architecture];
	if (!targetOS || !arch) throw new Error(`Unsupported runner: ${os}/${architecture}`);
	return { os: targetOS, arch };
}

export function verifyArchitecture(bytes, { os, arch }) {
	let valid = false;
	if (os === "linux" && bytes.length >= 20) {
		valid = bytes.subarray(0, 6).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]))
			&& bytes.readUInt16LE(18) === (arch === "amd64" ? 0x3e : 0xb7);
	} else if (os === "darwin" && bytes.length >= 8) {
		valid = bytes.readUInt32LE(0) === 0xfeedfacf
			&& bytes.readUInt32LE(4) === (arch === "amd64" ? 0x01000007 : 0x0100000c);
	} else if (os === "windows" && bytes.length >= 64 && bytes.toString("ascii", 0, 2) === "MZ") {
		const offset = bytes.readUInt32LE(60);
		valid = offset <= bytes.length - 6 && bytes.readUInt32LE(offset) === 0x4550
			&& bytes.readUInt16LE(offset + 4) === (arch === "amd64" ? 0x8664 : 0xaa64);
	}
	if (!valid) throw new Error(`Release binary does not match ${os}-${arch}; refusing to install it`);
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function setup(environment = process.env, execute = execFileSync) {
	const requested = environment.INPUT_VERSION?.trim() || "latest";
	if (requested !== "latest" && !tagPattern.test(requested)) {
		throw new Error("version must be latest or an exact release tag such as v0.7.0");
	}
	for (const name of ["RUNNER_TEMP", "GITHUB_PATH", "GITHUB_OUTPUT"]) {
		if (!environment[name] || /[\r\n]/.test(environment[name])) throw new Error(`A valid ${name} is required`);
	}
	const target = platform(environment.RUNNER_OS, environment.RUNNER_ARCH);
	const ext = target.os === "windows" ? ".exe" : "";
	const assetName = `envctl-${target.os}-${target.arch}${ext}`;
	const commandEnv = { ...environment, GH_REPO: repo, GH_TOKEN: environment.INPUT_TOKEN || environment.GH_TOKEN };
	const gh = (args, binary = false) =>
		execute("gh", args, {
			env: commandEnv,
			encoding: binary ? undefined : "utf8",
			maxBuffer: 16 * 1024 * 1024,
			stdio: ["ignore", "pipe", "pipe"],
		});
	const api = path => JSON.parse(gh(["api", `repos/{owner}/{repo}/${path}`]));
	const release = api(requested === "latest" ? "releases/latest" : `releases/tags/${requested}`);
	if (
		!tagPattern.test(release.tag_name) || release.draft
		|| (requested === "latest" && release.prerelease)
		|| (requested !== "latest" && release.tag_name !== requested)
	) throw new Error("GitHub returned an unexpected release");
	const version = release.tag_name;
	const commit = api(`commits/${version}`);
	if (!/^[a-f0-9]{40}$/.test(commit.sha) || commit.commit?.verification?.verified !== true) {
		throw new Error("The release target must be a verified signed commit");
	}
	const directory = mkdtempSync(join(environment.RUNNER_TEMP, "envctl-"));
	try {
		const download = name => {
			const assets = release.assets.filter(asset => asset.name === name);
			if (
				assets.length !== 1 || assets[0].state !== "uploaded"
				|| !Number.isSafeInteger(assets[0].id) || assets[0].id <= 0
				|| !/^sha256:[a-f0-9]{64}$/.test(assets[0].digest)
			) throw new Error(`Release must contain exactly one uploaded ${name} with a SHA-256 digest`);
			const bytes = gh(/* dprint-ignore */ [
				"api", `repos/{owner}/{repo}/releases/assets/${assets[0].id}`,
				"-H", "Accept: application/octet-stream",
			], true);
			if (`sha256:${sha256(bytes)}` !== assets[0].digest) throw new Error(`GitHub asset digest mismatch for ${name}`);
			writeFileSync(join(directory, name), bytes, { flag: "wx", mode: 0o600 });
			return bytes;
		};
		const binary = download(assetName);
		const sums = download("SHA256SUMS").toString("utf8");
		const entries = sums.split(/\r?\n/).map(line => /^([a-f0-9]{64}) [ *](.+)$/.exec(line))
			.filter(entry => entry?.[2] === assetName);
		if (entries.length !== 1 || entries[0][1] !== sha256(binary)) {
			throw new Error(`SHA256SUMS mismatch for ${assetName}`);
		}
		verifyArchitecture(binary, target);
		// Attestation lookup requires --owner or --repo and does not use GH_REPO.
		// The workflow identity and source checks constrain verification to this release.
		gh(/* dprint-ignore */ [
			"attestation", "verify",
			join(directory, assetName),
			"--owner", repo.split("/")[0],
			"--source-ref", `refs/tags/${version}`,
			"--source-digest", commit.sha,
			"--signer-workflow", workflow,
		]);
		const executable = join(directory, `envctl${ext}`);
		renameSync(join(directory, assetName), executable);
		chmodSync(executable, 0o755);
		const reported = execute(executable, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
		if (reported !== version) throw new Error(`Binary reports ${reported}; expected ${version}`);
		appendFileSync(environment.GITHUB_OUTPUT, `version=${version}\npath=${executable}\n`);
		appendFileSync(environment.GITHUB_PATH, `${directory}\n`);
		console.log(
			`Installed envctl ${version} (${target.os}-${target.arch}); checksum, architecture, and provenance verified.`,
		);
		return { version, path: executable };
	} catch (error) {
		rmSync(directory, { recursive: true, force: true });
		throw error;
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	try {
		setup();
	} catch (error) {
		console.error(`envctl setup failed: ${error.message}`);
		process.exitCode = 1;
	}
}
