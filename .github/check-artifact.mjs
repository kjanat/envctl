import { verifyArchitecture } from "#action";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import process from "node:process";

const file = resolve(process.argv[2]);
const expectedVersion = process.argv[3] || process.env.GITHUB_REF_NAME;
if (!expectedVersion) throw new Error("An expected release version is required");
const match = /^envctl-(linux|darwin|windows)-(amd64|arm64)(\.exe)?$/.exec(basename(file));
if (!match || (match[1] === "windows") !== Boolean(match[3])) throw new Error("Unexpected release artifact name");
verifyArchitecture(readFileSync(file), { os: match[1], arch: match[2] });
const version = execFileSync(file, ["--version"], { encoding: "utf8" }).trim();
if (version !== expectedVersion) throw new Error(`Unexpected artifact version: ${version}`);
console.log(`Verified ${basename(file)}: architecture and version ${version}`);
