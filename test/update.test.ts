// The weekly update check, install.sh and `nethound upgrade`. Installs use a local
// file:// "release" built from the source, so nothing touches the network.
import { beforeAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import pkg from "../package.json" with { type: "json" };
import {
	binaryName,
	compiled,
	decide,
	download,
	installKind,
	latestRelease,
	newer,
	readState,
	renameNotice,
	replaceBinary,
	replaceScript,
	sumFor,
	tarFile,
	updateNotice,
	upgradeCommand,
	WEEK,
} from "../src/update.ts";

const sha = (
	algorithm: string,
	b: Buffer | string,
	encoding: "hex" | "base64" = "hex",
) => createHash(algorithm).update(b).digest(encoding);

/** `text` with `line` inserted after its first line (the shebang stays first). */
function afterFirstLine(text: string, line: string): string {
	const [first, ...rest] = text.split("\n");
	return [first, line, ...rest].join("\n");
}

/** A gzipped ustar archive, as npm pack writes one. */
function tgz(files: Record<string, Buffer | string>): Buffer {
	const blocks: Buffer[] = [];
	for (const [name, body] of Object.entries(files)) {
		const data = Buffer.from(body);
		const h = Buffer.alloc(512);
		h.write(name, 0);
		h.write("0000644\0", 100);
		h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
		h.write("        ", 148);
		h.write("0", 156);
		h.write("ustar\0" + "00", 257);
		let sum = 0;
		for (const b of h) sum += b;
		h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
		blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
	}
	blocks.push(Buffer.alloc(1024));
	return gzipSync(Buffer.concat(blocks));
}

/**
 * A local release of `script` as `version`: the GitHub files, the npm package and the registry's
 * answer, all file: URLs. `files` are more GitHub files, such as binaries. `npm` replaces the script
 * inside the npm package, `sums` SHA256SUMS on GitHub, `npmSums` the copy in the npm package.
 */
function fakeRelease(
	script: Buffer | string,
	opts: {
		version?: string;
		npm?: string;
		sums?: string;
		npmSums?: string;
		files?: Record<string, Buffer | string>;
	} = {},
): Record<string, string> {
	const dir = mkdtempSync(join(tmpdir(), "nethound-release-"));
	const files = { "nethound.js": script, ...opts.files };
	for (const [name, data] of Object.entries(files))
		writeFileSync(join(dir, name), data);
	const sums = Object.entries(files)
		.map(([name, data]) => `${sha("sha256", data)}  ${name}\n`)
		.join("");
	writeFileSync(join(dir, "SHA256SUMS"), opts.sums ?? sums);
	const pkgTgz = tgz({
		"package/package.json": "{}",
		"package/dist/nethound.js": opts.npm ?? script,
		"package/dist/SHA256SUMS": opts.npmSums ?? sums,
	});
	writeFileSync(join(dir, "nethound.tgz"), pkgTgz);
	mkdirSync(join(dir, "registry"));
	writeFileSync(
		join(dir, "registry", "latest"),
		JSON.stringify({
			version: opts.version ?? "9.9.9",
			dist: {
				tarball: pathToFileURL(join(dir, "nethound.tgz")).href,
				integrity: `sha512-${sha("sha512", pkgTgz, "base64")}`,
			},
		}),
	);
	return {
		NETHOUND_BASE_URL: pathToFileURL(dir).href,
		NETHOUND_REGISTRY: pathToFileURL(join(dir, "registry")).href,
	};
}

describe("verified upgrades", () => {
	const script = "#!/usr/bin/env node\nconsole.log('new')\n";

	test("a release that matches SHA256SUMS and npm", async () => {
		const r = await latestRelease(fakeRelease(script));
		expect(r.version).toBe("9.9.9");
		expect(r.data.toString()).toBe(script);
	});
	test("refuses a checksum mismatch", () =>
		expect(
			latestRelease(
				fakeRelease(script, { sums: `${"0".repeat(64)}  nethound.js\n` }),
			),
		).rejects.toThrow("checksum mismatch"));
	test("refuses a GitHub file that npm didn't publish", () =>
		expect(
			latestRelease(fakeRelease(script, { npm: "console.log('other')\n" })),
		).rejects.toThrow("not the one published on npm"));
	test("a binary, listed in npm's SHA256SUMS too", async () => {
		const bin = Buffer.from("\x7fELF binary");
		const files = { "nethound-linux-x64": bin };
		const r = await latestRelease(
			fakeRelease(script, { files }),
			"nethound-linux-x64",
		);
		expect(r.data).toEqual(bin);
		await expect(
			latestRelease(
				fakeRelease(script, {
					files,
					npmSums: `${"0".repeat(64)}  nethound-linux-x64\n`,
				}),
				"nethound-linux-x64",
			),
		).rejects.toThrow("not the one npm lists");
		await expect(
			latestRelease(fakeRelease(script), "nethound-linux-x64"),
		).rejects.toThrow(); // not in that release
	});
	test("binary names, and telling a binary from a script", () => {
		expect(binaryName("linux", "x64")).toBe("nethound-linux-x64");
		expect(binaryName("darwin", "arm64")).toBe("nethound-darwin-arm64");
		expect(binaryName("win32", "x64")).toBe("nethound-windows-x64.exe");
		expect(binaryName("win32", "arm64")).toBeUndefined();
		expect(binaryName("freebsd", "x64")).toBeUndefined();
		expect(compiled("/$bunfs/root/nethound")).toBe(true);
		expect(compiled("B:\\~BUN\\root\\nethound.exe")).toBe(true);
		expect(compiled("/home/u/.local/bin/nethound")).toBe(false);
	});
	test("replaceBinary keeps the mode; on Windows the old one moves aside", () => {
		const dir = mkdtempSync(join(tmpdir(), "nethound-bin-"));
		const target = join(dir, "nethound.exe");
		writeFileSync(target, "old");
		chmodSync(target, 0o755);
		replaceBinary(target, Buffer.from("new"), true);
		expect(readFileSync(target, "utf8")).toBe("new");
		expect(readFileSync(`${target}.old`, "utf8")).toBe("old");
		replaceBinary(target, Buffer.from("newer"), true);
		expect(readFileSync(`${target}.old`, "utf8")).toBe("new");
		if (process.platform !== "win32")
			expect(statSync(target).mode & 0o777).toBe(0o755);
	});
	test("refuses plain http", () =>
		expect(
			latestRelease({ NETHOUND_REGISTRY: "http://registry.example" }),
		).rejects.toThrow("only https is allowed"));
	test("download refuses other schemes", () =>
		expect(download("ftp://x/y")).rejects.toThrow("only https"));
	test("SHA256SUMS lines, with or without the binary-mode star", () => {
		expect(sumFor("AB  nethound.js\ncd  install.sh\n", "nethound.js")).toBe(
			"ab",
		);
		expect(sumFor("ab *nethound.js\r\n", "nethound.js")).toBe("ab");
		expect(sumFor("ab  other.js\n", "nethound.js")).toBeUndefined();
	});

	// npm starts slowly on a cold Windows runner
	test("tarFile reads what npm pack writes", () => {
		const dir = mkdtempSync(join(tmpdir(), "nethound-pack-"));
		mkdirSync(join(dir, "dist"));
		writeFileSync(join(dir, "dist", "nethound.js"), script);
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ name: "pack-test", version: "1.0.0", files: ["dist"] }),
		);
		const r = spawnSync("npm", ["pack", "--silent", "--ignore-scripts"], {
			cwd: dir,
			encoding: "utf8",
			shell: process.platform === "win32",
		});
		expect(r.status).toBe(0);
		const packed = readFileSync(join(dir, r.stdout.trim()));
		expect(tarFile(packed, "package/dist/nethound.js")?.toString()).toBe(
			script,
		);
		expect(tarFile(packed, "package/nope")).toBeUndefined();
	}, 60_000);

	test.skipIf(process.platform === "win32")(
		"replaceScript keeps the file's mode and install.sh's choice of Bun",
		() => {
			const target = join(
				mkdtempSync(join(tmpdir(), "nethound-bin-")),
				"nethound",
			);
			writeFileSync(target, "#!/usr/bin/env bun\nold\n");
			chmodSync(target, 0o755);
			replaceScript(target, Buffer.from(script));
			expect(readFileSync(target, "utf8")).toBe(
				"#!/usr/bin/env bun\nconsole.log('new')\n",
			);
			expect(statSync(target).mode & 0o777).toBe(0o755);
		},
	);
});

describe("installKind", () => {
	const cases: [string, string][] = [
		["/opt/homebrew/Cellar/nethound/0.4.0/bin/nethound", "brew"],
		["C:\\Users\\u\\scoop\\apps\\nethound\\current\\nethound.exe", "scoop"],
		[
			"C:\\Users\\u\\AppData\\Local\\Microsoft\\WinGet\\Packages\\MichelSalib.nethound_x\\nethound.exe",
			"winget",
		],
		["/home/u/.local/bin/nethound", "standalone"],
		[
			"/home/u/.npm/_npx/0d1f/node_modules/@michelsalib/nethound/dist/nethound.js",
			"npx",
		],
		[
			"/tmp/bunx-1000-nethound@latest/node_modules/@michelsalib/nethound/dist/nethound.js",
			"bunx",
		],
		[
			"/home/u/.bun/install/global/node_modules/@michelsalib/nethound/dist/nethound.js",
			"bun",
		],
		["/usr/lib/node_modules/@michelsalib/nethound/dist/nethound.js", "npm"],
		[
			"/home/u/.nvm/versions/node/v24/lib/node_modules/@michelsalib/nethound/dist/nethound.js",
			"npm",
		],
		["/home/u/.local/bin/nethound", "standalone"],
		[
			"C:\\Users\\u\\AppData\\Local\\Programs\\nethound\\nethound.mjs",
			"standalone",
		],
		[
			"C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@michelsalib\\nethound\\dist\\nethound.js",
			"npm",
		],
		[
			"C:\\Users\\u\\AppData\\Local\\npm-cache\\_npx\\1a2b\\node_modules\\@michelsalib\\nethound\\dist\\nethound.js",
			"npx",
		],
		["/home/u/projects/nethound/src/cli.ts", "dev"],
		["/home/u/projects/nethound/dist/nethound.js", "dev"],
		// installed as netbeagle, before 0.8.0
		["/opt/homebrew/Cellar/netbeagle/0.8.0/bin/netbeagle", "brew"],
		["C:\\Users\\u\\scoop\\apps\\netbeagle\\current\\netbeagle.exe", "scoop"],
		["/usr/lib/node_modules/netbeagle/dist/netbeagle.js", "npm"],
		[
			"C:\\Users\\u\\AppData\\Local\\Programs\\netbeagle\\netbeagle.mjs",
			"standalone",
		],
	];
	for (const [path, kind] of cases)
		test(`${kind}: ${path}`, () =>
			expect(installKind(path)).toBe(kind as never));
	test("commands", () => {
		expect(upgradeCommand("npx")).toBe("npx @michelsalib/nethound@latest");
		expect(upgradeCommand("standalone")).toBe("nethound upgrade");
	});
});

describe("renameNotice", () => {
	test("nothing under the new name, nor in a checkout", () => {
		expect(renameNotice("/home/u/.local/bin/nethound")).toBeUndefined();
		expect(
			renameNotice(
				"/usr/lib/node_modules/@michelsalib/nethound/dist/nethound.js",
			),
		).toBeUndefined();
		expect(
			renameNotice("/home/u/projects/netbeagle/dist/nethound.js"),
		).toBeUndefined();
	});
	const cases: [string, string, boolean?][] = [
		[
			"/usr/lib/node_modules/netbeagle/dist/netbeagle.js",
			"npm uninstall -g netbeagle && npm install -g @michelsalib/nethound",
		],
		[
			"/home/u/.npm/_npx/0d1f/node_modules/netbeagle/dist/netbeagle.js",
			"npx @michelsalib/nethound",
		],
		[
			"/opt/homebrew/Cellar/netbeagle/0.8.0/bin/netbeagle",
			"brew uninstall netbeagle && brew install michelsalib/nethound/nethound",
		],
		[
			"C:\\Users\\u\\scoop\\apps\\netbeagle\\current\\netbeagle.exe",
			"scoop install nethound/nethound",
		],
		[
			"/home/u/.local/bin/netbeagle",
			"mv '/home/u/.local/bin/netbeagle' '/home/u/.local/bin/nethound'",
		],
		[
			"C:\\Users\\u\\AppData\\Local\\Programs\\netbeagle\\netbeagle.mjs",
			"install.ps1 | iex; Remove-Item -Recurse 'C:\\Users\\u\\AppData\\Local\\Programs\\netbeagle'",
			true,
		],
	];
	for (const [path, command, windows = false] of cases)
		test(path, () => {
			const notice = renameNotice(path, windows);
			expect(notice).toStartWith("netbeagle is now nethound");
			expect(notice).toContain(command);
		});
});

test("newer", () => {
	expect(newer("0.2.0", "0.1.9")).toBe(true);
	expect(newer("1.0.0", "0.99.99")).toBe(true);
	expect(newer("0.10.0", "0.9.0")).toBe(true);
	expect(newer("0.1.0", "0.1.0")).toBe(false);
	expect(newer("0.1.0", "0.2.0")).toBe(false);
	expect(newer("v0.2.0", "0.1.0")).toBe(true);
	expect(newer("garbage", "0.1.0")).toBe(false);
});

describe("decide", () => {
	const now = 100 * WEEK;
	test("first run checks, nothing to say", () =>
		expect(decide({}, "0.1.0", now)).toEqual({ check: true, notify: false }));
	test("checked recently: no check", () =>
		expect(decide({ checkedAt: now - 1000 }, "0.1.0", now).check).toBe(false));
	test("checked a week ago: check", () =>
		expect(decide({ checkedAt: now - WEEK }, "0.1.0", now).check).toBe(true));
	test("clock went back: check", () =>
		expect(decide({ checkedAt: now + 1000 }, "0.1.0", now).check).toBe(true));
	test("newer known: notify", () =>
		expect(
			decide({ checkedAt: now, latest: "0.2.0" }, "0.1.0", now).notify,
		).toBe(true));
	test("same version: quiet", () =>
		expect(
			decide({ checkedAt: now, latest: "0.1.0" }, "0.1.0", now).notify,
		).toBe(false));
	test("notified this week: quiet", () =>
		expect(
			decide(
				{ checkedAt: now, latest: "0.2.0", notifiedAt: now - 1000 },
				"0.1.0",
				now,
			).notify,
		).toBe(false));
	test("notified last week: again", () =>
		expect(
			decide(
				{ checkedAt: now, latest: "0.2.0", notifiedAt: now - WEEK },
				"0.1.0",
				now,
			).notify,
		).toBe(true));
});

describe("updateNotice", () => {
	const dir = mkdtempSync(join(tmpdir(), "nethound-update-"));
	const script = join(dir, "nethound");
	writeFileSync(script, "");
	const state = join(dir, "state", "update.json");
	const now = 100 * WEEK;

	test("shows once a week, with the command for the install", () => {
		// checked just now, so no background check starts
		mkdirSync(dirname(state), { recursive: true });
		writeFileSync(state, JSON.stringify({ checkedAt: now, latest: "9.0.0" }));
		expect(updateNotice("0.1.0", script, state, now)).toBe(
			"nethound 9.0.0 is available (you have 0.1.0). Update with: nethound upgrade",
		);
		expect(readState(state).notifiedAt).toBe(now);
		expect(updateNotice("0.1.0", script, state, now + 1000)).toBeUndefined();
		expect(
			updateNotice("0.1.0", script, state, now + WEEK - 1),
		).toBeUndefined();
	});

	test("a checkout never checks", () => {
		const src = join(dir, "cli.ts");
		writeFileSync(src, "");
		const fresh = join(dir, "other.json");
		expect(updateNotice("0.1.0", src, fresh, now)).toBeUndefined();
		expect(existsSync(fresh)).toBe(false);
	});

	test("a broken state file is ignored", () => {
		writeFileSync(state, "{not json");
		expect(readState(state)).toEqual({});
	});
});

// install.sh is POSIX sh only
describe.skipIf(process.platform === "win32")(
	"install.sh and nethound upgrade",
	() => {
		const root = join(import.meta.dir, "..");
		const release = mkdtempSync(join(tmpdir(), "nethound-release-"));
		const base = `file://${release}`;
		// a home of its own, never the real one
		const homeEnv = (home: string) => ({
			HOME: home,
			XDG_DATA_HOME: "",
			XDG_CONFIG_HOME: "",
		});
		const run = (
			cmd: string,
			args: string[],
			env: Record<string, string> = {},
		) =>
			spawnSync(cmd, args, {
				encoding: "utf8",
				env: { ...process.env, NETHOUND_NO_UPDATE_CHECK: "1", ...env },
			});

		beforeAll(() => {
			const r = spawnSync(
				"bun",
				[
					"build",
					"src/cli.ts",
					"--target=node",
					"--minify",
					"--outfile",
					join(release, "nethound.js"),
				],
				{
					cwd: root,
					encoding: "utf8",
				},
			);
			expect(r.status).toBe(0);
			const sum = createHash("sha256")
				.update(readFileSync(join(release, "nethound.js")))
				.digest("hex");
			writeFileSync(join(release, "SHA256SUMS"), `${sum}  nethound.js\n`);
			copyFileSync(join(root, "install.sh"), join(release, "install.sh"));
		});

		test("installs with completion, then upgrades in place", () => {
			const home = mkdtempSync(join(tmpdir(), "nethound-bin-"));
			const dir = join(home, "bin");
			const r = run("sh", [join(root, "install.sh")], {
				NETHOUND_BASE_URL: base,
				NETHOUND_INSTALL_DIR: dir,
				...homeEnv(home),
			});
			expect(r.stderr).toBe("");
			expect(r.stdout).toContain(
				`installed nethound ${pkg.version} in ${dir} (runs on node)`,
			);
			expect(r.stdout).toContain(`export PATH="${dir}:$PATH"`);
			expect(
				readFileSync(join(dir, "nethound"), "utf8").startsWith(
					"#!/usr/bin/env node\n",
				),
			).toBe(true);
			expect(run(join(dir, "nethound"), ["--version"]).stdout.trim()).toBe(
				pkg.version,
			);
			expect(
				readFileSync(
					join(
						home,
						".local",
						"share",
						"bash-completion",
						"completions",
						"nethound",
					),
					"utf8",
				),
			).toContain("nethound __complete");
			expect(r.stdout).toContain("bash completion:");
			expect(
				existsSync(
					join(home, ".config", "fish", "completions", "nethound.fish"),
				),
			).toBe(spawnSync("sh", ["-c", "command -v fish"]).status === 0);

			// upgrade replaces the file in place, checked against SHA256SUMS and npm
			const built = readFileSync(join(release, "nethound.js"));
			writeFileSync(
				join(dir, "nethound"),
				afterFirstLine(readFileSync(join(dir, "nethound"), "utf8"), "// old"),
			);
			const same = run(join(dir, "nethound"), ["upgrade"], {
				...fakeRelease(built, { version: pkg.version }),
				...homeEnv(home),
			});
			expect(same.stdout).toContain(
				`nethound ${pkg.version} is the latest version`,
			);
			const u = run(join(dir, "nethound"), ["upgrade"], {
				...fakeRelease(built),
				...homeEnv(home),
			});
			expect(u.status).toBe(0);
			// realpath: on macOS the temporary directory is a symlink into /private
			expect(u.stdout).toContain(
				`upgraded nethound ${pkg.version} to 9.9.9 in ${realpathSync(dir)}`,
			);
			expect(readFileSync(join(dir, "nethound"), "utf8")).not.toContain(
				"// old",
			);
			const bad = run(join(dir, "nethound"), ["upgrade"], {
				...fakeRelease(built, { npm: "console.log('evil')\n" }),
				...homeEnv(home),
			});
			expect(bad.status).toBe(1);
			expect(bad.stderr).toContain("nothing was changed");
		});

		test("refuses plain http and a malformed version", () => {
			const home = mkdtempSync(join(tmpdir(), "nethound-bin-"));
			const env = {
				NETHOUND_INSTALL_DIR: join(home, "bin"),
				...homeEnv(home),
			};
			const http = run("sh", [join(root, "install.sh")], {
				...env,
				NETHOUND_BASE_URL: "http://example.com",
			});
			expect(http.status).toBe(1);
			expect(http.stderr).toContain("must start with https://");
			const version = run("sh", [join(root, "install.sh")], {
				...env,
				NETHOUND_VERSION: "1.2; echo pwned",
			});
			expect(version.status).toBe(1);
			expect(version.stderr).toContain("must look like 0.2.1");
			expect(existsSync(join(home, "bin"))).toBe(false);
		});

		test("a download cut short runs nothing", () => {
			const text = readFileSync(join(root, "install.sh"), "utf8");
			const home = mkdtempSync(join(tmpdir(), "nethound-bin-"));
			const r = spawnSync("sh", ["-s"], {
				input: text.slice(0, Math.floor(text.length * 0.9)),
				encoding: "utf8",
				env: {
					...process.env,
					NETHOUND_BASE_URL: base,
					NETHOUND_INSTALL_DIR: join(home, "bin"),
					...homeEnv(home),
				},
			});
			expect(r.status).not.toBe(0);
			expect(r.stdout).toBe("");
			expect(existsSync(join(home, "bin"))).toBe(false);
		});

		test("refuses a download that doesn't match SHA256SUMS", () => {
			const bad = mkdtempSync(join(tmpdir(), "nethound-bad-"));
			writeFileSync(
				join(bad, "nethound.js"),
				"#!/usr/bin/env node\nconsole.log('evil')\n",
			);
			copyFileSync(join(release, "SHA256SUMS"), join(bad, "SHA256SUMS"));
			const dir = join(bad, "bin");
			const r = run("sh", [join(root, "install.sh")], {
				NETHOUND_BASE_URL: `file://${bad}`,
				NETHOUND_INSTALL_DIR: dir,
				...homeEnv(bad),
			});
			expect(r.status).toBe(1);
			expect(r.stderr).toContain("checksum mismatch");
			expect(existsSync(join(dir, "nethound"))).toBe(false);
		});

		// only Bun on PATH: the installed file must run on bun
		// stdout is null without sh: this body still runs on Windows, where the tests are skipped
		const bun =
			spawnSync("sh", ["-c", "command -v bun"], {
				encoding: "utf8",
			}).stdout?.trim() ?? "";
		const noNode = (path: string) =>
			spawnSync("sh", ["-c", "command -v node"], { env: { PATH: path } })
				.status !== 0;
		const bunPath = `${dirname(bun)}:/usr/bin:/bin`;
		test.skipIf(!bun || !noNode(bunPath))(
			"falls back to bun without node",
			() => {
				const dir = join(mkdtempSync(join(tmpdir(), "nethound-bun-")), "bin");
				const r = run("sh", [join(root, "install.sh")], {
					PATH: bunPath,
					NETHOUND_BASE_URL: base,
					NETHOUND_INSTALL_DIR: dir,
					...homeEnv(dirname(dir)),
				});
				expect(r.stdout).toContain("(runs on bun)");
				expect(
					readFileSync(join(dir, "nethound"), "utf8").startsWith(
						"#!/usr/bin/env bun\n",
					),
				).toBe(true);
			},
		);

		test("other installs are told their own command", () => {
			const r = run("bun", [join(root, "src", "cli.ts"), "upgrade"]);
			expect(r.stdout).toContain("git pull && bun run build");
		});
	},
);

describe.skipIf(process.platform !== "win32")(
	"install.ps1 and nethound upgrade on Windows",
	() => {
		const root = join(import.meta.dir, "..");
		const release = mkdtempSync(join(tmpdir(), "nethound-release-"));
		const base = pathToFileURL(release).href;
		const run = (
			cmd: string,
			args: string[],
			env: Record<string, string> = {},
		) =>
			spawnSync(cmd, args, {
				encoding: "utf8",
				shell: cmd.endsWith(".cmd"),
				env: { ...process.env, NETHOUND_NO_UPDATE_CHECK: "1", ...env },
			});
		const install = (env: Record<string, string>) =>
			run(
				"powershell.exe",
				[
					"-NoProfile",
					"-NonInteractive",
					"-ExecutionPolicy",
					"Bypass",
					"-File",
					join(root, "install.ps1"),
				],
				env,
			);

		beforeAll(() => {
			const r = spawnSync(
				"bun",
				[
					"build",
					"src/cli.ts",
					"--target=node",
					"--minify",
					"--outfile",
					join(release, "nethound.js"),
				],
				{ cwd: root, encoding: "utf8" },
			);
			expect(r.status).toBe(0);
			const sum = createHash("sha256")
				.update(readFileSync(join(release, "nethound.js")))
				.digest("hex");
			writeFileSync(join(release, "SHA256SUMS"), `${sum}  nethound.js\n`);
			copyFileSync(join(root, "install.ps1"), join(release, "install.ps1"));
		});

		test("installs with completion, then upgrades in place", () => {
			const dir = join(mkdtempSync(join(tmpdir(), "nethound-bin-")), "bin");
			const r = install({
				NETHOUND_BASE_URL: base,
				NETHOUND_INSTALL_DIR: dir,
			});
			expect(r.stderr).toBe("");
			expect(r.stdout).toContain(
				`installed nethound ${pkg.version} in ${dir} (runs on node)`,
			);
			expect(r.stdout).toContain(`SetEnvironmentVariable('Path'`);
			const cmd = join(dir, "nethound.cmd");
			expect(run(cmd, ["--version"]).stdout.trim()).toBe(pkg.version);

			// upgrade replaces nethound.mjs in place, checked against SHA256SUMS and npm
			const mjs = join(dir, "nethound.mjs");
			writeFileSync(mjs, afterFirstLine(readFileSync(mjs, "utf8"), "// old"));
			const u = run(
				cmd,
				["upgrade"],
				fakeRelease(readFileSync(join(release, "nethound.js"))),
			);
			expect(u.status).toBe(0);
			expect(u.stdout).toContain(
				`upgraded nethound ${pkg.version} to 9.9.9 in ${realpathSync(dir)}`,
			);
			expect(readFileSync(mjs, "utf8")).not.toContain("// old");
		});

		test("refuses a download that doesn't match SHA256SUMS", () => {
			const bad = mkdtempSync(join(tmpdir(), "nethound-bad-"));
			writeFileSync(join(bad, "nethound.js"), "console.log('evil')\n");
			copyFileSync(join(release, "SHA256SUMS"), join(bad, "SHA256SUMS"));
			const dir = join(bad, "bin");
			const r = install({
				NETHOUND_BASE_URL: pathToFileURL(bad).href,
				NETHOUND_INSTALL_DIR: dir,
			});
			expect(r.status).toBe(1);
			expect(r.stderr).toContain("checksum mismatch");
			expect(existsSync(join(dir, "nethound.mjs"))).toBe(false);
		});
	},
);

// the binary for this machine, built from the source, installed and upgraded the way users do
describe.skipIf(!binaryName())("standalone binary: install and upgrade", () => {
	const root = join(import.meta.dir, "..");
	const name = binaryName() ?? "";
	const windows = process.platform === "win32";
	const release = mkdtempSync(join(tmpdir(), "nethound-release-"));
	const run = (cmd: string, args: string[], env: Record<string, string> = {}) =>
		spawnSync(cmd, args, {
			encoding: "utf8",
			env: { ...process.env, NETHOUND_NO_UPDATE_CHECK: "1", ...env },
		});
	let binary: Buffer;

	beforeAll(() => {
		const r = spawnSync(
			"bun",
			[
				"build",
				"src/cli.ts",
				"--compile",
				"--minify",
				"--outfile",
				join(release, name),
			],
			{ cwd: root, encoding: "utf8" },
		);
		expect(r.status).toBe(0);
		binary = readFileSync(join(release, name));
		writeFileSync(
			join(release, "SHA256SUMS"),
			`${sha("sha256", binary)}  ${name}\n`,
		);
	}, 120_000);

	test("installs without Node or Bun, then upgrades itself", () => {
		const home = mkdtempSync(join(tmpdir(), "nethound-bin-"));
		const dir = join(home, "bin");
		const env = {
			NETHOUND_BASE_URL: pathToFileURL(release).href,
			NETHOUND_INSTALL_DIR: dir,
			NETHOUND_BINARY: "1",
			NETHOUND_NO_COMPLETION: "1",
			HOME: home,
		};
		const r = windows
			? run(
					"powershell.exe",
					[
						"-NoProfile",
						"-NonInteractive",
						"-ExecutionPolicy",
						"Bypass",
						"-File",
						join(root, "install.ps1"),
					],
					env,
				)
			: run("sh", [join(root, "install.sh")], env);
		expect(r.stderr).toBe("");
		expect(r.stdout).toContain(
			`installed nethound ${pkg.version} in ${dir} (standalone binary)`,
		);
		const exe = join(dir, windows ? "nethound.exe" : "nethound");
		expect(run(exe, ["--version"]).stdout.trim()).toBe(pkg.version);
		if (windows) expect(existsSync(join(dir, "nethound.cmd"))).toBe(false);

		const files = { [name]: binary };
		const bad = run(exe, ["upgrade"], {
			...fakeRelease("x", {
				files,
				npmSums: `${"0".repeat(64)}  ${name}\n`,
			}),
			HOME: home,
		});
		expect(bad.status).toBe(1);
		expect(bad.stderr).toContain("nothing was changed");

		const u = run(exe, ["upgrade"], {
			...fakeRelease("x", { files }),
			HOME: home,
		});
		expect(u.stderr).toBe("");
		// native: also expands Windows short names (RUNNER~1), as the binary's own path does
		expect(u.stdout).toContain(
			`upgraded nethound ${pkg.version} to 9.9.9 in ${realpathSync.native(dir)}`,
		);
		expect(existsSync(`${exe}.old`)).toBe(windows);
		expect(run(exe, ["--version"]).stdout.trim()).toBe(pkg.version);
	}, 120_000);
});
