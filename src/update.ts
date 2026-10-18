// Weekly update check. The registry is asked at most once a week, by a detached
// background process, so no command waits on the network; a later run prints the notice.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	mkdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

export const REPO = "michelsalib/nethound";
const REGISTRY = "https://registry.npmjs.org/@michelsalib/nethound";
export const WEEK = 7 * 24 * 3600 * 1000;

/**
 * A standalone binary (bun build --compile): its script lives in Bun's virtual file system
 * (/$bunfs/root/… or B:\\~BUN\\root\\… on Windows), and the file on disk is process.execPath.
 */
export const compiled = (argv1 = process.argv[1] ?? "") =>
	/[\\/](\$bunfs|~BUN)[\\/]/.test(argv1);

/** The file this nethound runs from: the script, or the binary. */
export const selfPath = () =>
	compiled() ? process.execPath : (process.argv[1] ?? process.execPath);

/** The release file holding the binary for this platform, or undefined when there is none. */
export function binaryName(
	platform: string = process.platform,
	arch: string = process.arch,
): string | undefined {
	const os = { linux: "linux", darwin: "darwin", win32: "windows" }[platform];
	if (!os || !["x64", "arm64"].includes(arch)) return undefined;
	if (os === "windows" && arch !== "x64") return undefined;
	return `nethound-${os}-${arch}${os === "windows" ? ".exe" : ""}`;
}

/** Where the weekly check keeps what it learnt: $XDG_STATE_HOME (~/.local/state), or on Windows
 * %LOCALAPPDATA%, where apps keep theirs. */
export function stateFile(
	env: Record<string, string | undefined> = process.env,
	home = homedir(),
	windows = process.platform === "win32",
): string {
	const dir = windows
		? env.LOCALAPPDATA || join(home, "AppData", "Local")
		: env.XDG_STATE_HOME || join(home, ".local", "state");
	return join(dir, "nethound", "update.json");
}

/** How this copy of nethound was installed, which decides how to update it. */
export type InstallKind =
	| "npx"
	| "bunx"
	| "bun"
	| "npm"
	| "brew"
	| "scoop"
	| "winget"
	| "standalone"
	| "dev";

export function installKind(script: string): InstallKind {
	const p = script.replaceAll("\\", "/");
	if (/\/Cellar\/(nethound|netbeagle)\//.test(p)) return "brew";
	if (/\/scoop\/apps\/(nethound|netbeagle)\//i.test(p)) return "scoop";
	if (/\/WinGet\/(Packages|Links)\//i.test(p)) return "winget";
	if (p.includes("/_npx/")) return "npx";
	if (p.includes("/bunx-")) return "bunx";
	if (p.includes("/.bun/install/global/")) return "bun";
	if (p.includes("/node_modules/")) return "npm";
	// install.ps1 installs nethound.mjs (with nethound.cmd next to it); before 0.8.0, netbeagle.mjs
	if (/\/(nethound|netbeagle)\.mjs$/.test(p)) return "standalone";
	// a checkout: src/cli.ts or dist/nethound.js; install.sh installs a file named plain `nethound`
	if (/\.[cm]?[jt]s$/.test(p)) return "dev";
	return "standalone";
}

export function upgradeCommand(kind: InstallKind): string {
	switch (kind) {
		case "npx":
			return "npx @michelsalib/nethound@latest";
		case "bunx":
			return "bunx @michelsalib/nethound@latest";
		case "bun":
			return "bun add -g @michelsalib/nethound@latest";
		case "npm":
			return "npm install -g @michelsalib/nethound@latest";
		case "brew":
			return "brew upgrade nethound";
		case "scoop":
			return "scoop update nethound";
		case "winget":
			return "winget upgrade nethound";
		case "standalone":
			return "nethound upgrade";
		case "dev":
			return "git pull && bun run build";
	}
}

/**
 * How to move to nethound, when this copy still runs under its name before 0.8.0, netbeagle (the npm
 * package, the Homebrew formula, the Scoop app, or the file install.sh or install.ps1 wrote); undefined
 * otherwise. 0.8.0 was published under both names, so that older copies could update and land here.
 */
export function renameNotice(
	script: string,
	windows = process.platform === "win32",
): string | undefined {
	const p = script.replaceAll("\\", "/");
	if (
		!/\/(node_modules|Cellar|scoop\/apps)\/netbeagle\/|\/netbeagle(\.\w+)?$/i.test(
			p,
		)
	)
		return undefined;
	const command = (() => {
		const kind = installKind(script);
		switch (kind) {
			case "npx":
			case "bunx":
				return `${kind} @michelsalib/nethound`;
			case "bun":
				return "bun remove -g netbeagle && bun add -g @michelsalib/nethound";
			case "npm":
				return "npm uninstall -g netbeagle && npm install -g @michelsalib/nethound";
			case "brew":
				return "brew uninstall netbeagle && brew install michelsalib/nethound/nethound";
			case "scoop":
				return "scoop uninstall netbeagle; scoop bucket add nethound https://github.com/michelsalib/scoop-nethound; scoop install nethound/nethound";
			case "dev":
				return undefined;
			default:
				// the same file under the new name: it updates itself from nethound's releases already
				return windows
					? `irm https://github.com/${REPO}/releases/latest/download/install.ps1 | iex; Remove-Item -Recurse '${script.replace(/[\\/][^\\/]*$/, "")}'`
					: `mv '${script}' '${script.replace(/netbeagle$/i, "nethound")}'`;
		}
	})();
	return (
		command &&
		`netbeagle is now nethound: same tool, new name. Switch with:\n  ${command}`
	);
}

/** True when version `a` is newer than `b`; only major.minor.patch counts. */
export function newer(a: string, b: string): boolean {
	const parse = (v: string) =>
		(v.match(/^v?(\d+)\.(\d+)\.(\d+)/) ?? []).slice(1).map(Number);
	const [x, y] = [parse(a), parse(b)];
	if (x.length !== 3 || y.length !== 3) return false;
	for (let i = 0; i < 3; i++)
		if (x[i] !== y[i]) return (x[i] ?? 0) > (y[i] ?? 0);
	return false;
}

export interface UpdateState {
	/** when the registry was last asked (ms) */
	checkedAt?: number;
	/** the latest version it reported */
	latest?: string;
	/** when the notice was last shown (ms) */
	notifiedAt?: number;
}

/** Pure decision: ask the registry now? show the notice now? */
export function decide(
	state: UpdateState,
	current: string,
	now: number,
): { check: boolean; notify: boolean } {
	const due = (t?: number) => t === undefined || now - t >= WEEK || t > now;
	return {
		check: due(state.checkedAt),
		notify:
			state.latest !== undefined &&
			newer(state.latest, current) &&
			due(state.notifiedAt),
	};
}

export function readState(file: string): UpdateState {
	try {
		const s = JSON.parse(readFileSync(file, "utf8"));
		return typeof s === "object" && s ? s : {};
	} catch {
		return {};
	}
}

function writeState(file: string, state: UpdateState): void {
	mkdirSync(dirname(file), { recursive: true });
	const tmp = `${file}.${process.pid}.tmp`;
	writeFileSync(tmp, `${JSON.stringify(state)}\n`);
	renameSync(tmp, file);
}

/**
 * Called at the start of a command. Starts a background check when one is due and
 * returns the notice to print at the end, if a newer version is known and the
 * notice wasn't shown this week. Never throws: an update check must not break a command.
 */
export function updateNotice(
	current: string,
	script: string,
	stateFile: string,
	now = Date.now(),
): string | undefined {
	try {
		const kind = installKind(realpathSync(script));
		if (kind === "dev") return undefined;
		const state = readState(stateFile);
		const { check, notify } = decide(state, current, now);
		if (check) {
			// recorded first, so a failing network doesn't start a check on every run
			writeState(stateFile, { ...state, checkedAt: now });
			// a binary runs itself; a script runs on the same node or bun as now
			const args = compiled() ? [] : [script];
			spawn(process.execPath, [...args, "__update-check", stateFile], {
				detached: true,
				stdio: "ignore",
				windowsHide: true,
			}).unref();
		}
		if (!notify) return undefined;
		writeState(stateFile, { ...readState(stateFile), notifiedAt: now });
		return `nethound ${state.latest} is available (you have ${current}). Update with: ${upgradeCommand(kind)}`;
	} catch {
		return undefined;
	}
}

/** The hidden `__update-check` command, run in the background by updateNotice. */
export async function fetchLatest(stateFile: string): Promise<void> {
	const res = await fetch(`${REGISTRY}/latest`, {
		signal: AbortSignal.timeout(10_000),
		headers: { accept: "application/json" },
	});
	if (!res.ok) return;
	const { version } = (await res.json()) as { version?: unknown };
	if (typeof version !== "string") return;
	writeState(stateFile, {
		...readState(stateFile),
		checkedAt: Date.now(),
		latest: version,
	});
}

/** Downloads only over https (or from a local file: for mirrors and tests): never plain http. */
export async function download(url: string): Promise<Buffer> {
	if (url.startsWith("file:")) return readFileSync(fileURLToPath(url));
	if (!url.startsWith("https://"))
		throw new Error(`refusing to download ${url}: only https is allowed`);
	const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
	if (!res.ok) throw new Error(`could not download ${url}: HTTP ${res.status}`);
	return Buffer.from(await res.arrayBuffer());
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/** The hash SHA256SUMS lists for `name`, as sha256sum prints it. */
export function sumFor(sums: string, name: string): string | undefined {
	for (const line of sums.split(/\r?\n/)) {
		const [sum, file] = line.trim().split(/\s+/, 2);
		if (file === name || file === `*${name}`) return sum?.toLowerCase();
	}
	return undefined;
}

/** One file's content from a .tgz such as an npm package; only plain ustar entries, which npm writes. */
export function tarFile(tgz: Buffer, path: string): Buffer | undefined {
	const tar = gunzipSync(tgz);
	const text = (at: number, len: number) =>
		tar.toString("utf8", at, at + len).replace(/\0.*$/s, "");
	for (let at = 0; at + 512 <= tar.length; ) {
		const name = text(at, 100);
		if (!name) return undefined; // the zero blocks at the end
		const prefix = text(at + 345, 155);
		const size = Number.parseInt(text(at + 124, 12).trim() || "0", 8);
		const type = text(at + 156, 1);
		const full = prefix ? `${prefix}/${name}` : name;
		if (full === path && (type === "0" || type === ""))
			return tar.subarray(at + 512, at + 512 + size);
		at += 512 + Math.ceil(size / 512) * 512;
	}
	return undefined;
}

export interface Release {
	version: string;
	/** The release file: nethound.js, the same bytes on GitHub and on npm, or a binary. */
	data: Buffer;
}

/**
 * The latest nethound's `file` (nethound.js, or a binary such as nethound-linux-x64), checked twice:
 * against the release's SHA256SUMS on GitHub, and against npm. npm has the same nethound.js, byte for
 * byte, and the same SHA256SUMS, which lists the binaries. Replacing it means compromising both
 * GitHub and npm. NETHOUND_REGISTRY and NETHOUND_BASE_URL point elsewhere (mirrors, tests).
 */
export async function latestRelease(
	env: Record<string, string | undefined>,
	file = "nethound.js",
): Promise<Release> {
	const registry = env.NETHOUND_REGISTRY ?? REGISTRY;
	const meta = JSON.parse(
		(await download(`${registry}/latest`)).toString(),
	) as {
		version?: unknown;
		dist?: { tarball?: unknown; integrity?: unknown };
	};
	const { version } = meta;
	const tarball = meta.dist?.tarball;
	const integrity = meta.dist?.integrity;
	if (
		typeof version !== "string" ||
		!/^\d+\.\d+\.\d+$/.test(version) ||
		typeof tarball !== "string" ||
		typeof integrity !== "string"
	)
		throw new Error(`unexpected answer from ${registry}/latest`);

	const base =
		env.NETHOUND_BASE_URL ??
		`https://github.com/${REPO}/releases/download/v${version}`;
	const data = await download(`${base}/${file}`);
	const expected = sumFor(
		(await download(`${base}/SHA256SUMS`)).toString(),
		file,
	);
	if (!expected) throw new Error(`SHA256SUMS has no entry for ${file}`);
	if (sha256(data) !== expected)
		throw new Error(`checksum mismatch for ${file}`);

	const tgz = await download(tarball);
	const [algorithm, digest] = integrity.split("-", 2);
	if (
		algorithm !== "sha512" ||
		createHash("sha512").update(tgz).digest("base64") !== digest
	)
		throw new Error(
			`the npm package for ${version} doesn't match its integrity`,
		);
	if (file === "nethound.js") {
		const published = tarFile(tgz, "package/dist/nethound.js");
		if (!published?.equals(data))
			throw new Error(
				`nethound.js on GitHub is not the one published on npm for ${version}`,
			);
	} else {
		const sums = tarFile(tgz, "package/dist/SHA256SUMS");
		if (!sums || sumFor(sums.toString(), file) !== expected)
			throw new Error(
				`${file} on GitHub is not the one npm lists for ${version}`,
			);
	}
	return { version, data };
}

/**
 * Put the new script in place of `target`: written beside it, then renamed over it, so a running
 * nethound is never half-written. install.sh rewrites the first line for Bun; that choice is kept.
 */
export function replaceScript(target: string, script: Buffer): void {
	const bun = readFileSync(target, "utf8").startsWith("#!/usr/bin/env bun");
	const content = bun
		? Buffer.from(
				script.toString("utf8").replace(/^#!.*/, "#!/usr/bin/env bun"),
			)
		: script;
	const tmp = join(dirname(target), `.${basename(target)}.new`);
	rmSync(tmp, { force: true });
	writeFileSync(tmp, content, {
		mode: statSync(target).mode & 0o7777,
		flag: "wx",
	});
	renameSync(tmp, target);
}

/**
 * Put the new binary in place of `target`, keeping its mode. Windows can't overwrite a running
 * program, but it can rename it: the old one moves aside to `target.old`, removed on the next upgrade.
 */
export function replaceBinary(
	target: string,
	data: Buffer,
	windows = process.platform === "win32",
): void {
	const tmp = join(dirname(target), `.${basename(target)}.new`);
	const old = `${target}.old`;
	rmSync(tmp, { force: true });
	try {
		rmSync(old, { force: true });
	} catch {} // still running: it goes next time
	writeFileSync(tmp, data, {
		mode: statSync(target).mode & 0o7777,
		flag: "wx",
	});
	if (windows) renameSync(target, old);
	renameSync(tmp, target);
}
