// The published build must run on plain Node, not only Bun, and on the real machine.
import { beforeAll, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { banner } from "../src/logo.ts";

const root = join(import.meta.dir, "..");
const hasNode = spawnSync("node", ["--version"]).status === 0;

const run = (...args: string[]) =>
	spawnSync("node", ["dist/nethound.js", ...args], {
		cwd: root,
		encoding: "utf8",
	});

beforeAll(() => {
	const r = spawnSync("bun", ["run", "build"], { cwd: root, encoding: "utf8" });
	if (r.status !== 0) throw new Error(r.stderr);
});

test.skipIf(!hasNode)("--version and --help", () => {
	// piped: plain text, without the logo
	expect(run("--version").stdout).toMatch(/^\d+\.\d+\.\d+\n$/);
	expect(run("--help").stdout).toStartWith("nethound ");
	expect(run("--help").stdout).not.toContain("▀");
	expect(run("--help").stdout).toContain("who PORT");
	// the sibling, from the same pack
	expect(run("--help").stdout).toContain("npx @michelsalib/envhound");
	const help = run("who", "--help");
	expect(help.stdout).toStartWith("Usage: nethound who PORT");
	expect(help.stdout).toContain("--show-secrets");
	expect(run("help", "if").stdout).toStartWith("Usage: nethound interfaces");
});

test("banner puts the text beside the logo, or under it on a narrow terminal", () => {
	const wide = banner(["nethound 1.2.3"], {
		color: false,
		truecolor: false,
		columns: 100,
	});
	expect(wide).toMatch(/\S +nethound 1\.2\.3\n/);
	expect(wide).not.toContain("\x1b[");
	expect(
		banner(["nethound 1.2.3"], {
			color: false,
			truecolor: false,
			columns: 40,
		}),
	).toEndWith("\n\n  nethound 1.2.3\n");
	const color = banner([], { color: true, truecolor: false });
	expect(color).toContain("\x1b[38;5;173m");
	// the watched port's link light blinks
	expect(color).toContain("\x1b[5;38;5;114;");
	expect(banner([], { color: true, truecolor: true })).toContain(
		"\x1b[38;2;224;138;58m",
	);
});

test.skipIf(!hasNode)(
	"usage errors exit 2 and point at the command's help",
	() => {
		const r = run("who", "http");
		expect(r.status).toBe(2);
		expect(r.stderr).toContain("nethound who --help");
		expect(run("nope").status).toBe(2);
		expect(run("--bogus").status).toBe(2);
	},
);

test.skipIf(!hasNode)(
	"every command runs on this machine, as JSON",
	() => {
		for (const cmd of [
			["list"],
			["conns", "--all"],
			["interfaces"],
			["map"],
			["route", "127.0.0.1"],
		]) {
			const r = run(...cmd, "--json", "--no-docker");
			expect(r.status, `${cmd.join(" ")}: ${r.stderr}`).toBe(0);
			expect(() => JSON.parse(r.stdout)).not.toThrow();
		}
		// lo, lo0 on macOS, "Loopback Pseudo-Interface 1" on Windows
		const lo = JSON.parse(
			run("interfaces", "--json", "--no-docker").stdout,
		).find((i: { kind: string }) => i.kind === "loopback")?.name;
		expect(lo).toBeString();
		expect(
			JSON.parse(run("route", "127.0.0.1", "--json", "--no-docker").stdout),
		).toMatchObject({ kind: "loopback", iface: lo });
		// each run asks the OS afresh: a few seconds on Windows, where PowerShell starts each time
	},
	120_000,
);

test.skipIf(!hasNode)(
	"who finds a port this test listens on, with its process",
	async () => {
		const { createServer } = await import("node:net");
		const server = createServer();
		await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
		const port = (server.address() as { port: number }).port;
		try {
			const r = spawnSync(
				"node",
				["dist/nethound.js", "who", String(port), "--json", "--no-docker"],
				{
					cwd: root,
					encoding: "utf8",
				},
			);
			expect(r.status).toBe(0);
			const out = JSON.parse(r.stdout);
			expect(out.listeners[0]).toMatchObject({
				proto: "tcp",
				port,
				addresses: ["127.0.0.1"],
				reach: { scope: "local" },
				process: { pid: process.pid },
			});
		} finally {
			server.close();
		}
	},
	60_000,
);
