import { expect, test } from "bun:test";
import type { Process, Snapshot } from "../src/model.ts";
import { alive, stop, treeOf } from "../src/stop.ts";
import { fixture } from "./helpers.ts";

const machine = (processes: Process[]) =>
	({ ...fixture([]), processes }) as Snapshot;
const p = (
	pid: number,
	ppid: number,
	name: string,
	cmd: string,
	uid = 1000,
): Process => ({
	pid,
	ppid,
	name,
	cmd,
	uid,
});
const pids = (ps: Process[]) => ps.map((x) => x.pid);

test("bun run dev → sh -c → vite → esbuild: the whole tree, never the shell it was typed in", () => {
	const snap = machine([
		p(10, 1, "zsh", "-zsh"),
		p(20, 10, "bun", "bun run dev"),
		p(30, 20, "sh", "sh -c vite"),
		p(40, 30, "node", "node /home/me/app/node_modules/.bin/vite"),
		p(50, 40, "esbuild", "esbuild --service=0.25.0 --ping"),
		p(60, 10, "vim", "vim src/main.ts"),
	]);
	expect(pids(treeOf(snap, 40, 999))).toEqual([20, 30, 40, 50]);
	// the fixture: zsh 240 → bun run dev 250 → node 300
	expect(pids(treeOf(fixture(), 300, 999))).toEqual([250, 300]);
});

test("npm and nodemon are node scripts: found by what they run", () => {
	const snap = machine([
		p(10, 1, "bash", "bash"),
		p(20, 10, "node", "node /usr/lib/node_modules/npm/bin/npm-cli.js run dev"),
		p(30, 20, "sh", "sh -c nodemon server.js"),
		p(40, 30, "node", "node /app/node_modules/.bin/nodemon server.js"),
		p(50, 40, "node", "node server.js"),
	]);
	expect(pids(treeOf(snap, 50, 999))).toEqual([20, 30, 40, 50]);
});

test("npm renamed after its command, as it does since npm 7: still npm", () => {
	const snap = machine([
		p(10, 1, "bash", "bash"),
		p(20, 10, "npm run dev", "npm run dev"),
		p(30, 20, "sh", "sh -c vite --host 127.0.0.1"),
		p(40, 30, "node", "node /app/node_modules/.bin/vite --host 127.0.0.1"),
	]);
	expect(pids(treeOf(snap, 40, 999))).toEqual([20, 30, 40]);
});

test("an agent, an IDE or a tool in node is not a runner, nor the bash -c it started", () => {
	const snap = machine([
		p(
			10,
			1,
			"node",
			"node /home/me/.npm/node_modules/@anthropic-ai/claude-code/cli.js",
		),
		p(20, 10, "bash", "bash -c node server.js"),
		p(30, 20, "node", "node server.js"),
		p(40, 1, "code", "/usr/share/code/code"),
		p(
			50,
			40,
			"node",
			"node /usr/share/code/resources/app/out/bootstrap-fork --type=extensionHost",
		),
		p(60, 50, "bun", "bun server.ts"),
	]);
	expect(pids(treeOf(snap, 30, 999))).toEqual([30]);
	// bun running a program, not a script: on its own
	expect(pids(treeOf(snap, 60, 999))).toEqual([60]);
});

test("never nethound or what started it; never another user's runner", () => {
	const snap = machine([
		p(20, 1, "bun", "bun run dev"),
		p(30, 20, "node", "node server.js"),
		// nethound, started by the same bun run (a "watch" script)
		p(40, 20, "node", "node dist/nethound.js watch"),
		p(50, 1, "pnpm", "pnpm dev", 0),
		p(60, 50, "node", "node api.js"),
	]);
	expect(pids(treeOf(snap, 30, 40))).toEqual([30]);
	expect(pids(treeOf(snap, 60, 999))).toEqual([60]);
	expect(treeOf(snap, 12345, 999)).toEqual([]);
});

test("stop and alive on a real process; a pid that is gone", async () => {
	// the runtime itself, as there is no sleep on Windows
	const child = Bun.spawn([
		process.execPath,
		"-e",
		"setTimeout(() => {}, 30000)",
	]);
	expect(alive(child.pid)).toBe(true);
	expect(stop([child.pid])).toEqual([{ pid: child.pid, result: "sent" }]);
	await child.exited;
	expect(alive(child.pid)).toBe(false);
	expect(stop([child.pid])).toEqual([{ pid: child.pid, result: "gone" }]);
});
