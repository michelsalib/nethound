import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import type { Snapshot, Socket } from "../src/model.ts";
import { handleMouse, readMouse } from "../src/watch/mouse.ts";
import {
	applySnapshot,
	handleKey,
	initialState,
	MARK_MS,
	type State,
	selectedRow,
	visible,
} from "../src/watch/state.ts";
import {
	footerAt,
	render,
	scrolled,
	TABLE_TOP,
	tableRoom,
} from "../src/watch/view.ts";
import { fixture, pg } from "./helpers.ts";

const base = fixture();
const listen = (port: number, pid: number): Socket => ({
	proto: "tcp",
	family: 4,
	local: { address: "127.0.0.1", port },
	remote: { address: "0.0.0.0", port: 0 },
	state: "LISTEN",
	pid,
	uid: 1000,
});
const withSocket = (snap: Snapshot, s: Socket): Snapshot => ({
	...snap,
	sockets: [...snap.sockets, s],
});
const keys = (s: State, ...ks: string[]) => {
	let effect: ReturnType<typeof handleKey>[1];
	for (const k of ks) {
		const named = ["up", "down", "return", "escape", "backspace"].includes(k);
		[s, effect] = handleKey(s, named ? { name: k } : { ch: k });
	}
	return [s, effect] as const;
};
const ports = (s: State) =>
	visible(s).map((r) => `${r.listener.proto} ${r.listener.port}`);

test("ports that open are marked, closed ones linger a while, then go", () => {
	let s = applySnapshot(initialState(999), base, 0);
	// the first snapshot marks nothing
	expect(s.rows.every((r) => !r.appeared)).toBe(true);
	s = applySnapshot(s, withSocket(base, listen(4100, 300)), 1000);
	expect(s.rows.find((r) => r.listener.port === 4100)?.appeared).toBe(1000);
	s = applySnapshot(s, base, 2000);
	expect(s.rows.find((r) => r.listener.port === 4100)?.closed).toBe(2000);
	s = applySnapshot(s, base, 2000 + MARK_MS);
	expect(s.rows.find((r) => r.listener.port === 4100)).toBeUndefined();
	expect(s.rows.every((r) => !r.appeared)).toBe(true);
});

test("the selection follows its row across refreshes; arrows move it; / filters", () => {
	let s = applySnapshot(initialState(999), base, 0);
	expect(ports(s)).toEqual([
		"tcp 22",
		"udp 53",
		"tcp 5000",
		"tcp 5432",
		"tcp 8080",
	]);
	[s] = keys(s, "down", "down");
	expect(selectedRow(s)?.listener.port).toBe(5000);
	s = applySnapshot(s, withSocket(base, listen(1234, 300)), 1000);
	expect(selectedRow(s)?.listener.port).toBe(5000);
	[s] = keys(s, "/", "8", "0", "8", "return");
	expect(ports(s)).toEqual(["tcp 8080"]);
	expect(selectedRow(s)?.listener.port).toBe(8080);
	[s] = keys(s, "escape");
	expect(ports(s)).toHaveLength(6);
});

test("k asks before stopping the process; K takes what started it; a second k forces", () => {
	let s = applySnapshot(initialState(999), base, 0);
	[s] = keys(s, "/", "5000", "return");
	let effect: ReturnType<typeof handleKey>[1];
	[s, effect] = keys(s, "k");
	expect(effect).toBeUndefined();
	expect(s.confirm?.question).toBe("stop node 300?");
	[s, effect] = keys(s, "y");
	expect(effect).toEqual({ kind: "stop", pids: [300], force: false });
	// still running at the next refresh: k again kills it
	s = applySnapshot(s, base, 1000);
	[s] = keys(s, "k");
	expect(s.confirm?.question).toBe("force-stop (SIGKILL) node 300?");
	[s, effect] = keys(s, "n");
	expect(effect).toBeUndefined();
	expect(s.message?.text).toBe("nothing stopped");
	// node 300 was started by bun run dev 250, from zsh 240: K stops bun and node, never zsh
	[s] = keys(s, "K");
	expect(s.confirm?.pids).toEqual([250, 300]);
});

test("a container is docker stopped; another user's process can't be", () => {
	let s = applySnapshot(initialState(999), fixture([pg]), 0);
	[s] = keys(s, "/", "5432", "return", "k");
	expect(s.confirm?.container).toBe("pg");
	const [, effect] = keys(s, "y");
	expect(effect).toEqual({ kind: "docker-stop", container: "pg" });
	let t = applySnapshot(initialState(999), base, 0);
	[t] = keys(t, "/", "tcp 22", "return", "k");
	expect(t.confirm).toBeUndefined();
	expect(t.message?.error).toBe(true);
});

test("the screen: where each server runs, and the selected one in detail", () => {
	let s = applySnapshot(initialState(999), base, 0);
	[s] = keys(s, "/", "8080", "return");
	// the fixture's home, as this system reads the link: \\home\\me on Windows
	const home = base.processes.find((p) => p.pid === 240)?.cwd;
	const text = render(s, 100, 24, {
		color: false,
		now: 61_000 + 1760000000000,
		home,
	}).join("\n");
	expect(text).toMatch(/tcp 8080 +node 300 +~[\\/]src[\\/]app-feature +\d+s/);
	expect(text).toContain("started by bun 250 ← zsh 240");
	expect(text).toContain("K stops    bun 250, node 300");
	expect(text).toContain("↑↓ select  k stop");
	expect(text).toMatch(/^── tcp 8080 {2}node 300 ─+$/m);
});

// a real terminal: the built CLI in a pseudo-terminal (Python's pty, not on Windows)
const python = spawnSync("python3", ["--version"]).status === 0;
test.skipIf(!python || process.platform === "win32")(
	"nethound watch runs in a terminal and quits on q",
	() => {
		const root = join(import.meta.dir, "..");
		const build = spawnSync("bun", ["run", "build"], {
			cwd: root,
			encoding: "utf8",
		});
		expect(build.status).toBe(0);
		const steps = [
			["wait", "nethound watch"],
			["wait", "PORT"],
			["send", "q"],
		];
		const r = spawnSync(
			"python3",
			[
				"-I",
				"scripts/pty.py",
				"100",
				"30",
				JSON.stringify(steps),
				"node",
				"dist/nethound.js",
				"watch",
				"--no-docker",
			],
			{ cwd: root, encoding: "utf8", timeout: 60_000 },
		);
		expect(r.status, r.stderr).toBe(0);
		const screen = (JSON.parse(r.stdout) as [number, string][])
			.map(([, t]) => t)
			.join("");
		expect(screen).toContain("\x1b[?1049h");
		// the alternate screen left, the cursor shown again
		expect(screen).toEndWith("\x1b[?25h\x1b[?1049l");
	},
	60_000,
);

test("scrolling: the list moves only when the selection leaves it; nothing else moves", () => {
	const many = base.sockets.concat(
		Array.from({ length: 40 }, (_, i) => listen(6000 + i, 300)),
	);
	let s = applySnapshot(initialState(999), { ...base, sockets: many }, 0);
	const height = 30;
	const room = tableRoom(height);
	const screen = () => {
		s = { ...s, top: scrolled(s, room) };
		return render(s, 100, height, { color: false, now: 0 });
	};
	const tops: number[] = [];
	const detailAt = new Set<number>();
	const heights = new Set<number>();
	for (let i = 0; i < room + 3; i++) {
		const lines = screen();
		tops.push(s.top);
		heights.add(lines.length);
		// the rule over the details, titled with the selected port
		detailAt.add(lines.findIndex((l) => /^── (tcp|udp) \d+ /.test(l)));
		[s] = keys(s, "down");
	}
	// still at the top while the selection is in view, then one row per step
	expect(tops.slice(0, room)).toEqual(Array(room).fill(0));
	expect(tops.slice(room)).toEqual([1, 2, 3]);
	expect(detailAt).toEqual(new Set([2 + room]));
	expect(heights).toEqual(new Set([height]));
	// back up: the list stays where it is until the selection reaches its top
	[s] = keys(s, "up");
	screen();
	expect(s.top).toBe(3);
});

test("a long checkout name is cut in WHERE, its tags kept", () => {
	const snap = structuredClone(base);
	const node = snap.processes.find((p) => p.pid === 300);
	if (!node) throw new Error("no node 300");
	node.app = "claude";
	node.orphan = true;
	node.project = {
		root: "/w/gt-846-writer-suggestions-seo-titres-et-mise-en",
		worktree: false,
		via: "session",
		removed: true,
	};
	let s = applySnapshot(initialState(999), snap, 0);
	[s] = keys(s, "/", "8080", "return");
	const text = render(s, 120, 30, { color: false, now: 0 }).join("\n");
	// 30 columns: 11 for the name, the rest for the tags
	expect(text).toMatch(/node 300 +gt-846-wri… \(removed\) · claude /);
	expect(text).toContain("its Claude session has ended");
});

test("the mouse: reports taken out of the keys, even cut in two", () => {
	const a = readMouse("q\x1b[<0;5;3Mj\x1b[<0;5;3m\x1b[<6");
	expect(a.events).toEqual([
		{ button: 0, x: 4, y: 2, pressed: true },
		{ button: 0, x: 4, y: 2, pressed: false },
	]);
	expect(a.rest).toBe("qj");
	expect(a.pending).toBe("\x1b[<6");
	const b = readMouse(`${a.pending}5;1;1M\x1b[A`);
	expect(b.events).toEqual([{ button: 65, x: 0, y: 0, pressed: true }]);
	expect(b.rest).toBe("\x1b[A");
});

test("the mouse: a click selects its row, the wheel moves, the keys on the last line press", () => {
	const height = 24;
	let s = applySnapshot(initialState(999), base, 0);
	const click = (x: number, y: number, button = 0) =>
		handleMouse(s, { button, x, y, pressed: true }, height);
	// the fourth row: tcp 5432
	[s] = click(10, TABLE_TOP + 3);
	expect(selectedRow(s)?.listener.port).toBe(5432);
	// below the last row, the details: nothing changes
	expect(click(10, TABLE_TOP + 10)[0]).toBe(s);
	[s] = click(10, 0, 64);
	expect(selectedRow(s)?.listener.port).toBe(22);
	[s] = click(10, 0, 65);
	expect(selectedRow(s)?.listener.port).toBe(5432);
	[s] = click(10, TABLE_TOP + 2);
	expect(selectedRow(s)?.listener.port).toBe(5000);
	// "↑↓ select  k stop": k at column 11
	expect(footerAt(s, 11)?.press).toEqual({ ch: "k" });
	expect(footerAt(s, 10)).toBeUndefined();
	[s] = click(12, height - 1);
	expect(s.confirm?.question).toBe("stop node 300?");
	// a question waits: a row clicked neither answers nor selects
	expect(click(10, TABLE_TOP)[0]).toBe(s);
	const yes = (footerAt(s, 0)?.label.length ?? 0) + 2;
	const [t, effect] = click(yes, height - 1);
	expect(t.confirm).toBeUndefined();
	expect(effect).toEqual({ kind: "stop", pids: [300], force: false });
});

test("a port that answers HTTP: o opens it, so does a click on its URL; others say why not", () => {
	const height = 24;
	let s = applySnapshot(initialState(999), base, 0);
	[s] = keys(s, "/", "8080", "return");
	const row = selectedRow(s);
	if (!row) throw new Error("no 8080");
	// not asked yet
	let effect: ReturnType<typeof handleKey>[1];
	[s, effect] = keys(s, "o");
	expect(effect).toBeUndefined();
	expect(s.message?.text).toContain("whether it answers HTTP");
	const url = "http://localhost:8080";
	s = { ...s, web: { [row.key]: { kind: "page", url, status: 200 } } };
	[s, effect] = keys(s, "o");
	expect(effect).toEqual({ kind: "open", url, row });
	const text = render(s, 100, height, { color: false, now: 0 }).join("\n");
	expect(text).toContain(`url        ${url}  page`);
	expect(text).toContain("↑↓ select  o open  k stop");
	// the URL is the details' first line, under the rule
	const [, click] = handleMouse(
		s,
		{ button: 0, x: 20, y: TABLE_TOP + tableRoom(height) + 1, pressed: true },
		height,
	);
	expect(click).toEqual({ kind: "open", url, row });
	s = { ...s, web: { [row.key]: { kind: "none" } } };
	[s, effect] = keys(s, "o");
	expect(effect).toBeUndefined();
	expect(s.message?.text).toBe("tcp 8080 doesn't answer HTTP: nothing to open");
	// refreshing asks again what didn't answer
	[s] = keys(s, "r");
	expect(s.web).toEqual({});
});

test("--no-probe: no port is asked; o opens its http URL, never a database", () => {
	let s = applySnapshot(initialState(999, false), fixture([pg]), 0);
	[s] = keys(s, "/", "8080", "return");
	const row = selectedRow(s);
	if (!row) throw new Error("no 8080");
	let effect: ReturnType<typeof handleKey>[1];
	[s, effect] = keys(s, "o");
	// bound to the LAN address alone: that is where to open it
	expect(effect).toEqual({
		kind: "open",
		url: "http://192.168.1.10:8080",
		row,
	});
	expect(render(s, 100, 24, { color: false, now: 0 }).join("\n")).toContain(
		"url        http://192.168.1.10:8080  not checked",
	);
	[s] = keys(s, "escape", "/", "5432", "return");
	[s, effect] = keys(s, "o");
	expect(effect).toBeUndefined();
	expect(s.message?.text).toContain("doesn't answer HTTP");
});
