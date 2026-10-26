// What `nethound watch` draws: a header, the ports as a table, the selected one in detail, and
// the keys; or, on the map, what nethound map prints. Pure: lines of text from the state, cut to
// the terminal's width.

import { map } from "../analyze.ts";
import {
	cut,
	ESC,
	paint,
	place,
	placeParts,
	type RenderOptions,
	reachLabel,
	renderMap,
	tilde,
	visibleLength,
} from "../format.ts";
import type { Process } from "../model.ts";
import { startedBy } from "../stop.ts";
import { webLabel } from "../web.ts";
import {
	type Key,
	MARK_MS,
	type Row,
	type State,
	selectedRow,
	targets,
	VIEWS,
	type View,
	visible,
	webOf,
} from "./state.ts";

/** Lines the selected port's details take, always: the rule with its title and up to 9 more. */
export const DETAIL = 10;

/** PORT ("udp 65535"), PROCESS, WHERE, UP, CLIENTS; the last column takes what is left. */
const WIDTHS = [9, 20, 30, 4, 7];

/** Rows the table shows: what the header, the titles, the details, the message and the keys leave. */
export const tableRoom = (height: number) => Math.max(3, height - 4 - DETAIL);

/** The first row shown: where the list was scrolled to, moved only as far as the selection needs. */
export function scrolled(s: State, room: number): number {
	const rows = visible(s);
	const at = Math.max(
		0,
		rows.findIndex((r) => r.key === selectedRow(s)?.key),
	);
	let top = Math.min(s.top, Math.max(0, rows.length - room));
	if (at < top) top = at;
	if (at >= top + room) top = at - room + 1;
	return Math.max(0, top);
}

const TITLE = "nethound watch";
const TAB_LABELS: Record<View, string> = { ports: "Ports", map: "Map" };
const tabLabels = () => VIEWS.map((v, i) => ` ${i + 1} ${TAB_LABELS[v]} `);

/** The first line: the title, the tabs (the one shown inverted), what is shown, and on the right
 * `right`. */
function header(
	s: State,
	width: number,
	o: RenderOptions,
	info: string,
	right: string,
): string {
	const c = paint(o);
	const tabs = tabLabels()
		.map((l, i) => (VIEWS[i] === s.view ? c.inverse(l) : c.dim(l)))
		.join(" ");
	const left = `${c.bold(TITLE)}  ${tabs}  ${s.snap ? `${c.cyan(s.snap.hostname)}  ` : ""}${c.dim(info)}`;
	const gap = width - visibleLength(left) - visibleLength(right);
	return cut(gap >= 2 ? left + " ".repeat(gap) + right : left, width);
}

/** The tab under column `x` of the first line, counted from 0. */
export function tabAt(x: number): View | undefined {
	let at = TITLE.length + 2;
	for (const [i, l] of tabLabels().entries()) {
		if (x >= at && x < at + l.length) return VIEWS[i];
		at += l.length + 1;
	}
	return undefined;
}

/** Lines the map shows: what the header, the message and the keys leave. */
export const mapRoom = (height: number) => Math.max(3, height - 3);

/** The map as nethound map prints it, a line each, without its first (the hostname, which the
 * header shows) and the blank line after it. */
export function mapLines(s: State, width: number, o: RenderOptions): string[] {
	if (!s.snap) return [];
	return renderMap(map(s.snap), {
		...o,
		width,
		wsl: s.snap.environment === "wsl",
		windows: s.snap.environment === "windows",
	})
		.split("\n")
		.slice(2);
}

/** The map's first line shown: where it was scrolled to, no further than its end allows. */
export const mapScrolled = (s: State, lines: number, room: number) =>
	Math.max(0, Math.min(s.mapTop, lines - room));

/** "45s", "12m", "3h", "2d": how long ago `t` was. */
export function age(t: number | undefined, now: number): string {
	if (t === undefined) return "";
	const s = Math.max(0, Math.round((now - t) / 1000));
	if (s < 60) return `${s}s`;
	if (s < 3600) return `${Math.floor(s / 60)}m`;
	if (s < 86400) return `${Math.floor(s / 3600)}h`;
	return `${Math.floor(s / 86400)}d`;
}

/** Where a server runs: its container, or its process's checkout or directory. */
export function where(r: Row, home?: string): string {
	const l = r.listener;
	if (l.container) return `container ${l.container.name}`;
	return l.process ? place(l.process, home) : "";
}

/** `where` in `w` characters: a long checkout name is cut, its tags ("(removed) · claude") kept;
 * the checkout coloured, the tags faded. */
function whereCell(r: Row, w: number, o: RenderOptions, home?: string): string {
	const c = paint(o);
	const p = r.listener.process;
	if (r.listener.container || !p) return where(r, home);
	const { name, tags } = placeParts(p, home);
	const removed = tags.startsWith("(removed)");
	const tagged = removed
		? `${c.yellow("(removed)")}${c.dim(tags.slice("(removed)".length))}`
		: c.dim(tags);
	if (!name || !tags) return name ? c.cyan(name) : tagged;
	return `${c.cyan(cut(name, Math.max(4, w - tags.length - 1)))} ${tagged}`;
}

export { cut, visibleLength };

/** `s` without its colour codes. */
const plain = (s: string) =>
	s.replace(new RegExp(`${ESC}\\[[0-9;]*m`, "g"), "");

/** `s` in exactly `w` visible characters: cut, or padded with spaces. */
const pad = (s: string, w: number) => {
	const t = cut(s, w);
	return t + " ".repeat(Math.max(0, w - visibleLength(t)));
};

/** Where the table's first row is drawn: under the header and the column titles. */
export const TABLE_TOP = 2;

/** A piece of the last line: a key and what it does (a click presses it), or just text. */
export interface Part {
	key?: string;
	label: string;
	press?: Key;
	style?: "question";
}

/** The last line: the question asked, the filter being typed, or the keys. */
export function footer(s: State): Part[] {
	if (s.confirm)
		return [
			{ label: s.confirm.question, style: "question" },
			{ key: "y", label: "yes", press: { ch: "y" } },
			{ key: "n", label: "no", press: { ch: "n" } },
		];
	if (s.filtering)
		return [
			{ label: `/${s.filter}▏` },
			{ key: "enter", label: "keep", press: { name: "return" } },
			{ key: "esc", label: "clear", press: { name: "escape" } },
		];
	if (s.view === "map")
		return [
			{ key: "↑↓", label: "scroll" },
			{ key: "tab", label: "ports", press: { name: "tab" } },
			{ key: "r", label: "refresh", press: { ch: "r" } },
			{ key: "q", label: "quit", press: { ch: "q" } },
		];
	const web = webOf(s, selectedRow(s));
	return [
		{ key: "↑↓", label: "select" },
		...(web && web.kind !== "none"
			? [{ key: "o", label: "open", press: { ch: "o" } }]
			: []),
		{ key: "k", label: "stop", press: { ch: "k" } },
		{ key: "K", label: "stop with what started it", press: { ch: "K" } },
		s.filter
			? { key: "esc", label: "clear filter", press: { name: "escape" } }
			: { key: "/", label: "filter", press: { ch: "/" } },
		{ key: "tab", label: "map", press: { name: "tab" } },
		{ key: "r", label: "refresh", press: { ch: "r" } },
		{ key: "q", label: "quit", press: { ch: "q" } },
	];
}

const partText = (p: Part) => (p.key ? `${p.key} ${p.label}` : p.label);

/** The part of the last line at column `x`, counted from 0. */
export function footerAt(s: State, x: number): Part | undefined {
	let at = 0;
	for (const p of footer(s)) {
		const end = at + [...partText(p)].length;
		if (x >= at && x < end) return p;
		at = end + 2;
	}
	return undefined;
}

export function render(
	s: State,
	width: number,
	height: number,
	o: RenderOptions & { now: number; home?: string },
): string[] {
	if (s.view === "map") return renderMapView(s, width, height, o);
	const c = paint(o);
	const rows = visible(s);
	const sel = selectedRow(s);
	const out: string[] = [];

	// the header: the tabs, where, and on the right how fresh it is
	out.push(
		header(
			s,
			width,
			o,
			s.snap
				? `${rows.length} port${rows.length === 1 ? "" : "s"}${s.filter ? ` matching "${s.filter}"` : ""}`
				: "reading the machine…",
			s.snap ? c.dim(`updated ${age(s.updated, o.now)} ago`) : "",
		),
	);

	// the table: as many rows as fit above the details, the selected one in view
	const cells = rows.map((r) => {
		const l = r.listener;
		const p = l.process;
		return [
			`${c.dim(l.proto)} ${c.bold(String(l.port))}`,
			p
				? `${p.name} ${c.dim(String(p.pid))}`
				: l.container
					? ""
					: `${l.user ?? "another user"}'s`,
			whereCell(r, WIDTHS[2] ?? 30, o, o.home),
			c.dim(age(p?.started, o.now)),
			l.clients.length ? String(l.clients.length) : "",
			reachCell(l, o),
		];
	});
	const titles = [
		"PORT",
		"PROCESS",
		"WHERE",
		"UP",
		"CLIENTS",
		"REACHABLE FROM",
	];
	// fixed widths: a longer name or "59s" turning "1m" never shifts the columns
	const widths = WIDTHS;
	const line = (cols: string[]) =>
		cut(
			cols
				.map((x, i) => (i === cols.length - 1 ? x : pad(x, widths[i] ?? 0)))
				.join("  "),
			width - 2,
		);
	// fixed places: the table always as tall, the details always as tall, so nothing moves as the
	// selection or the filter changes
	const room = tableRoom(height);
	out.push(`  ${c.bold(c.dim(line(titles)))}`);
	const first = scrolled(s, room);
	for (const [i, r] of rows.entries()) {
		if (i < first || i >= first + room) continue;
		const text = line(cells[i] ?? []);
		const mark = r.closed
			? c.red("−")
			: r.appeared && o.now - r.appeared < MARK_MS
				? c.green("+")
				: " ";
		// the selection a bar across the screen; what can't be acted on (another user's, closed) faded
		const body =
			r.key === sel?.key
				? c.inverse(pad(plain(text), width - 2))
				: r.closed || (!r.listener.process && !r.listener.container)
					? c.dim(plain(text))
					: text;
		out.push(`${mark} ${body}`);
	}
	if (!rows.length)
		out.push(
			c.dim(
				s.snap ? (s.filter ? "  nothing matches" : "  nothing listens") : "",
			),
		);
	while (out.length < TABLE_TOP + room) out.push("");

	// a rule between the table and the details, titled with the selected port; on its right, which
	// rows the table shows when they don't all fit
	const title = sel ? detailTitle(sel, o) : "";
	const span =
		rows.length > room
			? c.dim(
					`${first + 1}–${Math.min(rows.length, first + room)} of ${rows.length}`,
				)
			: "";
	const fill = Math.max(
		2,
		width - visibleLength(title) - visibleLength(span) - 8,
	);
	out.push(
		cut(
			`${c.dim("──")} ${title}${title ? " " : ""}${c.dim("─".repeat(fill))}${span ? ` ${span} ${c.dim("──")}` : c.dim("────")}`,
			width,
		),
	);
	const detail = (sel ? details(s, sel, width, o) : []).slice(0, DETAIL - 1);
	while (detail.length < DETAIL - 1) detail.push("");
	out.push(...detail);

	out.length = Math.min(out.length, Math.max(0, height - 2));
	return [...out, ...bottom(s, width, height, o, out.length)];
}

/** The map, scrolled, under a header like the ports'. */
function renderMapView(
	s: State,
	width: number,
	height: number,
	o: RenderOptions & { now: number },
): string[] {
	const c = paint(o);
	const lines = mapLines(s, width, o);
	const room = mapRoom(height);
	const top = mapScrolled(s, lines.length, room);
	const right = s.snap
		? c.dim(
				`${lines.length > room ? `${top + 1}–${Math.min(lines.length, top + room)} of ${lines.length}  ` : ""}updated ${age(s.updated, o.now)} ago`,
			)
		: "";
	const out = [
		header(s, width, o, s.snap ? "" : "reading the machine…", right),
		...lines.slice(top, top + room).map((l) => cut(l, width)),
	];
	return [...out, ...bottom(s, width, height, o, out.length)];
}

/** The last two lines, the screen filled down to them: a message, and the keys. */
function bottom(
	s: State,
	width: number,
	height: number,
	o: RenderOptions,
	used: number,
): string[] {
	const c = paint(o);
	const out: string[] = Array.from(
		{ length: Math.max(0, height - 2 - used) },
		() => "",
	);
	// a message on its own line, so the keys stay in sight
	out.push(
		s.message
			? cut(
					s.message.error ? c.red(s.message.text) : c.green(s.message.text),
					width,
				)
			: "",
	);
	out.push(
		cut(
			footer(s)
				.map((p) =>
					p.key
						? `${c.bold(p.key)} ${c.dim(p.label)}`
						: p.style === "question"
							? c.yellow(p.label)
							: p.label,
				)
				.join("  "),
			width,
		),
	);
	return out;
}

/** How far a port reaches: this machine alone reassures, every interface warns. */
function reachCell(l: Row["listener"], o: RenderOptions): string {
	const c = paint(o);
	const text = reachLabel(l, o);
	const [base = "", windows] = text.split(" + ");
	const coloured =
		l.reach.scope === "local"
			? c.green(base)
			: l.reach.scope === "everywhere"
				? c.yellow(base)
				: base;
	return windows ? `${coloured}${c.dim(` + ${windows}`)}` : coloured;
}

/** The selected port, as the details' title: its port and who holds it. */
function detailTitle(r: Row, o: RenderOptions): string {
	const c = paint(o);
	const l = r.listener;
	const who = l.process
		? `${l.process.name} ${l.process.pid}`
		: l.container
			? `container ${l.container.name}`
			: "";
	return `${c.bold(`${l.proto} ${l.port}`)}${who ? `  ${who}` : ""}${r.closed ? c.red("  closed") : ""}`;
}

/** The selected port in full: command, directory, what started it, what stopping would take, clients. */
function details(
	s: State,
	r: Row,
	width: number,
	o: RenderOptions & { home?: string },
): string[] {
	const c = paint(o);
	const l = r.listener;
	const p = l.process;
	const kv: [string, string][] = [];
	// first, always on the same line: a click on it opens it
	const web = s.web[r.key];
	if (web && web.kind !== "none")
		kv.push([
			"url",
			`${c.cyan(c.underline(web.url))}  ${webLabel(web)}${c.dim("  o or click to open")}`,
		]);
	if (l.container)
		kv.push([
			"container",
			`${l.container.name}  ${c.dim(l.container.image)}${l.published ? c.dim(`  → :${l.published.containerPort}`) : ""}`,
		]);
	if (p) {
		kv.push(["command", p.cmd]);
		if (p.git)
			kv.push([
				"checkout",
				`${tilde(p.git.root, o.home)}  ${p.git.branch ? `branch ${p.git.branch}` : "detached HEAD"}${p.git.worktree ? c.dim("  (worktree)") : ""}`,
			]);
		if (p.project)
			kv.push([
				"project",
				`${tilde(p.project.root, o.home)}  ${p.project.removed ? c.yellow("removed") : p.project.branch ? `branch ${p.project.branch}` : ""}${c.dim(p.project.via === "session" ? "  (from its Claude session)" : "  (from what started it)")}`,
			]);
		if (p.cwd && p.cwd !== p.git?.root)
			kv.push(["directory", tilde(p.cwd, o.home)]);
		if (p.app) kv.push(["app", p.app]);
		if (p.orphan)
			kv.push([
				"",
				c.yellow(
					"its Claude session has ended: probably left behind (k stops it)",
				),
			]);
		if (s.snap) {
			const up = startedBy(s.snap, p.pid).slice(0, 4);
			if (up.length)
				kv.push([
					"started by",
					up.map((x: Process) => `${x.name} ${x.pid}`).join(" ← "),
				]);
			const tree = targets(s, r, true);
			if (tree.length > 1)
				kv.push(["K stops", tree.map((x) => `${x.name} ${x.pid}`).join(", ")]);
		}
	} else if (!l.container)
		kv.push([
			"process",
			c.yellow(
				`${l.user ?? "another user"}'s: run with sudo (or as administrator) to see it`,
			),
		]);
	kv.push(["bound to", l.addresses.join(", ")]);
	if (l.clients.length)
		kv.push([
			"clients",
			l.clients
				.slice(0, 3)
				.map(
					(x) =>
						`${x.remote.address}:${x.remote.port}${x.peer.kind === "local" && x.peer.process ? ` ${x.peer.process.name} ${x.peer.process.pid}` : ""}`,
				)
				.join(", ") + (l.clients.length > 3 ? ` +${l.clients.length - 3}` : ""),
		]);
	return kv.map(
		([k, v]) => `  ${c.dim(k.padEnd(10))} ${cut(v, Math.max(10, width - 14))}`,
	);
}
