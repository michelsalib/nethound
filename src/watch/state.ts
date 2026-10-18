// What `nethound watch` holds between keys and refreshes, and how each changes it: pure
// functions, so the terminal driver only draws and runs effects.

import { type Listener, listeners } from "../analyze.ts";
import type { Process, Snapshot } from "../model.ts";
import { treeOf } from "../stop.ts";
import { unchecked, type Web } from "../web.ts";

/** How long a port that appeared or closed stays marked. */
export const MARK_MS = 10_000;

export interface Row {
	/** proto/port/owner: the same row across refreshes. */
	key: string;
	listener: Listener;
	/** When it appeared, after the first snapshot. */
	appeared?: number;
	/** When it closed: shown a little longer, then dropped. */
	closed?: number;
}

export interface Confirm {
	/** What to ask. */
	question: string;
	pids: number[];
	force: boolean;
	/** A container to stop with docker instead of processes. */
	container?: string;
}

export interface State {
	snap?: Snapshot;
	rows: Row[];
	/** The selected row's key, kept across refreshes. */
	selected?: string;
	/** The first row shown: the list scrolls only when the selection leaves it. */
	top: number;
	/** Typing a filter, and the filter itself: matched against port, process, command and checkout. */
	filtering: boolean;
	filter: string;
	confirm?: Confirm;
	message?: { text: string; error?: boolean };
	/** Pids already sent SIGTERM: stopping one again sends SIGKILL. */
	signalled: number[];
	/** When the last snapshot came. */
	updated?: number;
	/** nethound's own pid: never part of a tree to stop. */
	self: number;
	/** What each row answers over HTTP, by row key, once asked. */
	web: Record<string, Web>;
	/** Ask the selected port whether it answers HTTP; off (--no-probe), every port is taken for one. */
	probe: boolean;
}

export interface Key {
	name?: string;
	ch?: string;
	ctrl?: boolean;
	shift?: boolean;
}

export type Effect =
	| { kind: "quit" }
	| { kind: "refresh" }
	| { kind: "stop"; pids: number[]; force: boolean }
	| { kind: "docker-stop"; container: string }
	| { kind: "open"; url: string; row: Row };

export const initialState = (self = process.pid, probe = true): State => ({
	rows: [],
	top: 0,
	filtering: false,
	filter: "",
	signalled: [],
	self,
	web: {},
	probe,
});

const ownerKey = (l: Listener) =>
	l.container
		? `c${l.container.id}`
		: l.process
			? `p${l.process.pid}`
			: `u${l.user ?? "?"}`;
export const rowKey = (l: Listener) => `${l.proto}/${l.port}/${ownerKey(l)}`;

/** A new snapshot: rows keep their selection, new ones are marked, closed ones linger. */
export function applySnapshot(s: State, snap: Snapshot, now: number): State {
	const first = !s.snap;
	const old = new Map(s.rows.map((r) => [r.key, r]));
	const fresh = listeners(snap).map((listener) => {
		const key = rowKey(listener);
		const was = old.get(key);
		return {
			key,
			listener,
			appeared: first ? undefined : was && !was.closed ? was.appeared : now,
		};
	});
	const keys = new Set(fresh.map((r) => r.key));
	const closed = s.rows
		.filter((r) => !keys.has(r.key))
		.map((r) => ({ ...r, closed: r.closed ?? now }))
		.filter((r) => now - (r.closed ?? now) < MARK_MS);
	const rows = [...fresh, ...closed]
		.map((r) => ({
			...r,
			appeared:
				r.appeared !== undefined && now - r.appeared < MARK_MS
					? r.appeared
					: undefined,
		}))
		.sort(
			(a, b) =>
				a.listener.port - b.listener.port ||
				a.listener.proto.localeCompare(b.listener.proto),
		);
	// a stopped process that is gone needs no SIGKILL any more
	const running = new Set(snap.processes.map((p) => p.pid));
	return {
		...s,
		snap,
		rows,
		updated: now,
		signalled: s.signalled.filter((pid) => running.has(pid)),
		// what a closed port answered goes with it: one opening on its port is asked again
		web: s.probe
			? Object.fromEntries(
					Object.entries(s.web).filter(([key]) =>
						fresh.some((r) => r.key === key),
					),
				)
			: Object.fromEntries(fresh.map((r) => [r.key, unchecked(r.listener)])),
		selected: s.selected ?? visible({ ...s, rows })[0]?.key,
	};
}

/** The text a filter is matched against. */
const haystack = (r: Row) => {
	const l = r.listener;
	return [
		`${l.proto} ${l.port}`,
		l.process?.name,
		l.process?.cmd,
		l.process?.cwd,
		l.process?.git?.branch,
		l.container?.name,
		l.container?.image,
	]
		.filter(Boolean)
		.join(" ")
		.toLowerCase();
};

/** The rows shown: the filter applied. */
export const visible = (s: State) =>
	s.filter
		? s.rows.filter((r) => haystack(r).includes(s.filter.toLowerCase()))
		: s.rows;

export const selectedRow = (s: State) =>
	visible(s).find((r) => r.key === s.selected) ?? visible(s)[0];

/** The processes stopping the selected row would signal: its process, or the tree that started it. */
export function targets(s: State, r: Row, tree: boolean): Process[] {
	const p = r.listener.process;
	if (!s.snap || !p) return [];
	return tree ? treeOf(s.snap, p.pid, s.self) : [p];
}

const label = (p: Process) => `${p.name} ${p.pid}`;

/** What `k` (the process) or `K` (with its runners) asks before stopping. */
function askStop(s: State, r: Row, tree: boolean): State {
	const l = r.listener;
	if (r.closed) return { ...s, message: { text: "it has closed already" } };
	if (l.container && !l.process)
		return {
			...s,
			confirm: {
				question: `stop container ${l.container.name} (docker stop)?`,
				pids: [],
				force: false,
				container: l.container.name,
			},
		};
	if (l.container)
		return {
			...s,
			confirm: {
				question: `${l.port} is container ${l.container.name}'s: docker stop it?`,
				pids: [],
				force: false,
				container: l.container.name,
			},
		};
	if (!l.process)
		return {
			...s,
			message: {
				text: `${l.user ?? "another user"}'s process: run nethound with sudo (or as administrator) to see and stop it`,
				error: true,
			},
		};
	const ps = targets(s, r, tree);
	// a second stop of the same processes, still running: force it
	const force = ps.every((p) => s.signalled.includes(p.pid));
	const what =
		ps.length === 1
			? label(ps[0] as Process)
			: `${ps.length} processes: ${ps.map(label).join(" → ")}`;
	return {
		...s,
		confirm: {
			question: `${force ? "force-stop (SIGKILL)" : "stop"} ${what}?`,
			pids: ps.map((p) => p.pid),
			force,
		},
	};
}

/** The selection `by` rows down (up when negative), kept within the list. */
/** What the selected row's server answers over HTTP: its URL to open, when it is a page or an API. */
export const webOf = (s: State, r: Row | undefined) =>
	r ? s.web[r.key] : undefined;

/** What `o` does: open the selected port in the browser, or say why it can't. */
function askOpen(s: State, r: Row): [State, Effect?] {
	const w = webOf(s, r);
	const port = `${r.listener.proto} ${r.listener.port}`;
	if (r.closed) return [{ ...s, message: { text: "it has closed already" } }];
	if (!w)
		return [
			{
				...s,
				message: { text: `asking ${port} whether it answers HTTP…` },
			},
		];
	if (w.kind === "none")
		return [
			{
				...s,
				message: { text: `${port} doesn't answer HTTP: nothing to open` },
			},
		];
	return [
		{ ...s, message: { text: `opening ${w.url}` } },
		{ kind: "open", url: w.url, row: r },
	];
}

export function move(s: State, by: number): State {
	const rows = visible(s);
	if (!rows.length) return s;
	const at = Math.max(
		0,
		rows.findIndex((r) => r.key === selectedRow(s)?.key),
	);
	const next = Math.min(rows.length - 1, Math.max(0, at + by));
	return { ...s, selected: rows[next]?.key, message: undefined };
}

export function handleKey(s: State, k: Key): [State, Effect?] {
	if (k.ctrl && k.name === "c") return [s, { kind: "quit" }];
	if (s.confirm) {
		if (k.ch === "y" || k.ch === "Y") {
			const c = s.confirm;
			const next = {
				...s,
				confirm: undefined,
				signalled: c.force
					? s.signalled
					: [...new Set([...s.signalled, ...c.pids])],
			};
			return c.container
				? [next, { kind: "docker-stop", container: c.container }]
				: [next, { kind: "stop", pids: c.pids, force: c.force }];
		}
		return [{ ...s, confirm: undefined, message: { text: "nothing stopped" } }];
	}
	if (s.filtering) {
		if (k.name === "return" || k.name === "enter")
			return [{ ...s, filtering: false }];
		if (k.name === "escape") return [{ ...s, filtering: false, filter: "" }];
		if (k.name === "backspace")
			return [{ ...s, filter: s.filter.slice(0, -1) }];
		if (k.ch) {
			const next = { ...s, filter: s.filter + k.ch };
			return [{ ...next, selected: visible(next)[0]?.key }];
		}
		return [s];
	}
	const r = selectedRow(s);
	switch (k.name) {
		case "up":
			return [move(s, -1)];
		case "down":
			return [move(s, 1)];
		case "pageup":
			return [move(s, -10)];
		case "pagedown":
			return [move(s, 10)];
		case "home":
			return [move(s, -Infinity)];
		case "end":
			return [move(s, Infinity)];
		case "escape":
			return s.filter ? [{ ...s, filter: "" }] : [{ ...s, message: undefined }];
	}
	switch (k.ch) {
		case "q":
			return [s, { kind: "quit" }];
		case "k":
			return r ? [askStop(s, r, false)] : [s];
		case "K":
			return r ? [askStop(s, r, true)] : [s];
		case "/":
			return [{ ...s, filtering: true }];
		case "o":
			return r ? askOpen(s, r) : [s];
		case "r":
			// ports that didn't answer HTTP are asked again: a server still starting may now
			return [
				{
					...s,
					message: { text: "refreshing…" },
					web: Object.fromEntries(
						Object.entries(s.web).filter(([, w]) => w.kind !== "none"),
					),
				},
				{ kind: "refresh" },
			];
	}
	return [s];
}
