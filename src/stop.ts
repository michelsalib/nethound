// Stopping a server: the process holding the port, or the whole tree a dev command started
// (bun run dev → vite → esbuild), so no runner or watcher (nodemon) starts it again.

import type { Process, Snapshot } from "./model.ts";

// What starts dev servers, and nothing else: an IDE, an agent or a tool written in node is a node
// process too, and must never be part of a tree nethound stops.
// package runners, watchers and monorepo tools, by name
const RUNNER =
	/^(npm|npx|pnpm|pnpx|yarn|bunx|nodemon|tsx|ts-node|turbo|nx|lerna|concurrently|watchexec|air)$/i;
// bun and deno running a script, not any program written for them
const SCRIPT_RUNTIME = /^(bun|deno)$/i;
const SCRIPT_ARGS = /\s(run|x|task|--watch|--hot)(\s|$)/;
// node running a runner or dev tool: npm and yarn are node scripts, and vite or next start from
// node_modules (node …/node_modules/.bin/vite)
const RUNNER_SCRIPT =
	/(npm-cli\.js|npx-cli\.js|pnpm\.c?js|yarn\.c?js|[\\/]node_modules[\\/](\.bin[\\/])?(vite|next|nuxt|astro|remix|webpack|parcel|nodemon|tsx|turbo|nx|concurrently))/i;
const SHELL = /^-?(sh|bash|zsh|dash|fish|ksh|cmd|powershell|pwsh)$/i;

/** A runner: what a person starts a dev server with. npm (7 and later), pnpm and yarn rename their
 * process after the command: "npm run dev", in its name and its command line. */
const runner = (p: Process) =>
	RUNNER.test(p.name.split(" ")[0] ?? "") ||
	(SCRIPT_RUNTIME.test(p.name) && SCRIPT_ARGS.test(` ${p.cmd} `)) ||
	RUNNER_SCRIPT.test(p.cmd);

/** A shell running one command for a runner (`sh -c vite`, `cmd /d /s /c vite`), not one a person types in. */
const scriptShell = (p: Process) =>
	SHELL.test(p.name) && /\s(-c|\/c|-Command)\s/i.test(` ${p.cmd} `);

/** `pid`'s parents, nearest first. */
export function ancestors(snap: Snapshot, pid: number): Process[] {
	const by = new Map(snap.processes.map((p) => [p.pid, p]));
	const out: Process[] = [];
	let p = by.get(pid);
	while (p?.ppid && !out.some((x) => x.pid === p?.ppid)) {
		const parent = by.get(p.ppid);
		if (!parent) break;
		out.push(parent);
		p = parent;
	}
	return out;
}

/** What started `pid`, nearest first, up to the user's session: not init, systemd or launchd, nor
 * another user's process. */
export function startedBy(snap: Snapshot, pid: number): Process[] {
	const p = snap.processes.find((x) => x.pid === pid);
	const out: Process[] = [];
	for (const a of ancestors(snap, pid)) {
		if (
			a.pid <= 1 ||
			/^(init|systemd|launchd|wininit|services|smss)$/i.test(a.name)
		)
			break;
		if (p?.uid !== undefined && a.uid !== undefined && a.uid !== p.uid) break;
		out.push(a);
	}
	return out;
}

/** Every process under `pid`, children before grandchildren. */
export function descendants(snap: Snapshot, pid: number): Process[] {
	const out: Process[] = [];
	const queue = [pid];
	while (queue.length) {
		const parent = queue.shift();
		for (const p of snap.processes)
			if (p.ppid === parent && p.pid !== pid && !out.includes(p)) {
				out.push(p);
				queue.push(p.pid);
			}
	}
	return out;
}

/**
 * What stopping `pid` with its runners means: the topmost runner above it (bun run dev, npm, a
 * `sh -c` they started), never an interactive shell, a terminal, an IDE or another user's process,
 * nor nethound or what started it; then everything under that one. Top first.
 */
export function treeOf(
	snap: Snapshot,
	pid: number,
	self = process.pid,
): Process[] {
	const by = new Map(snap.processes.map((p) => [p.pid, p]));
	const server = by.get(pid);
	if (!server) return [];
	const ours = new Set([self, ...ancestors(snap, self).map((p) => p.pid)]);
	let top = server;
	const up = ancestors(snap, pid);
	for (const [i, parent] of up.entries()) {
		if (ours.has(parent.pid)) break;
		if (server.uid !== undefined && parent.uid !== server.uid) break;
		// a sh -c belongs to the tree only when a runner started it (npm runs scripts that way);
		// one an agent or a script started may run other things too
		const next = up[i + 1];
		if (!(runner(parent) || (scriptShell(parent) && next && runner(next))))
			break;
		top = parent;
	}
	return [top, ...descendants(snap, top.pid)].filter((p) => !ours.has(p.pid));
}

export interface Stopped {
	pid: number;
	/** "sent": signalled; "gone": it had exited already; "denied": another user's (sudo or administrator). */
	result: "sent" | "gone" | "denied" | "failed";
	error?: string;
}

/** Signals each process, in order: SIGTERM, or SIGKILL with `force`. On Windows, either ends it at once. */
export function stop(pids: number[], force = false): Stopped[] {
	return pids.map((pid) => {
		try {
			process.kill(pid, force ? "SIGKILL" : "SIGTERM");
			return { pid, result: "sent" };
		} catch (e) {
			const code = (e as NodeJS.ErrnoException).code;
			if (code === "ESRCH") return { pid, result: "gone" };
			if (code === "EPERM") return { pid, result: "denied" };
			return { pid, result: "failed", error: (e as Error).message };
		}
	});
}

/** Whether `pid` still runs. */
export function alive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (e) {
		// another user's process exists too: we may just not signal it
		return (e as NodeJS.ErrnoException).code === "EPERM";
	}
}
