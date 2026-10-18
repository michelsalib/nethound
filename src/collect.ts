// Reads one Snapshot of the machine, the way its OS tells: /proc and /sys on Linux, netstat,
// lsof and ifconfig on macOS, PowerShell on Windows. Docker is asked the same way everywhere.

import { hostname } from "node:os";
import { collectDarwin } from "./darwin/collect.ts";
import { readContainers } from "./docker.ts";
import { checkoutOf } from "./git.ts";
import { collectLinux } from "./linux/collect.ts";
import type { Address, Container, Snapshot } from "./model.ts";
import { annotate } from "./origin.ts";
import { type Run, run as system } from "./run.ts";
import { collectWindows } from "./windows/collect.ts";

export interface CollectOptions {
	/** Default: the one nethound runs on. */
	platform?: NodeJS.Platform;
	/** Linux: where proc/, sys/ and etc/ are; "/" for the real machine. */
	root?: string;
	/** Linux: addresses by interface; default os.networkInterfaces(). */
	addresses?: Record<string, Address[]>;
	/** macOS and Windows: runs their commands; tests pass recorded output. */
	run?: Run;
	/** Containers; default from `docker inspect`. */
	containers?: Container[];
	uid?: number;
	hostname?: string;
}

export function collect(o: CollectOptions = {}): Snapshot {
	const platform = o.platform ?? process.platform;
	const run = o.run ?? system;
	const machine =
		platform === "win32"
			? collectWindows(run)
			: platform === "darwin"
				? collectDarwin(run)
				: collectLinux(o.root ?? "/", o.addresses);
	// a container's network names a bridge on this machine only on Linux; Docker Desktop keeps
	// them in its VM
	const names = new Set(machine.interfaces.map((i) => i.name));
	const containers = (o.containers ?? readContainers()).map((c) => ({
		...c,
		networks: c.networks.map((n) => ({
			...n,
			bridge: n.bridge && names.has(n.bridge) ? n.bridge : undefined,
		})),
	}));
	// the git checkout each process runs in: which worktree's dev server is which
	const cache = new Map();
	for (const p of machine.processes)
		if (p.cwd) {
			const git = checkoutOf(p.cwd, cache);
			if (git) p.git = git;
		}
	// the app that launched each, and the project of those whose directory says nothing
	annotate(machine.processes, cache);
	return {
		hostname: o.hostname ?? hostname(),
		...machine,
		containers,
		uid: o.uid ?? process.getuid?.(),
	};
}
