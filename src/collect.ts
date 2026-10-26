// Reads one Snapshot of the machine, the way its OS tells: /proc and /sys on Linux, netstat,
// lsof and ifconfig on macOS, PowerShell on Windows. Docker is asked the same way everywhere.

import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { collectDarwin, parseArpAn } from "./darwin/collect.ts";
import { readMacFirewall } from "./darwin/firewall.ts";
import { readContainers } from "./docker.ts";
import { checkoutOf } from "./git.ts";
import { collectLinux } from "./linux/collect.ts";
import { readLinuxFirewall } from "./linux/firewall.ts";
import { readNeighbours } from "./linux/neighbours.ts";
import type { Address, Container, Snapshot } from "./model.ts";
import { annotate } from "./origin.ts";
import { type Run, run as system } from "./run.ts";
import { collectWindows } from "./windows/collect.ts";
import {
	parseNetshNeighbours,
	readWindowsPorts,
	readWindowsRouting,
} from "./wsl.ts";

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
	/** In WSL: also the ports Windows listens on (nethound doctor), through `run`. */
	windows?: boolean;
	/** In WSL: also Windows' routes (nethound doctor, map, route), through `run`. */
	windowsRouting?: boolean;
	/** Also what the firewall lets in (nethound doctor and who). */
	firewall?: boolean;
	/** Also the neighbour table (nethound map). */
	neighbours?: boolean;
}

export function collect(o: CollectOptions = {}): Snapshot {
	const platform = o.platform ?? process.platform;
	const run = o.run ?? system;
	const root = o.root ?? "/";
	const uid = o.uid ?? process.getuid?.();
	const found = o.containers ?? readContainers();
	const machine =
		platform === "win32"
			? collectWindows(run, o.firewall, o.neighbours)
			: platform === "darwin"
				? collectDarwin(run)
				: collectLinux(root, o.addresses, found);
	if (o.neighbours && platform !== "win32")
		machine.neighbours =
			platform === "darwin"
				? parseArpAn(run("arp", ["-an"]))
				: readNeighbours(join(root, "proc"));
	if (o.firewall && platform !== "win32") {
		const read = (p: string) => {
			try {
				return readFileSync(join(root, p), "utf8");
			} catch {
				return "";
			}
		};
		const firewall =
			platform === "darwin"
				? readMacFirewall(run)
				: readLinuxFirewall(root, read, run, machine.processes, uid);
		if (firewall) machine.firewall = firewall;
	}
	// a container's network names a bridge on this machine only on Linux; Docker Desktop keeps
	// them in its VM
	const names = new Set(machine.interfaces.map((i) => i.name));
	const containers = found.map((c) => ({
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
	const windowsPorts =
		o.windows && machine.environment === "wsl"
			? readWindowsPorts(run)
			: undefined;
	const windowsRouting =
		o.windowsRouting && machine.environment === "wsl"
			? readWindowsRouting(run)
			: undefined;
	if (o.neighbours && windowsRouting)
		windowsRouting.neighbours = parseNetshNeighbours(
			run("netsh.exe", ["interface", "ipv4", "show", "neighbors"]),
		);
	return {
		hostname: o.hostname ?? hostname(),
		...machine,
		...(windowsPorts && { windowsPorts }),
		...(windowsRouting && { windowsRouting }),
		containers,
		uid,
	};
}
