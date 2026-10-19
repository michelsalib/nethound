// Linux: everything from /proc, /sys and /etc. Every path is relative to `root`, so tests can
// point it at a fixture tree instead of the real machine.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Address, Container, Snapshot } from "../model.ts";
import { readInterfaces, systemAddresses } from "./interfaces.ts";
import { readNamespaces } from "./namespaces.ts";
import { readUsers, scanProcesses } from "./processes.ts";
import { readRoutes } from "./routes.ts";
import { readSockets } from "./sockets.ts";

const servers = (text: string) =>
	[...text.matchAll(/^\s*nameserver\s+(\S+)/gm)].map((m) => m[1] ?? "");

/** resolv.conf's servers; behind systemd-resolved's stub (127.0.0.53), the ones it asks too. */
function nameServers(read: (p: string) => string): string[] {
	const own = servers(read("etc/resolv.conf"));
	if (!own.includes("127.0.0.53")) return own;
	return [
		...new Set([...own, ...servers(read("run/systemd/resolve/resolv.conf"))]),
	];
}

export function collectLinux(
	root: string,
	addresses?: Record<string, Address[]>,
	containers: Container[] = [],
): Omit<Snapshot, "hostname" | "containers" | "uid"> {
	const proc = join(root, "proc");
	const read = (p: string) => {
		try {
			return readFileSync(join(root, p), "utf8");
		} catch {
			return "";
		}
	};
	const scan = scanProcesses(proc);
	// a socket on :: takes IPv4 too unless the system says otherwise (or the program, which /proc doesn't show)
	const v6only = read("proc/sys/net/ipv6/bindv6only").trim() === "1";
	const sockets = readSockets(proc).map((s) => ({
		...s,
		pid: s.inode === undefined ? undefined : scan.owners.get(s.inode),
		...(v6only && s.local.address === "::" && { v6only: true }),
	}));
	return {
		// WSL's kernel, and WSL's own files: a container on that kernel is no WSL, Windows forwards
		// nothing to it
		environment:
			/microsoft|wsl/i.test(read("proc/sys/kernel/osrelease")) &&
			(existsSync(join(root, "run/WSL")) ||
				existsSync(join(proc, "sys/fs/binfmt_misc/WSLInterop")))
				? "wsl"
				: "linux",
		interfaces: readInterfaces(
			join(root, "sys"),
			addresses ?? systemAddresses(),
		),
		routes: readRoutes(proc),
		sockets,
		processes: scan.processes,
		namespaces: readNamespaces(root, scan.processes, scan.owners, containers),
		users: readUsers(join(root, "etc/passwd")),
		dns: nameServers(read),
		hidden: scan.hidden,
	};
}
