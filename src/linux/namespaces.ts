// The network namespaces other than nethound's, and what listens in each: a container's own
// sockets, which `ss` on the host doesn't show. /proc/PID/net/tcp shows PID's namespace, and anyone
// can read it, so a container's first process (from docker) is enough. Other namespaces are found
// by the processes in them, when /proc/PID/ns/net can be read: one's own, or all as root.

import { readdirSync, readlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Container, Namespace, Process, Socket } from "../model.ts";
import { readSockets } from "./sockets.ts";

/** net:[4026531840] → 4026531840; undefined when it can't be read (another user's, without root). */
function nsOf(proc: string, pid: number | "self"): number | undefined {
	try {
		const m = readlinkSync(join(proc, String(pid), "ns/net")).match(
			/^net:\[(\d+)\]$/,
		);
		return m?.[1] ? Number(m[1]) : undefined;
	} catch {
		return undefined;
	}
}

const listening = (s: Socket) =>
	s.state === "LISTEN" || (s.state === "UNCONN" && s.local.port !== 0);

export function readNamespaces(
	root: string,
	processes: Process[],
	owners: Map<number, number>,
	containers: Pick<Container, "id" | "pid" | "networks">[],
): Namespace[] {
	const proc = join(root, "proc");
	const own = nsOf(proc, "self");
	const byInode = new Map<number, Namespace>();
	const out: Namespace[] = [];
	const at = (inode: number) => {
		let ns = byInode.get(inode);
		if (!ns) {
			ns = { inode, pids: [] };
			byInode.set(inode, ns);
			out.push(ns);
		}
		return ns;
	};
	// containers first: theirs is the name that says most
	for (const c of containers) {
		// on the host's network, a container's sockets are the host's
		if (!c.pid || c.networks.some((n) => n.name === "host")) continue;
		const inode = nsOf(proc, c.pid);
		if (inode === own && inode !== undefined) continue;
		const ns: Namespace = inode === undefined ? { pids: [] } : at(inode);
		if (inode === undefined) out.push(ns);
		ns.container = c.id;
		ns.pids.push(c.pid);
	}
	for (const p of processes) {
		const inode = nsOf(proc, p.pid);
		if (inode === undefined || inode === own) continue;
		const ns = at(inode);
		if (!ns.pids.includes(p.pid)) ns.pids.push(p.pid);
	}
	// ip netns' names: their files are the namespaces themselves
	let names: string[] = [];
	try {
		names = readdirSync(join(root, "run/netns"));
	} catch {}
	for (const name of names)
		try {
			const ns = byInode.get(statSync(join(root, "run/netns", name)).ino);
			if (ns) ns.name = name;
		} catch {}
	for (const ns of out) {
		const [pid] = ns.pids;
		if (pid === undefined) continue;
		const dir = join(proc, String(pid));
		try {
			statSync(join(dir, "net/tcp"));
		} catch {
			continue;
		}
		ns.sockets = readSockets(dir)
			.filter(listening)
			// docker's DNS server in every container, held by dockerd: not the container's
			.filter((s) => !(ns.container && s.local.address === "127.0.0.11"))
			.map((s) => ({
				...s,
				pid: s.inode === undefined ? undefined : owners.get(s.inode),
			}));
	}
	return out.filter((ns) => ns.container || ns.sockets?.length);
}
