// The IPv4 neighbour table, from /proc/net/arp: the machines this one has exchanged packets with on
// each of its networks. The kernel keeps it; nethound only reads it.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Neighbour } from "../model.ts";
import { neighbour } from "../net.ts";

const ATF_COM = 0x2;

export function parseArp(text: string): Neighbour[] {
	const out: Neighbour[] = [];
	for (const line of text.split("\n").slice(1)) {
		const [ip, , flags, mac, , iface] = line.trim().split(/\s+/);
		if (!ip || !flags || !mac || !iface) continue;
		if (!(Number.parseInt(flags, 16) & ATF_COM)) continue;
		const n = neighbour(ip, mac, iface);
		if (n) out.push(n);
	}
	return out;
}

export function readNeighbours(proc: string): Neighbour[] {
	try {
		return parseArp(readFileSync(join(proc, "net/arp"), "utf8"));
	} catch {
		return [];
	}
}
