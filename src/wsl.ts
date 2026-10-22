// In WSL: the TCP ports Windows itself listens on, read through Windows' own commands, which WSL
// can run. Windows forwards its localhost to WSL only for ports it doesn't hold, so a Windows
// program on the same port as a WSL server takes localhost from it. netstat, tasklist and netsh
// answer in half a second, where PowerShell takes several.

import type { Iface, Route, WindowsPort } from "./model.ts";
import { plainIP } from "./net.ts";
import type { Run } from "./run.ts";
import { kindOf } from "./windows/collect.ts";

/** Listening sockets from `netstat -ano -p TCP` and `-p TCPv6`. The state is translated (ÉCOUTE in
 * French), so a listener is told by its remote end, 0.0.0.0:0 or [::]:0. */
export function parseNetstatListeners(
	text: string,
): Omit<WindowsPort, "name">[] {
	const out: Omit<WindowsPort, "name">[] = [];
	for (const line of text.split("\n")) {
		const m = line.match(
			/^\s*TCP\s+(\S+):(\d+)\s+(?:0\.0\.0\.0|\[::\]):0\s+\S+\s+(\d+)\s*$/,
		);
		if (!m) continue;
		const [, address = "", port = "", pid = ""] = m;
		out.push({
			address: plainIP(address.replace(/^\[|\]$/g, "")).address,
			port: Number(port),
			pid: Number(pid),
		});
	}
	return out;
}

/** Image names by pid, from `tasklist /fo csv /nh`, without .exe. */
export function parseTasklist(text: string): Map<number, string> {
	const out = new Map<number, string>();
	for (const m of text.matchAll(/^"([^"]*)","(\d+)"/gm))
		out.set(Number(m[2]), (m[1] ?? "").replace(/\.exe$/i, ""));
	return out;
}

/** The ports `netsh interface portproxy` forwards: often to WSL, on purpose. Its headers are
 * translated, its rows are four columns of addresses and ports. */
export function parsePortProxy(text: string): Set<number> {
	const out = new Set<number>();
	for (const line of text.split("\n")) {
		const f = line.trim().split(/\s+/);
		if (f.length === 4 && /^\d+$/.test(f[1] ?? "") && /^\d+$/.test(f[3] ?? ""))
			out.add(Number(f[1]));
	}
	return out;
}

/** What Windows listens on; undefined when WSL can't run Windows' programs (interop off). */
export function readWindowsPorts(run: Run): WindowsPort[] | undefined {
	const netstat = ["TCP", "TCPv6"]
		.map((p) => run("netstat.exe", ["-ano", "-p", p]))
		.join("\n");
	if (!netstat.trim()) return undefined;
	const names = parseTasklist(run("tasklist.exe", ["/fo", "csv", "/nh"]));
	const proxied = parsePortProxy(
		run("netsh.exe", ["interface", "portproxy", "show", "all"]),
	);
	return parseNetstatListeners(netstat).map((p) => ({
		...p,
		name: names.get(p.pid),
		...(proxied.has(p.port) && { proxy: true }),
	}));
}

/** Interfaces from `netsh interface ipv4 show interfaces`: index, metric, MTU, state, name. The
 * state stays in English in every language. */
export function parseNetshInterfaces(
	text: string,
): { index: number; metric: number; mtu: number; up: boolean; name: string }[] {
	const out = [];
	for (const line of text.split("\n")) {
		const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$/);
		if (!m) continue;
		const [, index = "", metric = "", mtu = "", state = "", name = ""] = m;
		out.push({
			index: Number(index),
			metric: Number(metric),
			mtu: Number(mtu),
			up: state === "connected",
			name,
		});
	}
	return out;
}

/** IPv4 routes from `netsh interface ipv4 show route`: metric, prefix, interface index, and a
 * gateway, or the interface's name for a route on its link. */
export function parseNetshRoutes(text: string): {
	metric: number;
	dest: string;
	prefix: number;
	index: number;
	gateway?: string;
}[] {
	const out = [];
	for (const line of text.split("\n")) {
		const m = line.match(
			/^\S+\s+\S+\s+(\d+)\s+([\d.]+)\/(\d+)\s+(\d+)\s+(.+?)\s*$/,
		);
		if (!m) continue;
		const [, metric = "", dest = "", prefix = "", index = "", hop = ""] = m;
		out.push({
			metric: Number(metric),
			dest,
			prefix: Number(prefix),
			index: Number(index),
			...(/^\d+\.\d+\.\d+\.\d+$/.test(hop) &&
				hop !== "0.0.0.0" && { gateway: hop }),
		});
	}
	return out;
}

/** IPv4 addresses by interface index, from `netsh interface ipv4 show ipaddresses`: an
 * "Interface 4 : Ethernet" line, then rows ending with an address. */
export function parseNetshAddresses(text: string): Map<number, string[]> {
	const out = new Map<number, string[]>();
	let index: number | undefined;
	for (const line of text.split("\n")) {
		const head = line.match(/^Interface (\d+)\s*:/);
		if (head) {
			index = Number(head[1]);
			continue;
		}
		const a = line.match(/\s(\d+\.\d+\.\d+\.\d+)\s*$/);
		if (a?.[1] && index !== undefined)
			out.set(index, [...(out.get(index) ?? []), a[1]]);
	}
	return out;
}

/** Adapters' descriptions by name, from `ipconfig /all`: each block opens with a line ending in
 * "<name> :" (its first words, the adapter's type, are translated), then a "Description" line. */
export function parseIpconfigDescriptions(
	text: string,
	names: string[],
): Map<string, string> {
	const out = new Map<string, string>();
	let name: string | undefined;
	for (const line of text.split("\n")) {
		if (/^\S.*:\s*$/.test(line)) {
			const head = line.replace(/\s*:\s*$/, "");
			// the longest name the header ends with: "vEthernet (WSL)" over "Ethernet"
			name = names
				.filter((n) => head === n || head.endsWith(` ${n}`))
				.sort((a, b) => b.length - a.length)[0];
			continue;
		}
		const d = line.match(/^\s+Description[ .]*:\s*(.+?)\s*$/);
		if (d?.[1] && name && !out.has(name)) out.set(name, d[1]);
	}
	return out;
}

/** Windows' IPv4 interfaces and routes, for where Windows sends what WSL hands it (behind NAT, a
 * VPN Windows runs is invisible from WSL); undefined when WSL can't run Windows' programs. Four
 * commands that answer in a tenth of a second each, where PowerShell takes several. */
export function readWindowsRouting(
	run: Run,
): { interfaces: Iface[]; routes: Route[] } | undefined {
	const list = parseNetshInterfaces(
		run("netsh.exe", ["interface", "ipv4", "show", "interfaces"]),
	);
	if (!list.length) return undefined;
	const addresses = parseNetshAddresses(
		run("netsh.exe", ["interface", "ipv4", "show", "ipaddresses"]),
	);
	const described = parseIpconfigDescriptions(
		run("ipconfig.exe", ["/all"]),
		list.map((i) => i.name),
	);
	const interfaces: Iface[] = list.map((i) => {
		const description = described.get(i.name);
		const wireless =
			/wi-?fi|wireless|802\.11/i.test(description ?? "") &&
			!/direct/i.test(description ?? "");
		return {
			name: i.name,
			index: i.index,
			kind: /loopback/i.test(i.name)
				? "loopback"
				: kindOf(wireless ? "Wireless80211" : "Ethernet", description ?? ""),
			...(description && { description }),
			state: i.up ? "up" : "down",
			mtu: i.mtu,
			addresses: (addresses.get(i.index) ?? []).map((address) => ({
				family: 4,
				address,
				prefix: 32,
			})),
			members: [],
			rxBytes: 0,
			txBytes: 0,
		};
	});
	const byIndex = new Map(list.map((i) => [i.index, i]));
	const own = new Set([...addresses.values()].flat());
	const routes: Route[] = parseNetshRoutes(
		run("netsh.exe", ["interface", "ipv4", "show", "route"]),
	).flatMap((r) => {
		const i = byIndex.get(r.index);
		// as from PowerShell: no multicast, broadcast, or host routes to its own addresses
		const skip =
			/^(22[4-9]|23\d)\./.test(r.dest) ||
			(r.prefix === 32 && (own.has(r.dest) || r.dest.endsWith(".255")));
		// Windows ranks routes by the route's metric plus its interface's
		return i?.up && !skip
			? [
					{
						family: 4,
						dest: r.dest,
						prefix: r.prefix,
						...(r.gateway && { gateway: r.gateway }),
						iface: i.name,
						metric: r.metric + i.metric,
					},
				]
			: [];
	});
	return { interfaces, routes };
}
