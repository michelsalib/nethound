// macOS: no /proc, so its commands. Every socket of every user from `netstat -an`; the process
// behind each from `lsof` (without root, only your own: other users' show no process, as on
// Linux); interfaces from `ifconfig -a`, their traffic and index from `netstat -ibn`, which port is
// Wi-Fi from `networksetup`; routes from `netstat -rn`; processes from `ps`; for nethound map,
// neighbours from `arp -an`.

import { basename } from "node:path";
import type {
	Family,
	Iface,
	IfaceKind,
	Neighbour,
	Process,
	Proto,
	Route,
	Snapshot,
	Socket,
	SocketState,
} from "../model.ts";
import { neighbour, plainIP } from "../net.ts";
import type { Run } from "../run.ts";

const STATES: Record<string, SocketState> = {
	LISTEN: "LISTEN",
	ESTABLISHED: "ESTABLISHED",
	SYN_SENT: "SYN_SENT",
	SYN_RCVD: "SYN_RECV",
	FIN_WAIT_1: "FIN_WAIT1",
	FIN_WAIT_2: "FIN_WAIT2",
	TIME_WAIT: "TIME_WAIT",
	CLOSE_WAIT: "CLOSE_WAIT",
	LAST_ACK: "LAST_ACK",
	CLOSING: "CLOSING",
	CLOSED: "CLOSE",
};

/** "192.168.1.20.443", "fe80::1%lo0.5432", "*.8080": the port comes after the last dot. */
function netstatEndpoint(s: string, family: Family) {
	const dot = s.lastIndexOf(".");
	const host = s.slice(0, dot);
	const port = s.slice(dot + 1);
	const address =
		host === "*" ? (family === 4 ? "0.0.0.0" : "::") : plainIP(host).address;
	return { address, port: port === "*" ? 0 : Number(port) };
}

/** Sockets from `netstat -an`: tcp4, tcp6 and tcp46 (one socket for both families), and udp. */
export function parseNetstatSockets(text: string): Socket[] {
	const out: Socket[] = [];
	for (const line of text.split("\n")) {
		const f = line.trim().split(/\s+/);
		const m = f[0]?.match(/^(tcp|udp)(4|6|46)$/);
		if (!m || f.length < 5) continue;
		const proto = m[1] as Proto;
		const both = m[2] === "46";
		const family: Family = m[2] === "4" ? 4 : 6;
		const local = netstatEndpoint(f[3] ?? "", family);
		const remote = netstatEndpoint(f[4] ?? "", family);
		const state: SocketState | undefined =
			proto === "udp"
				? remote.port === 0
					? "UNCONN"
					: "ESTABLISHED"
				: STATES[f[5] ?? ""];
		if (!state) continue;
		const l = plainIP(local.address);
		out.push({
			proto,
			family: l.family,
			local: { address: l.address, port: local.port },
			remote,
			state,
			...(family === 6 && !both && local.address === "::" && { v6only: true }),
		});
	}
	return out;
}

export interface LsofSocket {
	pid: number;
	uid: number;
	proto: Proto;
	local: { address: string; port: number };
	remote?: { address: string; port: number };
}

/** "127.0.0.1:5000", "[::1]:5432", "*:8080": lsof's endpoints. */
function lsofEndpoint(s: string, v6: boolean) {
	const m = s.match(/^\[?(.*?)\]?:(\d+|\*)$/);
	const host = m?.[1] ?? "*";
	return {
		address: host === "*" ? (v6 ? "::" : "0.0.0.0") : plainIP(host).address,
		port: m?.[2] === "*" ? 0 : Number(m?.[2] ?? 0),
	};
}

/** Internet sockets by process from `lsof -nP -iTCP -iUDP -FpuftPn`. */
export function parseLsof(text: string): LsofSocket[] {
	const out: LsofSocket[] = [];
	let pid = 0;
	let uid = -1;
	let file: { type?: string; proto?: string } = {};
	for (const line of text.split("\n")) {
		const k = line[0];
		const v = line.slice(1);
		if (k === "p") pid = Number(v);
		else if (k === "u") uid = Number(v);
		else if (k === "f") file = {};
		else if (k === "t") file.type = v;
		else if (k === "P") file.proto = v.toLowerCase();
		else if (k === "n" && (file.proto === "tcp" || file.proto === "udp")) {
			const v6 = file.type === "IPv6";
			const [l = "", r] = v.split("->");
			out.push({
				pid,
				uid,
				proto: file.proto,
				local: lsofEndpoint(l, v6),
				remote: r ? lsofEndpoint(r, v6) : undefined,
			});
		}
	}
	return out;
}

/** Working directories by pid, from `lsof -a -d cwd -Fn -p PIDS`. */
export function parseLsofCwd(text: string): Map<number, string> {
	const out = new Map<number, string>();
	let pid = 0;
	for (const line of text.split("\n")) {
		if (line[0] === "p") pid = Number(line.slice(1));
		else if (line[0] === "n" && pid) out.set(pid, line.slice(1));
	}
	return out;
}

const key = (
	proto: Proto,
	l: { address: string; port: number },
	r?: { address: string; port: number },
) =>
	`${proto} ${l.address} ${l.port} ${r?.port ? `${r.address} ${r.port}` : "*"}`;

/** Each socket's process, where lsof could see it. */
export function owners(sockets: Socket[], files: LsofSocket[]): Socket[] {
	const by = new Map<string, LsofSocket>();
	for (const f of files) {
		const k = key(f.proto, f.local, f.remote);
		// a socket shared by several processes (a forked server) keeps the first
		if (!by.has(k)) by.set(k, f);
	}
	return sockets.map((s) => {
		const f = by.get(key(s.proto, s.local, s.remote));
		if (f) return { ...s, pid: f.pid, uid: f.uid };
		// nobody holds a TIME_WAIT socket
		return s.state === "TIME_WAIT" ? { ...s, orphan: true } : s;
	});
}

/** "1-02:03:04", "02:03:04", "03:04": how long ago a process started, as ps's etime says, in ms. */
export function elapsed(etime: string): number {
	const [days, clock = ""] = etime.includes("-")
		? etime.split("-")
		: ["0", etime];
	const [s = 0, m = 0, h = 0] = clock.split(":").map(Number).reverse();
	return (((Number(days) * 24 + h) * 60 + m) * 60 + s) * 1000;
}

/** `ps -axo pid=,ppid=,uid=,user=,etime=,comm=` and `ps -axww -o pid=,args=`; `now` for start times. */
export function parsePs(
	names: string,
	args: string,
	now = Date.now(),
): { processes: Process[]; users: Record<number, string> } {
	const cmds = new Map<number, string>();
	for (const line of args.split("\n")) {
		const m = line.match(/^\s*(\d+)\s+(.*)$/);
		if (m?.[1] && m[2]) cmds.set(Number(m[1]), m[2].trim());
	}
	const processes: Process[] = [];
	const users: Record<number, string> = {};
	for (const line of names.split("\n")) {
		const m = line.match(
			/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+([\d:-]+)\s+(.*)$/,
		);
		if (!m?.[1] || !m[2] || !m[3] || !m[4] || !m[5] || !m[6]) continue;
		const pid = Number(m[1]);
		const ppid = Number(m[2]);
		const uid = Number(m[3]);
		users[uid] = m[4];
		const name = basename(m[6].trim());
		processes.push({
			pid,
			name,
			cmd: cmds.get(pid) || name,
			uid,
			...(ppid > 0 && { ppid }),
			started: now - elapsed(m[5]),
		});
	}
	return { processes, users };
}

const v4mask = (hex: string) =>
	Number.parseInt(hex, 16).toString(2).replace(/0+$/, "").length;

function kindOf(name: string, wifi: Set<string>): IfaceKind {
	if (/^lo\d/.test(name)) return "loopback";
	if (wifi.has(name)) return "wifi";
	if (/^bridge\d/.test(name)) return "bridge";
	if (/^(utun|ipsec|ppp|tun|tap)\d/.test(name)) return "tun";
	if (/^vlan\d/.test(name)) return "vlan";
	if (/^bond\d/.test(name)) return "bond";
	if (/^en\d/.test(name)) return "ethernet";
	// awdl, llw, anpi, ap, gif, stf, vmenet…
	return "virtual";
}

/** Interfaces from `ifconfig -a`; Wi-Fi ports by name from `networksetup -listallhardwareports`. */
export function parseIfconfig(text: string, wifiPorts: string): Iface[] {
	const wifi = new Set(
		[...wifiPorts.matchAll(/Hardware Port: Wi-Fi\s*\nDevice: (\S+)/g)].map(
			(m) => m[1] ?? "",
		),
	);
	const out: (Iface & { status?: string; flags: string[] })[] = [];
	let cur: (typeof out)[number] | undefined;
	for (const line of text.split("\n")) {
		const head = line.match(/^(\S+): flags=\w+<([^>]*)> mtu (\d+)/);
		if (head?.[1]) {
			cur = {
				name: head[1],
				index: 0,
				kind: kindOf(head[1], wifi),
				state: "unknown",
				mtu: Number(head[3]),
				addresses: [],
				members: [],
				rxBytes: 0,
				txBytes: 0,
				flags: (head[2] ?? "").split(","),
			};
			out.push(cur);
			continue;
		}
		if (!cur) continue;
		const f = line.trim().split(/\s+/);
		if (f[0] === "ether") cur.mac = f[1];
		// "inet 10.8.0.2 --> 10.8.0.2 netmask 0xffffffff" on point-to-point links
		else if (f[0] === "inet" && f[1] && f.includes("netmask"))
			cur.addresses.push({
				family: 4,
				address: f[1],
				prefix: v4mask(f[f.indexOf("netmask") + 1] ?? "0"),
			});
		else if (f[0] === "inet6" && f[1]) {
			const prefix = Number(f[f.indexOf("prefixlen") + 1] ?? 128);
			cur.addresses.push({ family: 6, address: plainIP(f[1]).address, prefix });
		} else if (f[0] === "status:") cur.status = f[1];
		else if (f[0] === "member:" && f[1]) cur.members.push(f[1]);
	}
	for (const i of out) {
		const up = i.flags.includes("UP") && i.flags.includes("RUNNING");
		// `status:` says whether the link is there; interfaces without one have only their flags
		i.state = i.status
			? i.status === "active" && up
				? "up"
				: "down"
			: up
				? "up"
				: "down";
		for (const m of i.members) {
			const port = out.find((x) => x.name === m);
			if (port) port.master = i.name;
		}
	}
	return out.map(({ status, flags, ...i }) => i);
}

/** Traffic and index by interface, from the <Link#N> rows of `netstat -ibn`. */
export function parseNetstatI(text: string) {
	const out = new Map<string, { index: number; rx: number; tx: number }>();
	for (const line of text.split("\n")) {
		const f = line.trim().split(/\s+/);
		const link = f[2]?.match(/^<Link#(\d+)>$/);
		if (!link?.[1] || !f[0] || out.has(f[0])) continue;
		// the MAC address column is empty on some links: count from the end
		// (Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll)
		const n = (i: number) => Number(f[f.length - i]) || 0;
		out.set(f[0].replace(/\*$/, ""), {
			index: Number(link[1]),
			rx: n(5),
			tx: n(2),
		});
	}
	return out;
}

/** "default", "127", "192.168.1", "10/8", "fe80::%lo0/64", "::1": macOS's destinations. */
function destination(d: string, family: Family, host: boolean) {
	if (d === "default")
		return { dest: family === 4 ? "0.0.0.0" : "::", prefix: 0 };
	const [net = "", len] = d.split("/");
	if (family === 6) {
		const a = plainIP(net).address;
		return { dest: a, prefix: len ? Number(len) : 128 };
	}
	const octets = net.split(".");
	const dest = [...octets, "0", "0", "0"].slice(0, 4).join(".");
	const prefix = len ? Number(len) : host ? 32 : octets.length * 8;
	return { dest, prefix };
}

/** The routing table from `netstat -rn`: its Internet and Internet6 sections. */
export function parseNetstatRoutes(text: string): Route[] {
	const out: Route[] = [];
	let family: Family | undefined;
	let col: Record<string, number> = {};
	for (const line of text.split("\n")) {
		if (/^Internet:/.test(line)) family = 4;
		else if (/^Internet6:/.test(line)) family = 6;
		const f = line.trim().split(/\s+/);
		if (f[0] === "Destination") {
			col = Object.fromEntries(f.map((name, i) => [name, i]));
			continue;
		}
		if (!family || col.Netif === undefined || f.length <= col.Netif) continue;
		const [d = "", gw = "", flags = ""] = [f[0], f[1], f[col.Flags ?? 2]];
		const iface = f[col.Netif] ?? "";
		// interface-scoped copies (I), neighbours (L: ARP and NDP entries), rejected and blackholed,
		// multicast and broadcast
		if (/[ILRB]/.test(flags) || /^(22[4-9]|23\d|255)\b|^ff/.test(d)) continue;
		const { dest, prefix } = destination(d, family, flags.includes("H"));
		const gateway = flags.includes("G") ? plainIP(gw).address : undefined;
		out.push({ family, dest, prefix, gateway, iface, metric: 0 });
	}
	return out;
}

/** The IPv4 neighbour table from `arp -an` (-n: no name looked up): "? (192.168.1.1) at
 * a4:91:b1:12:34:56 on en0 ifscope [ethernet]", MACs without leading zeros (1:0:5e:0:0:fb). */
export function parseArpAn(text: string): Neighbour[] {
	const out: Neighbour[] = [];
	for (const m of text.matchAll(/\((\S+)\) at (\S+) on (\S+)/g)) {
		const n = neighbour(m[1] ?? "", m[2] ?? "", m[3] ?? "");
		if (n) out.push(n);
	}
	return out;
}

export function collectDarwin(
	run: Run,
): Omit<Snapshot, "hostname" | "containers" | "uid"> {
	const interfaces = parseIfconfig(
		run("ifconfig", ["-a"]),
		run("networksetup", ["-listallhardwareports"]),
	);
	const traffic = parseNetstatI(run("netstat", ["-ibn"]));
	interfaces.forEach((i, n) => {
		const t = traffic.get(i.name);
		i.index = t?.index ?? n + 1;
		i.rxBytes = t?.rx ?? 0;
		i.txBytes = t?.tx ?? 0;
	});
	const sockets = owners(
		parseNetstatSockets(run("netstat", ["-an"])),
		parseLsof(run("lsof", ["-nP", "-iTCP", "-iUDP", "-FpuftPn"])),
	);
	const { processes, users } = parsePs(
		run("ps", ["-axo", "pid=,ppid=,uid=,user=,etime=,comm="]),
		run("ps", ["-axww", "-o", "pid=,args="]),
	);
	// the working directories of the servers: one lsof for them all (without root, ours only)
	const servers = [
		...new Set(
			sockets.filter((s) => s.state === "LISTEN" && s.pid).map((s) => s.pid),
		),
	].sort((a, b) => (a ?? 0) - (b ?? 0));
	if (servers.length) {
		const cwds = parseLsofCwd(
			run("lsof", ["-a", "-d", "cwd", "-Fn", "-p", servers.join(",")]),
		);
		for (const p of processes) {
			const cwd = cwds.get(p.pid);
			if (cwd) p.cwd = cwd;
		}
	}
	return {
		environment: "macos",
		interfaces,
		routes: parseNetstatRoutes(run("netstat", ["-rn"])),
		sockets,
		processes,
		users,
		dns: [
			...run("cat", ["/etc/resolv.conf"]).matchAll(/^\s*nameserver\s+(\S+)/gm),
		].map((m) => plainIP(m[1] ?? "").address),
		hidden: 0,
	};
}
