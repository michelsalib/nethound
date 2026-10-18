// nethound doctor: what is wrong with how this machine listens, each with what is behind it and how
// to fix it. Each rule is a function from the listeners to findings, so adding one is adding a
// function to RULES.

import { type Listener, listeners } from "./analyze.ts";
import type { Family, Iface, Snapshot, Socket } from "./model.ts";
import { isLoopback } from "./net.ts";

export type Severity = "error" | "warning" | "info";

export interface Finding {
	/** Which rule found it, e.g. "exposed". */
	rule: string;
	severity: Severity;
	/** One line: what is wrong. */
	title: string;
	/** What is behind it, a line each: the process, who answers where. */
	details: string[];
	/** What to do about it. */
	fix: string;
	proto: Socket["proto"];
	port: number;
}

type Rule = (snap: Snapshot, ls: Listener[]) => Finding[];

interface Service {
	name: string;
	ports: number[];
	/** Process names, without .exe. */
	processes: RegExp;
	/** Its process is that service on any port (a database); otherwise only on its ports (node is
	 * the inspector on 9229 alone). */
	anyPort?: boolean;
	severity: Severity;
	/** Why it matters, after "anyone who can reach it". */
	risk: string;
	/** How to keep it on this machine, when it is a process here. */
	bind: string;
}

// what should stay on this machine, and how each is told to
const SERVICES: Service[] = [
	{
		name: "Node.js inspector",
		ports: [9229],
		processes: /^node$/,
		severity: "error",
		risk: "can run any code as its user",
		bind: "start it with --inspect=127.0.0.1:9229 (or plain --inspect, which is local)",
	},
	{
		name: "Docker API without TLS",
		ports: [2375],
		processes: /^dockerd$/,
		severity: "error",
		risk: "controls docker: in effect, root on this machine",
		bind: "remove -H tcp://0.0.0.0:2375 (or the hosts entry in daemon.json); use the unix socket, or TLS on 2376",
	},
	{
		name: "PostgreSQL",
		anyPort: true,
		ports: [5432],
		processes: /^(postgres|postmaster)$/,
		severity: "warning",
		risk: "can try passwords, or log in where pg_hba.conf trusts",
		bind: "listen_addresses = 'localhost' in postgresql.conf",
	},
	{
		name: "MySQL",
		anyPort: true,
		ports: [3306, 33060],
		processes: /^(mysqld|mariadbd)$/,
		severity: "warning",
		risk: "can try passwords",
		bind: "bind-address = 127.0.0.1 in my.cnf",
	},
	{
		name: "Redis",
		anyPort: true,
		ports: [6379],
		processes: /^(redis-server|valkey-server)$/,
		severity: "warning",
		risk: "reads and writes every key, often without a password",
		bind: "bind 127.0.0.1 ::1 in redis.conf",
	},
	{
		name: "MongoDB",
		anyPort: true,
		ports: [27017, 27018, 27019],
		processes: /^mongod$/,
		severity: "warning",
		risk: "reads and writes every database when auth is off, its default",
		bind: "net.bindIp: 127.0.0.1 in mongod.conf",
	},
	{
		name: "Elasticsearch",
		anyPort: true,
		ports: [9200, 9300],
		processes: /^elasticsearch$/,
		severity: "warning",
		risk: "reads and writes every index when security is off",
		bind: "network.host: 127.0.0.1 in elasticsearch.yml",
	},
	{
		name: "Memcached",
		anyPort: true,
		ports: [11211],
		processes: /^memcached$/,
		severity: "warning",
		risk: "reads and writes the cache, with no password at all",
		bind: "start it with -l 127.0.0.1",
	},
	{
		name: "Jupyter",
		ports: [8888],
		processes: /^jupyter/,
		severity: "warning",
		risk: "runs code as its user, with only a token in the way",
		bind: "--ip=127.0.0.1 (c.ServerApp.ip in jupyter_server_config.py)",
	},
	{
		name: "a development server",
		ports: [3000, 3001, 4200, 5000, 5173, 8000, 8080, 8081],
		processes:
			/^(node|bun|deno|vite|python\d*(\.\d+)?|ruby|rails|php|java|dotnet)$/,
		severity: "info",
		risk: "sees what it serves: fine on purpose (to try it from a phone), worth knowing otherwise",
		bind: "bind it to 127.0.0.1 or localhost (vite --host, next -H, flask --host and the like say where)",
	},
];

const INTERNAL: Iface["kind"][] = ["loopback", "bridge", "veth", "virtual"];

/** The interfaces that lead off this machine: not the loopback, docker's bridges or VM switches. */
function outside(snap: Snapshot, l: Listener): string[] {
	const kind = new Map(snap.interfaces.map((i) => [i.name, i.kind]));
	return l.reach.interfaces.filter((n) => {
		const k = kind.get(n);
		return k !== undefined && !INTERNAL.includes(k);
	});
}

/** The service a listener is: a container by its image or port, a process by its name, else its port. */
function serviceOf(l: Listener): Service | undefined {
	if (l.container) {
		// postgres:18, bitnami/redis, mysql/mysql-server:8
		const image =
			l.container.image
				.replace(/[:@].*$/, "")
				.split("/")
				.pop() ?? "";
		const port = l.published?.containerPort ?? l.port;
		return (
			SERVICES.find(
				(s) => s.processes.test(image) || s.name.toLowerCase() === image,
			) ?? SERVICES.find((s) => s.severity !== "info" && s.ports.includes(port))
		);
	}
	const name = l.process?.name;
	if (!name)
		// another user's process: its port is all there is to go by
		return SERVICES.find(
			(s) => s.severity !== "info" && s.ports.includes(l.port),
		);
	return SERVICES.find(
		(s) => s.processes.test(name) && (s.anyPort || s.ports.includes(l.port)),
	);
}

/** Who is behind a listener, in a finding's words. */
function owner(l: Listener): string {
	if (l.container) return `container ${l.container.name}`;
	if (l.process) return `${l.process.name} ${l.process.pid}`;
	return `${l.user ?? "another user"}'s process`;
}

const exposed: Rule = (snap, ls) =>
	ls.flatMap((l) => {
		const s = serviceOf(l);
		const via = outside(snap, l);
		if (!s || !via.length) return [];
		const where =
			l.reach.scope === "everywhere" ? "every interface" : via.join(", ");
		const container = l.container && l.published;
		return [
			{
				rule: "exposed",
				severity: s.severity,
				proto: l.proto,
				port: l.port,
				title: `${s.name} on ${l.proto} ${l.port} is reachable from ${where}`,
				details: [
					`${owner(l)}, bound to ${l.addresses.join(", ")}`,
					`any machine that can reach ${via.join(", ")} ${s.risk}, unless a firewall stops it`,
					...(snap.environment === "wsl"
						? [
								"in WSL that is Windows itself, and other machines too with mirrored networking or a port Windows forwards",
							]
						: []),
				],
				fix: container
					? `publish it on this machine only: -p 127.0.0.1:${l.port}:${l.published?.containerPort} (in compose: "127.0.0.1:${l.port}:${l.published?.containerPort}")`
					: s.bind,
			},
		];
	});

/** The listener a client reaches at `address` (127.0.0.1, ::1, or a machine elsewhere). */
function answers(group: Listener[], family: Family, address?: string) {
	const takes = (l: Listener, a: string) =>
		l.sockets.some(
			(s) => s.local.address === a && (a !== "::" || family === 6 || !s.v6only),
		);
	// the socket on that very address wins over one on every address, as the kernel decides
	if (address) {
		const exact = group.find((l) => takes(l, address));
		if (exact) return exact;
	}
	return (
		group.find((l) => takes(l, family === 4 ? "0.0.0.0" : "::")) ??
		(family === 4 ? group.find((l) => takes(l, "::")) : undefined)
	);
}

/** The families a listener takes on every address, and the ones it has a specific address in. */
function spread(l: Listener) {
	const every = new Set<Family>();
	const some = new Set<Family>();
	for (const s of l.sockets) {
		if (s.local.address === "0.0.0.0") every.add(4);
		else if (s.local.address === "::") {
			every.add(6);
			if (!s.v6only) every.add(4);
		} else some.add(s.family);
	}
	return { every, some };
}

/** Two owners a client can mix up: one on every address and the other on one of them, or both on every address. */
function overlap(a: Listener, b: Listener): boolean {
	const x = spread(a);
	const y = spread(b);
	return ([4, 6] as Family[]).some(
		(f) =>
			(x.every.has(f) && (y.every.has(f) || y.some.has(f))) ||
			(y.every.has(f) && x.some.has(f)),
	);
}

/** One owner per program: a server's workers (nginx, gunicorn) share their port on purpose. */
const ownerKey = (l: Listener) =>
	l.container
		? `c ${l.container.id}`
		: l.process
			? `p ${l.process.name}`
			: `u ${l.user ?? "?"}`;

const portShared: Rule = (_snap, ls) => {
	const groups = new Map<string, Listener[]>();
	// UDP ports are shared on purpose (mDNS, DHCP): only TCP
	for (const l of ls.filter((x) => x.proto === "tcp")) {
		const k = String(l.port);
		groups.set(k, [...(groups.get(k) ?? []), l]);
	}
	const out: Finding[] = [];
	for (const group of groups.values()) {
		const owners = new Map(group.map((l) => [ownerKey(l), l]));
		if (owners.size < 2) continue;
		const port = group[0]?.port ?? 0;
		const ways: [string, Listener | undefined][] = [
			[
				`localhost over IPv4 (127.0.0.1:${port})`,
				answers(group, 4, "127.0.0.1"),
			],
			[`localhost over IPv6 ([::1]:${port})`, answers(group, 6, "::1")],
			[
				"other machines",
				answers(group, 4) ??
					answers(group, 6) ??
					group.find((l) => l.addresses.some((a) => !isLoopback(a))),
			],
		];
		const names = new Set(ways.map(([, l]) => l && ownerKey(l)));
		const split =
			ways[0]?.[1] &&
			ways[1]?.[1] &&
			ownerKey(ways[0][1]) !== ownerKey(ways[1][1]);
		const all = [...owners.values()];
		// on distinct addresses of their own (a DNS stub on 127.0.0.53, another on 10.255.255.254),
		// each client says which one it wants
		if (
			!split &&
			!all.some((a, i) => all.slice(i + 1).some((b) => overlap(a, b)))
		)
			continue;
		out.push({
			rule: "port-shared",
			severity: "warning",
			proto: "tcp",
			port,
			title: split
				? `localhost:${port} reaches ${owner(ways[0]?.[1] as Listener)} over IPv4 and ${owner(ways[1]?.[1] as Listener)} over IPv6`
				: `tcp ${port} is taken by ${owners.size} programs: ${all.map(owner).join(", ")}`,
			details: [
				...all.map((l) => `${owner(l)} on ${l.addresses.join(", ")}`),
				...(names.size > 1
					? ways.map(([way, l]) => `${way} → ${l ? owner(l) : "nobody"}`)
					: []),
			],
			fix: split
				? `a client may pick either (browsers and node try IPv6 first, many others IPv4): stop one, or move it to another port`
				: "stop one, or move it to another port: which one a client gets depends on the address it uses",
		});
	}
	return out;
};

export const RULES: Rule[] = [exposed, portShared];

const RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

/** Every finding, the most serious first, then by port. */
export function doctor(snap: Snapshot): Finding[] {
	const ls = listeners(snap);
	return RULES.flatMap((r) => r(snap, ls)).sort(
		(a, b) => RANK[a.severity] - RANK[b.severity] || a.port - b.port,
	);
}
