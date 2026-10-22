// nethound doctor: what is wrong with how this machine listens and routes, each with what is behind
// it and how to fix it. Each rule is a function from the snapshot and its listeners to findings,
// so adding one is adding a function to RULES.

import {
	DOCKER,
	insideListeners,
	type Listener,
	listeners,
	publishedTarget,
	type RouteResult,
	routeTo,
	upVpns,
	VPN_KINDS,
	vpnLabel,
	widest,
} from "./analyze.ts";
import { INTERNAL, outside, verdictFor } from "./firewall.ts";
import type { Family, Route, Snapshot, Socket } from "./model.ts";
import { inNetwork, isLinkLocal, isLoopback, isWildcard } from "./net.ts";

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
	/** The port it is about; none for the routing rules. */
	proto?: Socket["proto"];
	port?: number;
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
		const fw = verdictFor(snap, l, via);
		const blocked = fw?.result === "blocked";
		return [
			{
				rule: "exposed",
				// bound to the network, but the firewall keeps it here: fine until the firewall changes
				severity: blocked ? "info" : s.severity,
				proto: l.proto,
				port: l.port,
				title: blocked
					? `${s.name} on ${l.proto} ${l.port} is bound to ${where}, but the firewall blocks it`
					: `${s.name} on ${l.proto} ${l.port} is reachable from ${where}`,
				details: [
					`${owner(l)}, bound to ${l.addresses.join(", ")}`,
					...(blocked
						? [
								`firewall: ${fw.why}`,
								"fine while the firewall stays as it is; bound to this machine, it wouldn't depend on it",
							]
						: [
								`any machine that can reach ${via.join(", ")} ${s.risk}${fw ? "" : ", unless a firewall stops it"}`,
								...(fw ? [`firewall: ${fw.why}`] : []),
							]),
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

/** One owner per program: a server's workers (nginx, gunicorn) share their port on purpose, from
 * one directory; the same program in two checkouts is two servers. */
const ownerKey = (l: Listener) =>
	l.container
		? `c ${l.container.id}`
		: l.process
			? `p ${l.process.name} ${l.process.cwd ?? ""}`
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

/** A socket that takes IPv4 clients: an IPv4 one, or one on :: that takes both. */
const takes4 = (s: Socket) =>
	s.family === 4 || (s.local.address === "::" && !s.v6only);

const ipv6Only: Rule = (snap, ls) => {
	const tcp = ls.filter((l) => l.proto === "tcp");
	return tcp.flatMap((l): Finding[] => {
		// a published port the firewall forwards has no socket to go by
		if (!l.sockets.length || l.sockets.some(takes4)) return [];
		const loop = l.addresses.every((a) => a === "::1");
		// on an address of its own, clients ask for that address
		if (!loop && !l.addresses.includes("::")) return [];
		// another program takes IPv4 on that port: port-shared says who answers where
		if (tcp.some((o) => o !== l && o.port === l.port && o.sockets.some(takes4)))
			return [];
		const base = { rule: "ipv6-only", proto: "tcp" as const, port: l.port };
		const first =
			"localhost works for clients that try IPv6 first (browsers, curl, node 17 and later)";
		if (loop)
			return [
				{
					...base,
					severity: "info",
					title: `${owner(l)} on tcp ${l.port} listens on ::1 only: 127.0.0.1:${l.port} is refused`,
					details: [
						`${first}; 127.0.0.1 and older tools get connection refused`,
						"node 17 and later resolve localhost to ::1 first, so a server told to listen on localhost often ends up there",
					],
					fix: `bind it to 127.0.0.1 (vite --host 127.0.0.1, server.listen(${l.port}, "127.0.0.1")), or ask for localhost:${l.port} rather than 127.0.0.1`,
				},
			];
		return [
			{
				...base,
				severity: "warning",
				title: `${owner(l)} on tcp ${l.port} takes IPv6 only: IPv4 clients are refused`,
				details: [
					`bound to :: for IPv6 alone${snap.environment === "windows" ? ", Windows' default" : ""}: it looks open on every interface, but not to IPv4`,
					`127.0.0.1:${l.port} and other machines over IPv4 get connection refused; ${first}`,
				],
				fix: "bind it to 0.0.0.0 as well, or make its socket on :: take both (IPV6_V6ONLY off)",
			},
		];
	});
};

/** In WSL: a Windows program on a port WSL serves takes Windows' localhost from it. */
const wslShadowed: Rule = (snap, ls) => {
	const windows = snap.windowsPorts;
	if (snap.environment !== "wsl" || !windows) return [];
	const ip = snap.interfaces
		.find((i) => i.kind === "ethernet" && i.state !== "down")
		?.addresses.find((a) => a.family === 4)?.address;
	return ls.flatMap((l): Finding[] => {
		// Windows forwards its localhost to what WSL holds on the loopback or on every address
		if (
			l.proto !== "tcp" ||
			!l.addresses.some((a) => isWildcard(a) || isLoopback(a))
		)
			return [];
		const theirs = windows.filter(
			(w) =>
				w.port === l.port &&
				// a port proxy, wslrelay or Docker Desktop: forwarding to WSL, not a server of Windows'
				!w.proxy &&
				!DOCKER.test(w.name ?? "") &&
				(isWildcard(w.address) || isLoopback(w.address)),
		);
		const [w] = theirs;
		if (!w) return [];
		// one program's two halves: a relay in WSL to its Windows side on the same port (Orca's)
		const cmd = l.process?.cmd.toLowerCase() ?? "";
		const name = w.name?.toLowerCase() ?? "";
		if (
			/relay|proxy|forward/.test(cmd) ||
			(name.length > 2 && cmd.includes(name))
		)
			return [];
		const them = `${w.name ?? "a process"} ${w.pid}`;
		return [
			{
				rule: "wsl-port-shadowed",
				severity: "warning",
				proto: "tcp",
				port: l.port,
				title: `localhost:${l.port} in Windows reaches ${them}, not ${owner(l)} in WSL`,
				details: [
					`in WSL: ${owner(l)} on ${l.addresses.join(", ")}`,
					`in Windows: ${them} on ${[...new Set(theirs.map((x) => x.address))].join(", ")}`,
					"Windows forwards its localhost to WSL only for the ports it doesn't hold itself: a browser in Windows gets Windows' server",
				],
				fix: `stop one, or move it to another port${ip ? `; from Windows, WSL's is still at ${ip}:${l.port}` : ""}`,
			},
		];
	});
};

/** A port docker publishes, to a container where nothing takes it: connections are reset. */
const publishedNowhere: Rule = (snap, ls) =>
	ls.flatMap((l): Finding[] => {
		const c = l.container;
		const p = l.published;
		if (!c || !p) return [];
		const t = publishedTarget(snap, c, p);
		const base = {
			rule: "published-nowhere",
			severity: "warning" as const,
			proto: l.proto,
			port: l.port,
		};
		// keeping the host address it is published on
		const host = isWildcard(p.hostIp) ? "" : `${p.hostIp}:`;
		const map = (inside: number) =>
			`-p ${host}${l.port}:${inside} (in compose: "${host}${l.port}:${inside}")`;
		if (t.state === "nothing") {
			// what it does listen on, to other containers and the published ports
			const elsewhere = insideListeners(snap).filter(
				(x) =>
					x.container?.id === c.id &&
					x.proto === l.proto &&
					!x.addresses.every(isLoopback),
			);
			const [only] = elsewhere;
			return [
				{
					...base,
					title: `${l.proto} ${l.port} goes to ${p.containerPort} in container ${c.name}, where nothing listens`,
					details: [
						"docker accepts the connection, finds nobody behind it, and closes it",
						elsewhere.length
							? `in the container, ${elsewhere.map((x) => x.port).join(", ")} ${elsewhere.length > 1 ? "listen" : "listens"} instead`
							: "nothing in it listens on the network: still starting, or its server didn't start (docker logs)",
					],
					fix:
						only && elsewhere.length === 1
							? `publish the port it listens on: ${map(only.port)}`
							: "start its server, or publish the port it listens on",
				},
			];
		}
		if (t.state === "loopback") {
			const [x] = t.inside;
			const ip = c.networks.find((n) => n.ip)?.ip;
			return [
				{
					...base,
					title: `${l.proto} ${l.port} goes to container ${c.name}, where ${p.containerPort} listens on ${x?.addresses.join(", ")} only`,
					details: [
						`docker forwards to the container's own address${ip ? ` (${ip})` : ""}, which its server doesn't take: connections are reset`,
					],
					fix: "bind it to 0.0.0.0 in the container: a dev server's --host 0.0.0.0 (vite, flask run, next -H), or HOST=0.0.0.0",
				},
			];
		}
		return [];
	});

/** Any address on the internet: where traffic to it goes is where the internet goes. */
const INTERNET: Record<Family, string> = {
	4: "1.1.1.1",
	6: "2606:4700:4700::1111",
};
const FAMILIES: Family[] = [4, 6];

const kindOf = (snap: Snapshot, name?: string) =>
	snap.interfaces.find((i) => i.name === name)?.kind;

const isLinkLocalNet = (r: Route) =>
	r.dest.startsWith("169.254.") || /^fe[89ab][0-9a-f]:/i.test(r.dest);

const net = (r: Route) => `${r.dest}/${r.prefix}`;

/** "default via 192.168.1.1 on eth0", "10.8.0.0/16 on utun4". */
const routeText = (r: Route) =>
	`${r.prefix === 0 ? "default" : net(r)}${r.gateway ? ` via ${r.gateway}` : ""} on ${r.iface}`;

const unique = (xs: string[]) => [...new Set(xs)];

/** The networks a route table reaches, by name: "192.168.1.0/24 on wlan0". */
const networks = (rs: Route[]) =>
	unique(rs.map((r) => `${net(r)} on ${r.iface}`)).join(", ");

const offline = (snap: Snapshot) =>
	FAMILIES.every((f) => routeTo(snap, INTERNET[f]).kind === "unreachable");

const noDefaultRoute: Rule = (snap) => {
	if (!offline(snap)) return [];
	const reach = snap.routes.filter(
		(r) => kindOf(snap, r.iface) !== "loopback" && !isLinkLocalNet(r),
	);
	return [
		{
			rule: "no-default-route",
			severity: "warning",
			title: "no route to the internet: there is no default route",
			details: [
				reach.length
					? `this machine reaches only ${networks(reach)}`
					: "nor any network: every interface is down or has no address",
				...(snap.dns.some((d) => routeTo(snap, d).kind === "unreachable")
					? ["name lookups wait for DNS servers they can't reach, and fail"]
					: []),
			],
			fix: reach.length
				? "the network gave no gateway: reconnect to renew the lease, or set the gateway in the interface's settings; a VPN that went away can take it along: restart it"
				: "connect to a network: Wi-Fi or Ethernet",
		},
	];
};

const defaultRoutes: Rule = (snap) => {
	// macOS gives no metrics: the service order in its Network settings decides
	if (snap.environment === "macos") return [];
	return FAMILIES.flatMap((f): Finding[] => {
		const defaults = snap.routes.filter(
			(r) => r.family === f && r.prefix === 0,
		);
		const best = Math.min(...defaults.map((r) => r.metric));
		const tied = defaults.filter((r) => r.metric === best);
		const ifaces = unique(tied.map((r) => r.iface));
		if (ifaces.length < 2) return [];
		return [
			{
				rule: "default-routes",
				severity: "warning",
				title: `${ifaces.length} default routes for IPv${f} with the same metric: ${ifaces.join(", ")}`,
				details: [
					...tied.map((r) => `${routeText(r)}, metric ${r.metric}`),
					`${tied[0]?.iface} wins now, being first; which one does can change when either reconnects, and connections open through the other then break`,
				],
				fix:
					snap.environment === "windows"
						? "give one a lower interface metric, in an administrator PowerShell: Set-NetIPInterface -InterfaceAlias NAME -InterfaceMetric 10"
						: `give one a lower metric: nmcli connection modify NAME ipv${f}.route-metric 50 with NetworkManager, or metric: under its route in netplan`,
			},
		];
	});
};

/** In WSL behind NAT, Windows' routing as a snapshot of its own: its VPN decides where WSL's
 * traffic goes. */
const windowsView = (snap: Snapshot): Snapshot | undefined =>
	snap.windowsRouting && {
		...snap,
		...snap.windowsRouting,
		environment: "windows",
		containers: [],
		dns: [],
	};

/** Both views a VPN rule looks at: this machine's, and in WSL Windows'. */
const vpnViews = (snap: Snapshot): [Snapshot, string][] => {
	const win = windowsView(snap);
	return [
		[snap, ""],
		...(win ? [[win, "Windows: "] as [Snapshot, string]] : []),
	];
};

const vpnAllTraffic: Rule = (snap) =>
	vpnViews(snap).flatMap(([view, where]) => {
		const through = FAMILIES.map((f) => routeTo(view, INTERNET[f])).filter(
			(r): r is RouteResult & { route: Route } =>
				!!r.route && VPN_KINDS.includes(kindOf(view, r.iface) ?? "loopback"),
		);
		if (!through.length) return [];
		const vpns = unique(through.map((r) => r.route.iface));
		// what stays off it: the local network, not docker's bridges
		const off = view.routes.filter((r) => {
			const k = kindOf(view, r.iface);
			return (
				r.prefix > 0 &&
				k !== undefined &&
				!INTERNAL.includes(k) &&
				!VPN_KINDS.includes(k) &&
				!isLinkLocalNet(r)
			);
		});
		return [
			{
				rule: "vpn-all-traffic",
				severity: "info",
				title: `${where}all internet traffic goes through the VPN on ${vpns.join(", ")}`,
				details: [
					...through.map((r) => `IPv${r.family}: ${routeText(r.route)}`),
					...(off.length ? [`stays off it: ${networks(off)}`] : []),
				],
				fix: "nothing to do when that is the point. When only some networks should use it (the company's), that is split tunnelling: a setting of the VPN, or of its administrator",
			},
		];
	});

/** A VPN that carries some networks only, the internet going around it: worth knowing which. */
const vpnSplit: Rule = (snap) =>
	vpnViews(snap).flatMap(([view, where]): Finding[] => {
		const internet = routeTo(view, INTERNET[4]);
		return upVpns(view).flatMap((vpn): Finding[] => {
			// all traffic through it is vpn-all-traffic's
			if (FAMILIES.some((f) => routeTo(view, INTERNET[f]).iface === vpn.name))
				return [];
			const own = new Set(vpn.addresses.map((a) => a.address));
			const carried = view.routes.filter(
				(r) =>
					r.iface === vpn.name &&
					r.prefix > 0 &&
					!isLinkLocalNet(r) &&
					!own.has(r.dest),
			);
			if (!carried.length) return [];
			const { shown, more } = widest(carried);
			// a link-local server is on whichever link it is, not beyond the VPN
			const dns = view.dns.filter(
				(d) => !isLinkLocal(d) && routeTo(view, d).iface === vpn.name,
			);
			return [
				{
					rule: "vpn-split",
					severity: "info",
					title: `${where}the VPN on ${vpnLabel(vpn)} carries ${carried.length} network${carried.length > 1 ? "s" : ""}, the rest goes around it`,
					details: [
						`through it: ${shown.map(net).join(", ")}${more ? ` and ${more} more` : ""}`,
						...(internet.route
							? [`the internet: ${routeText(internet.route)}`]
							: []),
						...(dns.length
							? [
									`DNS servers through it: ${dns.join(", ")}: lookups to them fail while it is down`,
								]
							: []),
						...(where
							? ["WSL's traffic leaves through Windows, and takes the same way"]
							: []),
					],
					fix: "nothing to do when that is the point. To know which way a host goes: nethound route HOST. One that should go through it and doesn't: its network is missing from the VPN's, a setting of its administrator",
				},
			];
		});
	});

const PRIVATE: [string, number][] = [
	["10.0.0.0", 8],
	["172.16.0.0", 12],
	["192.168.0.0", 16],
	["100.64.0.0", 10],
	["fc00::", 7],
];
const isPrivate = (ip: string) => PRIVATE.some(([n, p]) => inNetwork(ip, n, p));

const dnsServers: Rule = (snap) => {
	const all = snap.dns.map((server) => ({
		server,
		route: routeTo(snap, server),
	}));
	// a resolver on this machine (systemd-resolved, WSL's, dnsmasq) asks others in turn
	const remote = all.filter(
		(d) => d.route.kind !== "loopback" && d.route.kind !== "local",
	);
	const out: Finding[] = [];
	// with no way out at all, no-default-route says it
	const lost = offline(snap)
		? []
		: remote.filter((d) => d.route.kind === "unreachable");
	const named = (ds: typeof all) => ds.map((d) => d.server).join(", ");
	const remove =
		"remove the server (resolv.conf, or the interface's DNS settings)";
	if (lost.length) {
		const others = remote.filter((d) => !lost.includes(d));
		// an IPv6 server on a network that has no IPv6
		const v6 =
			lost.every((d) => d.route.family === 6) &&
			routeTo(snap, INTERNET[6]).kind === "unreachable";
		out.push({
			rule: "dns-unreachable",
			severity: others.length ? "warning" : "error",
			title:
				lost.length === 1
					? `DNS server ${named(lost)} has no route`
					: `${lost.length} DNS servers have no route: ${named(lost)}`,
			details: [
				others.length
					? `a lookup that tries it waits for it to time out, then goes on to ${named(others)}`
					: "every name lookup fails",
			],
			fix: v6
				? `this network has no IPv6: ${remove}`
				: `it probably belongs to a VPN or a network this machine has left: reconnect to it, or ${remove}`,
		});
	}
	const astray = remote.filter(
		(d) =>
			d.route.kind === "gateway" &&
			d.route.route?.prefix === 0 &&
			isPrivate(d.server),
	);
	const [first] = astray;
	if (first?.route.route)
		out.push({
			rule: "dns-private",
			severity: "info",
			title:
				astray.length === 1
					? `DNS server ${named(astray)} is a private address on none of this machine's networks`
					: `DNS servers ${named(astray)} are private addresses on none of this machine's networks`,
			details: [
				`queries leave by the default route, via ${first.route.gateway} on ${first.route.iface}`,
				"fine when the network beyond knows the address (a company's DNS); when it was a VPN's and the VPN has disconnected, lookups wait for it and fail",
			],
			fix: `nothing to do when the network knows it; when it was a VPN's, reconnect the VPN, or ${remove}`,
		});
	return out;
};

export const RULES: Rule[] = [
	exposed,
	portShared,
	ipv6Only,
	wslShadowed,
	publishedNowhere,
	noDefaultRoute,
	defaultRoutes,
	vpnAllTraffic,
	vpnSplit,
	dnsServers,
];

const RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

/** Every finding, the most serious first, then by port: the routing ones, with none, first. */
export function doctor(snap: Snapshot): Finding[] {
	const ls = listeners(snap);
	return RULES.flatMap((r) => r(snap, ls)).sort(
		(a, b) =>
			RANK[a.severity] - RANK[b.severity] || (a.port ?? 0) - (b.port ?? 0),
	);
}
