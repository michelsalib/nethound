// From a Snapshot to answers: who listens where and who can reach it, who talks to whom, which
// way traffic to an address goes, and the whole picture interface by interface.

import type {
	Container,
	Endpoint,
	Family,
	Iface,
	Namespace,
	Neighbour,
	Process,
	Proto,
	PublishedPort,
	Route,
	Snapshot,
	Socket,
} from "./model.ts";
import {
	familyOf,
	inNetwork,
	ipBytes,
	isLinkLocal,
	isLoopback,
	isWildcard,
	networkOf,
} from "./net.ts";

/** Who can reach a listener: this machine only, every interface, or the interfaces holding its address. */
export interface Reach {
	scope: "local" | "everywhere" | "interfaces";
	interfaces: string[];
	/** Bound to :: only, taking IPv6 alone: Windows' default, an option elsewhere. */
	ipv6Only?: boolean;
}

export interface Listener {
	proto: Proto;
	port: number;
	/** The addresses it is bound to, e.g. 0.0.0.0 and :: for one server on both families. */
	addresses: string[];
	reach: Reach;
	process?: Process;
	/** The owner's user name (or uid), known even when the process is not; unknown on Windows, and
	 * on macOS for other users' sockets without root. */
	user?: string;
	/** The container publishing this port, through docker-proxy or the firewall. */
	container?: Container;
	published?: PublishedPort;
	sockets: Socket[];
	/** Connections to it, open now: not those closing (TIME_WAIT…), which `conns --all` shows. */
	clients: Connection[];
}

export type Peer =
	/** The other end is on this machine: its process, and the listener when we are its client. */
	| { kind: "local"; process?: Process; user?: string; listener?: Listener }
	| { kind: "container"; container: Container; network: string }
	| { kind: "remote"; route: RouteResult };

export interface Connection {
	proto: Proto;
	local: Endpoint;
	remote: Endpoint;
	state: Socket["state"];
	process?: Process;
	/** None for a socket no process holds any more (TIME_WAIT): the kernel finishes closing it. */
	user?: string;
	/** "in" when a client connected to one of our listeners, "out" when we started it. */
	direction: "in" | "out";
	peer: Peer;
	/** Docker's side of a published port: docker-proxy accepting a client on it, or its own
	 * connection to the container for that client, not a connection of its own. */
	relay?: { container: Container; published: PublishedPort };
}

export interface RouteResult {
	dest: string;
	family: Family;
	kind:
		| "loopback"
		| "local"
		| "container"
		| "network"
		| "gateway"
		| "unreachable";
	iface?: string;
	gateway?: string;
	route?: Route;
	/** The address packets leave with. */
	source?: string;
	container?: Container;
	/** It leaves through a VPN: the interface, with its adapter's description when known. */
	vpn?: string;
	/** VPNs that are up but that it does not go through: split tunnelling leaves it outside. */
	outside?: string[];
	/** In WSL behind NAT: where Windows sends it next, from Windows' own routing table. */
	windows?: RouteResult;
}

export const VPN_KINDS: Iface["kind"][] = ["tun", "wireguard"];

/** The VPNs that are up, with an address: not macOS' own utun0-3, which have fe80:: only. */
export const upVpns = (snap: Pick<Snapshot, "interfaces">) =>
	snap.interfaces.filter(
		(i) =>
			VPN_KINDS.includes(i.kind) &&
			i.state !== "down" &&
			i.addresses.some((a) => !isLinkLocal(a.address)),
	);

/** A long route list cut short: the default and the widest networks first, and how many more.
 * A split-tunnel VPN pushes hundreds. */
export function widest(rs: Route[], max = 6): { shown: Route[]; more: number } {
	if (rs.length <= max) return { shown: rs, more: 0 };
	const shown = [...rs].sort((a, b) => a.prefix - b.prefix).slice(0, max);
	return { shown, more: rs.length - max };
}

export const vpnLabel = (i: Iface) =>
	i.description ? `${i.name} (${i.description})` : i.name;

export const userName = (snap: Snapshot, uid: number | undefined) =>
	uid === undefined ? undefined : (snap.users[uid] ?? String(uid));

/** The loopback interface's name: lo, lo0 on macOS, "Loopback Pseudo-Interface 1" on Windows. */
const loopback = (snap: Snapshot) =>
	snap.interfaces.find((i) => i.kind === "loopback")?.name ?? "lo";

const processOf = (snap: Snapshot, pid: number | undefined) =>
	pid === undefined ? undefined : snap.processes.find((p) => p.pid === pid);

const ownAddress = (snap: Snapshot, ip: string) =>
	snap.interfaces.find((i) => i.addresses.some((a) => a.address === ip));

export function containerAt(snap: Snapshot, ip: string) {
	for (const c of snap.containers)
		for (const n of c.networks)
			if (n.ip === ip) return { container: c, network: n };
	return undefined;
}

/** Where traffic to `ip` goes: the same choice the kernel makes with the main routing table. */
export function routeTo(snap: Snapshot, ip: string): RouteResult {
	const family = familyOf(ip) ?? 4;
	const base = { dest: ip, family };
	if (isLoopback(ip))
		return { ...base, kind: "loopback", iface: loopback(snap), source: ip };
	const own = ownAddress(snap, ip);
	if (own) return { ...base, kind: "local", iface: own.name, source: ip };
	const best = snap.routes
		.filter((r) => r.family === family && inNetwork(ip, r.dest, r.prefix))
		.sort((a, b) => b.prefix - a.prefix || a.metric - b.metric)[0];
	if (!best) return { ...base, kind: "unreachable" };
	const iface = snap.interfaces.find((i) => i.name === best.iface);
	const near = best.gateway ?? ip;
	const addrs = iface?.addresses.filter((a) => a.family === family) ?? [];
	const source =
		addrs.find((a) => inNetwork(near, networkOf(a), a.prefix))?.address ??
		addrs.find((a) => !isLinkLocal(a.address))?.address ??
		addrs[0]?.address;
	const c = containerAt(snap, ip);
	const outside = upVpns(snap)
		.filter((i) => i.name !== best.iface)
		.map(vpnLabel);
	return {
		...base,
		kind: c ? "container" : best.gateway ? "gateway" : "network",
		iface: best.iface,
		gateway: best.gateway,
		route: best,
		source,
		container: c?.container,
		...(iface && VPN_KINDS.includes(iface.kind) && { vpn: vpnLabel(iface) }),
		...(outside.length && { outside }),
	};
}

/** In WSL behind NAT, Windows' routing as a snapshot of its own: its VPN decides where WSL's
 * traffic goes. Its name servers are every interface's. */
export const windowsView = (snap: Snapshot): Snapshot | undefined =>
	snap.windowsRouting && {
		...snap,
		environment: "windows",
		interfaces: snap.windowsRouting.interfaces,
		routes: snap.windowsRouting.routes,
		dns: [...new Set(Object.values(snap.windowsRouting.dns ?? {}).flat())],
		containers: [],
	};

/** In WSL behind NAT, a route through Windows' address on the virtual switch: where Windows then
 * sends it, through its VPN or not. Undefined when the gateway is not Windows (mirrored
 * networking, where WSL sees Windows' interfaces itself). */
export function throughWindows(
	snap: Snapshot,
	r: RouteResult,
): RouteResult | undefined {
	const win = windowsView(snap);
	if (!win || r.kind !== "gateway" || r.family !== 4) return undefined;
	const at = r.gateway;
	if (!win.interfaces.some((i) => i.addresses.some((a) => a.address === at)))
		return undefined;
	return routeTo(win, r.dest);
}

function reachOf(
	snap: Snapshot,
	addresses: string[],
	sockets: Socket[] = [],
): Reach {
	// an address on the loopback interface (WSL's 10.255.255.254) is as local as 127.0.0.1
	const local = (a: string) =>
		isLoopback(a) || ownAddress(snap, a)?.kind === "loopback";
	if (addresses.every(local))
		return { scope: "local", interfaces: [loopback(snap)] };
	const up = snap.interfaces.filter(
		(i) => i.state !== "down" && i.addresses.length,
	);
	if (addresses.some(isWildcard)) {
		// a socket on :: also takes IPv4, unless it is IPv6 only (Windows' default)
		const fams = new Set<Family>(addresses.includes("0.0.0.0") ? [4] : []);
		if (addresses.includes("::")) {
			fams.add(6);
			const v6 = sockets.filter((s) => s.local.address === "::");
			if (!v6.length || v6.some((s) => !s.v6only)) fams.add(4);
		}
		return {
			scope: "everywhere",
			...(!fams.has(4) && { ipv6Only: true }),
			interfaces: up
				// a bridge's ports carry its traffic, they are not ways in of their own
				.filter((i) => !i.master)
				.filter((i) => i.addresses.some((a) => fams.has(a.family)))
				.map((i) => i.name),
		};
	}
	const names = new Set<string>();
	for (const a of addresses) {
		if (isLoopback(a)) names.add(loopback(snap));
		const i = ownAddress(snap, a);
		if (i) names.add(i.name);
	}
	return { scope: "interfaces", interfaces: [...names] };
}

/** The programs that hold a published port for docker: docker-proxy, Docker Desktop's, podman's. */
export const DOCKER =
	/docker|vpnkit|wslrelay|rootless|slirp4netns|gvproxy|containerd/i;

const publishes = (
	p: PublishedPort,
	proto: Proto,
	port: number,
	address?: string,
	strict = false,
) =>
	p.proto === proto &&
	p.hostPort === port &&
	(address === undefined ||
		p.hostIp === address ||
		(strict
			? isWildcard(p.hostIp) && isWildcard(address)
			: isWildcard(p.hostIp) || isWildcard(address)));

function publisherOf(
	snap: Snapshot,
	proto: Proto,
	port: number,
	address?: string,
	strict = false,
) {
	for (const c of snap.containers)
		for (const p of c.ports)
			if (publishes(p, proto, port, address, strict))
				return { container: c, published: p };
	return undefined;
}

const isListening = (s: Socket) =>
	s.state === "LISTEN" || (s.state === "UNCONN" && s.local.port !== 0);

/** Every listening socket, grouped by port and owner; ports docker publishes without a socket too. */
export function listeners(snap: Snapshot): Listener[] {
	const groups = new Map<string, Listener>();
	for (const s of snap.sockets.filter(isListening)) {
		const proc = processOf(snap, s.pid);
		// docker-proxy's sockets belong to its container (with sudo, docker-proxy itself is the
		// process), and so do Docker Desktop's; another program's never do, nor, when its program is
		// hidden, a socket on another address than the published one: a local server on 127.0.0.1
		// beside a container published on 0.0.0.0
		const pub = proc
			? DOCKER.test(proc.name)
				? publisherOf(snap, s.proto, s.local.port, s.local.address)
				: undefined
			: publisherOf(snap, s.proto, s.local.port, s.local.address, true);
		const owner = pub
			? `c${pub.container.id}`
			: s.pid !== undefined
				? `p${s.pid}`
				: `u${s.uid ?? "?"}`;
		const key = `${s.proto}/${s.local.port}/${owner}`;
		let l = groups.get(key);
		if (!l) {
			l = {
				proto: s.proto,
				port: s.local.port,
				addresses: [],
				reach: { scope: "local", interfaces: [] },
				process: processOf(snap, s.pid),
				user: userName(snap, s.uid),
				container: pub?.container,
				published: pub?.published,
				sockets: [],
				clients: [],
			};
			groups.set(key, l);
		}
		l.sockets.push(s);
		if (!l.addresses.includes(s.local.address))
			l.addresses.push(s.local.address);
	}
	// with the firewall doing the forwarding (no docker-proxy), a published port has no socket
	for (const c of snap.containers)
		for (const p of c.ports) {
			const taken = [...groups.values()].some(
				(l) =>
					l.proto === p.proto &&
					l.port === p.hostPort &&
					l.container?.id === c.id,
			);
			if (taken) continue;
			const key = `${p.proto}/${p.hostPort}/c${c.id}`;
			const l = groups.get(key);
			if (l) {
				if (!l.addresses.includes(p.hostIp)) l.addresses.push(p.hostIp);
				continue;
			}
			groups.set(key, {
				proto: p.proto,
				port: p.hostPort,
				addresses: [p.hostIp],
				reach: { scope: "local", interfaces: [] },
				user: "root",
				container: c,
				published: p,
				sockets: [],
				clients: [],
			});
		}
	const all = [...groups.values()];
	for (const l of all) l.reach = reachOf(snap, l.addresses, l.sockets);
	for (const c of connections(snap, all))
		if (c.direction === "in" && c.state === "ESTABLISHED")
			listenerFor(all, c.proto, c.local)?.clients.push(c);
	return all.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
}

function listenerFor(all: Listener[], proto: Proto, e: Endpoint) {
	return all.find(
		(l) =>
			l.proto === proto &&
			l.port === e.port &&
			l.addresses.some((a) => a === e.address || isWildcard(a)),
	);
}

/** Every connected socket (TCP other than LISTEN, connected UDP), with what is at the other end. */
export function connections(snap: Snapshot, known?: Listener[]): Connection[] {
	const all = known ?? listeners(snap);
	const out: Connection[] = [];
	for (const s of snap.sockets) {
		if (isListening(s) || s.remote.port === 0) continue;
		const listener = listenerFor(all, s.proto, s.local);
		const direction = listener ? "in" : "out";
		const process = processOf(snap, s.pid);
		const peer = peerOf(snap, all, s);
		// docker-proxy (its process hidden without root): accepting on the port a container
		// publishes, or forwarding to the container behind it
		const docker = !process || DOCKER.test(process.name);
		const into =
			direction === "in" && docker && listener?.container && listener.published
				? { container: listener.container, published: listener.published }
				: undefined;
		const published =
			direction === "out" && peer.kind === "container" && docker
				? peer.container.ports.find(
						(p) => p.proto === s.proto && p.containerPort === s.remote.port,
					)
				: undefined;
		out.push({
			proto: s.proto,
			local: s.local,
			remote: s.remote,
			state: s.state,
			process,
			user: s.orphan ? undefined : userName(snap, s.uid),
			direction,
			peer,
			...(into && { relay: into }),
			...(published &&
				peer.kind === "container" && {
					relay: { container: peer.container, published },
				}),
		});
	}
	return out;
}

function peerOf(snap: Snapshot, all: Listener[], s: Socket): Peer {
	const r = s.remote.address;
	if (isLoopback(r) || ownAddress(snap, r)) {
		// the other end's own socket: its local is our remote
		const other = snap.sockets.find(
			(o) =>
				o !== s &&
				o.proto === s.proto &&
				o.local.port === s.remote.port &&
				o.remote.port === s.local.port &&
				o.local.address === r &&
				o.remote.address === s.local.address,
		);
		const listener = listenerFor(all, s.proto, s.remote);
		return {
			kind: "local",
			process: processOf(snap, other?.pid),
			user: other ? userName(snap, other.uid) : undefined,
			// only when we are its client, not when it is ours
			listener:
				listener && listenerFor(all, s.proto, s.local) !== listener
					? listener
					: undefined,
		};
	}
	const c = containerAt(snap, r);
	if (c)
		return {
			kind: "container",
			container: c.container,
			network: c.network.name,
		};
	const route = routeTo(snap, r);
	const next = throughWindows(snap, route);
	return { kind: "remote", route: next ? { ...route, windows: next } : route };
}

export interface WhoReport {
	port: number;
	listeners: Listener[];
	/** Inside containers and other namespaces: on that port, or published on it. */
	inside: InsideListener[];
	/** Connections from this machine to that port elsewhere. */
	outbound: Connection[];
	/** docker-proxy's connections to the container behind that port: one per client. */
	relayed: Connection[];
}

export function who(snap: Snapshot, port: number): WhoReport {
	const conns = connections(snap);
	return {
		port,
		listeners: listeners(snap).filter((l) => l.port === port),
		inside: insideListeners(snap).filter(
			(l) => l.port === port || l.published.some((p) => p.hostPort === port),
		),
		relayed: conns.filter(
			(c) =>
				c.direction === "out" &&
				c.relay?.published.hostPort === port &&
				c.state === "ESTABLISHED",
		),
		outbound: conns.filter(
			(c) =>
				c.direction === "out" &&
				c.remote.port === port &&
				// docker-proxy relaying a client of a published port: listed with that port's clients
				!c.relay &&
				// clients of our own listener are listed with it
				!(c.peer.kind === "local" && c.peer.listener?.port === port),
		),
	};
}

export interface IfaceView {
	iface: Iface;
	routes: Route[];
	/** Listeners bound to one of its addresses (those bound everywhere are listed once, apart). */
	listeners: Listener[];
	/** Connections that leave through it, to other machines. */
	outbound: Connection[];
	/** For the loopback: connections between processes of this machine, client side. */
	local: Connection[];
	containers: { container: Container; ip?: string }[];
	/** The machines on its network it has exchanged packets with lately, from the neighbour table:
	 * its containers left out (listed above), sorted by address. */
	neighbours: Neighbour[];
}

export interface MapReport {
	hostname: string;
	environment: Snapshot["environment"];
	everywhere: Listener[];
	interfaces: IfaceView[];
	/** Interfaces down with no address but link-local ones, named only. */
	idle: Iface[];
	dns: { server: string; route: RouteResult }[];
	/** What listens inside containers and other namespaces. */
	inside: InsideListener[];
	hidden: number;
	/** In WSL behind NAT: Windows' interfaces and the machines on their networks, which WSL can't
	 * see from behind the NAT. */
	windowsNeighbours?: {
		iface: Iface;
		routes: Route[];
		neighbours: Neighbour[];
	}[];
	/** In WSL behind NAT: the VPNs Windows runs, which WSL's traffic goes through too. */
	windowsVpns?: {
		vpn: string;
		/** The networks it carries; all of them when it takes the default route. */
		networks: number;
		all: boolean;
		/** The interface the internet goes by. */
		internet?: string;
	}[];
}

const byAddress = (a: string, b: string) => {
	const x = ipBytes(a) ?? [];
	const y = ipBytes(b) ?? [];
	for (let i = 0; i < Math.max(x.length, y.length); i++)
		if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
	return 0;
};

export function map(snap: Snapshot): MapReport {
	const ls = listeners(snap);
	// the map is what is connected now: not sockets opening or closing
	const conns = connections(snap, ls).filter((c) => c.state === "ESTABLISHED");
	const views: IfaceView[] = [];
	const idle: Iface[] = [];
	for (const iface of snap.interfaces) {
		// bridge ports are listed with their bridge
		if (iface.master) continue;
		const containers = snap.containers.flatMap((c) =>
			c.networks
				.filter((n) => n.bridge === iface.name)
				.map((n) => ({ container: c, ip: n.ip })),
		);
		const view: IfaceView = {
			iface,
			routes: snap.routes.filter((r) => r.iface === iface.name),
			listeners: ls.filter(
				(l) =>
					l.reach.scope !== "everywhere" &&
					l.reach.interfaces.includes(iface.name),
			),
			outbound: conns.filter(
				(c) =>
					c.direction === "out" &&
					c.peer.kind === "remote" &&
					c.peer.route.iface === iface.name,
			),
			local:
				iface.kind === "loopback"
					? conns.filter(
							(c) => c.peer.kind === "local" && c.direction === "out",
						)
					: [],
			containers,
			neighbours: (snap.neighbours ?? [])
				.filter(
					(n) =>
						n.iface === iface.name &&
						!containers.some((x) => x.ip === n.address),
				)
				.sort((a, b) => byAddress(a.address, b.address)),
		};
		// a link-local address is one any interface gives itself (Windows' Wi-Fi Direct adapters):
		// down with only those, it is as idle as one with none
		const empty =
			iface.addresses.every((a) => isLinkLocal(a.address)) &&
			!view.listeners.length &&
			!view.outbound.length &&
			!containers.length;
		if (iface.state === "down" && empty) idle.push(iface);
		else views.push(view);
	}
	return {
		hostname: snap.hostname,
		environment: snap.environment,
		everywhere: ls.filter((l) => l.reach.scope === "everywhere"),
		interfaces: views,
		idle,
		dns: snap.dns.map((server) => ({ server, route: routeTo(snap, server) })),
		inside: insideListeners(snap),
		hidden: snap.hidden,
		...(snap.windowsRouting && { windowsVpns: windowsVpns(snap) }),
		...(snap.windowsRouting?.neighbours && {
			windowsNeighbours: windowsNeighbours(snap),
		}),
	};
}

function windowsNeighbours(
	snap: Snapshot,
): NonNullable<MapReport["windowsNeighbours"]> {
	const win = snap.windowsRouting;
	// WSL's own addresses: WSL itself on the virtual switch, and with mirrored networking Windows'
	// interfaces, whose neighbours WSL lists already
	const own = new Set(
		snap.interfaces.flatMap((i) => i.addresses.map((a) => a.address)),
	);
	return (win?.interfaces ?? []).flatMap((iface) => {
		if (iface.addresses.some((a) => own.has(a.address))) return [];
		const neighbours = (win?.neighbours ?? [])
			.filter((n) => n.iface === iface.name && !own.has(n.address))
			.sort((a, b) => byAddress(a.address, b.address));
		return neighbours.length
			? [
					{
						iface,
						routes: (win?.routes ?? []).filter((r) => r.iface === iface.name),
						neighbours,
					},
				]
			: [];
	});
}

function windowsVpns(snap: Snapshot): NonNullable<MapReport["windowsVpns"]> {
	const win = windowsView(snap);
	if (!win) return [];
	const internet = routeTo(win, "1.1.1.1").iface;
	return upVpns(win).map((i) => ({
		vpn: vpnLabel(i),
		networks: win.routes.filter((r) => r.iface === i.name && r.prefix > 0)
			.length,
		all: internet === i.name,
		...(internet && { internet }),
	}));
}

/** A port that listens inside another network namespace: a container's own, which the host's
 * sockets don't show. */
export interface InsideListener {
	proto: Proto;
	port: number;
	addresses: string[];
	namespace: Namespace;
	container?: Container;
	/** Its process, when nethound may see who holds the socket (root). */
	process?: Process;
	/** The host ports docker publishes it on. */
	published: PublishedPort[];
	sockets: Socket[];
}

/** Every port listening in another namespace, by namespace, port and process. */
export function insideListeners(snap: Snapshot): InsideListener[] {
	const out: InsideListener[] = [];
	for (const ns of snap.namespaces ?? []) {
		const container = snap.containers.find((c) => c.id === ns.container);
		const groups = new Map<string, InsideListener>();
		for (const s of ns.sockets ?? []) {
			const key = `${s.proto}/${s.local.port}/${s.pid ?? "?"}`;
			let l = groups.get(key);
			if (!l) {
				l = {
					proto: s.proto,
					port: s.local.port,
					addresses: [],
					namespace: ns,
					container,
					process: processOf(snap, s.pid),
					published: (container?.ports ?? []).filter(
						(p) => p.proto === s.proto && p.containerPort === s.local.port,
					),
					sockets: [],
				};
				groups.set(key, l);
				out.push(l);
			}
			l.sockets.push(s);
			if (!l.addresses.includes(s.local.address))
				l.addresses.push(s.local.address);
		}
	}
	return out.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto));
}

/** What listens in a container on a port it publishes: nothing, its own loopback only (which
 * docker's forwarding never reaches), a server, or unknown when its sockets weren't read. */
export function publishedTarget(
	snap: Snapshot,
	c: Container,
	p: PublishedPort,
): {
	state: "unknown" | "nothing" | "loopback" | "ok";
	inside: InsideListener[];
} {
	const ns = snap.namespaces?.find((n) => n.container === c.id);
	if (!ns?.sockets) return { state: "unknown", inside: [] };
	const inside = insideListeners(snap).filter(
		(l) =>
			l.container?.id === c.id &&
			l.proto === p.proto &&
			l.port === p.containerPort,
	);
	if (!inside.length) return { state: "nothing", inside };
	return {
		state: inside.every((l) => l.addresses.every(isLoopback))
			? "loopback"
			: "ok",
		inside,
	};
}

/** A namespace by what it is: "container redis", "netns blue", "the namespace of python3 1234". */
export function namespaceLabel(snap: Snapshot, ns: Namespace): string {
	const c = snap.containers.find((x) => x.id === ns.container);
	if (c) return `container ${c.name}`;
	if (ns.name) return `netns ${ns.name}`;
	const p = processOf(snap, ns.pids[0]);
	return p ? `the namespace of ${p.name} ${p.pid}` : `namespace ${ns.inode}`;
}

/** Sockets nethound could not tie to a process: other users', without root. */
export const unowned = (snap: Snapshot) =>
	snap.sockets.filter(
		(s) => s.pid === undefined && !s.orphan && s.uid !== snap.uid,
	).length;
