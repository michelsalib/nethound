import {
	type Connection,
	type IfaceView,
	type InsideListener,
	type Listener,
	type MapReport,
	namespaceLabel,
	type Peer,
	publishedTarget,
	type RouteResult,
	type WhoReport,
} from "./analyze.ts";
import type { Finding } from "./doctor.ts";
import { outside, verdictFor } from "./firewall.ts";
import type { Container, Iface, Process, Route, Snapshot } from "./model.ts";
import { endpoint, isLoopback, isWildcard } from "./net.ts";
import { startedBy } from "./stop.ts";

export interface RenderOptions {
	color: boolean;
	/** Terminal width; undefined means never truncate (output is piped). */
	width?: number;
	/** In WSL, Windows forwards its localhost to ports bound to 127.0.0.1 or every interface. */
	wsl?: boolean;
	/** A Windows snapshot: other users' processes need an administrator terminal, not sudo. */
	windows?: boolean;
}

export function paint(o: RenderOptions) {
	const wrap = (code: string) => (s: string) =>
		o.color && s ? `\x1b[${code}m${s}\x1b[0m` : s;
	return {
		bold: wrap("1"),
		dim: wrap("2"),
		red: wrap("31"),
		green: wrap("32"),
		yellow: wrap("33"),
		blue: wrap("34"),
		magenta: wrap("35"),
		cyan: wrap("36"),
		inverse: wrap("7"),
		underline: wrap("4"),
	};
}

function fit(s: string, width: number | undefined): string {
	return width !== undefined && width > 0 && s.length > width
		? `${s.slice(0, Math.max(0, width - 1))}…`
		: s;
}

/** Columns padded to their widest cell; the last one cut to the terminal. */
function table(
	rows: string[][],
	styles: ((s: string) => string)[],
	width: number | undefined,
): string {
	const widths =
		rows[0]?.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? "").length))) ??
		[];
	return rows
		.map((cells) => {
			let used = 0;
			return cells
				.map((cell, i) => {
					const last = i === cells.length - 1;
					const text = last
						? fit(
								cell,
								width === undefined ? undefined : Math.max(10, width - used),
							)
						: cell.padEnd(widths[i] ?? 0);
					used += (widths[i] ?? 0) + 2;
					return (styles[i] ?? ((s: string) => s))(text);
				})
				.join("  ")
				.trimEnd();
		})
		.join("\n");
}

export const procLabel = (p: Process) => `${p.name} ${p.pid}`;

/** A path under the home directory as ~/…. */
export const tilde = (path: string, home?: string) =>
	home &&
	(path === home || path.startsWith(`${home}/`) || path.startsWith(`${home}\\`))
		? `~${path.slice(home.length)}`
		: path;

/** Where a process runs, in two parts: what (its checkout and branch, else its project, else its
 * directory, else on Windows its arguments) and tags (the worktree removed, the app that launched it),
 * so a narrow column cuts the name and keeps the tags. */
export function placeParts(
	p: Process,
	home?: string,
): { name: string; tags: string } {
	const checkout = p.git ?? p.project;
	// a worktree named after its branch: once is enough
	const dir = checkout?.root.split(/[\\/]/).pop() ?? "";
	const tags = [
		p.project?.removed ? "(removed)" : "",
		p.app ? `· ${p.app}` : "",
	]
		.filter(Boolean)
		.join(" ");
	const name = checkout
		? `${dir}${p.project?.removed || checkout.branch === dir ? "" : checkout.branch ? ` (${checkout.branch})` : " (detached)"}`
		: // an app's own process: its name says more than its directory
			p.app
			? ""
			: p.cwd
				? tilde(p.cwd, home)
				: p.cmd.split(/\s+/).slice(1).join(" ");
	return { name, tags: name ? tags : (p.app ?? "") };
}

export function place(p: Process, home?: string): string {
	const { name, tags } = placeParts(p, home);
	return [name, tags].filter(Boolean).join(" ");
}

/** How to see other users' processes: sudo, or on Windows an administrator terminal. */
export const elevate = (o?: RenderOptions) =>
	o?.windows ? "run as administrator" : "run with sudo";

/** Our side of a connection: its process, else its user, else nobody (closing). */
const connOwner = (x: Connection) =>
	x.process
		? procLabel(x.process)
		: // hidden without root, but what else relays a published port to its container
			x.relay
			? `docker-proxy (${x.user ?? "root"})`
			: x.user
				? `${x.user}'s process`
				: "closing, no process";

/** Who is behind a listener: its container, its process, or at least its user. */
/** Who holds a socket inside a container: its process as root, else whoever it may be. */
const insideOwner = (x?: InsideListener) =>
	x?.process ? procLabel(x.process) : "a process (sudo to see which)";

export function ownerLabel(l: Listener, o?: RenderOptions): string {
	if (l.container)
		return `container ${l.container.name}${l.published ? ` :${l.published.containerPort}` : ""}`;
	if (l.process) return procLabel(l.process);
	// Windows names every socket's process; one gone since keeps its pid
	const pid = l.sockets.find((s) => s.pid !== undefined)?.pid;
	if (pid !== undefined) return `pid ${pid}`;
	return `${l.user ?? "another user"}'s process (${o?.windows ? "run as administrator" : "sudo"} to see it)`;
}

export function reachLabel(l: Listener, o: RenderOptions): string {
	const windows =
		o.wsl && l.addresses.some((a) => isWildcard(a) || a.startsWith("127."));
	const base =
		l.reach.scope === "local"
			? "this machine only"
			: l.reach.scope === "everywhere"
				? l.reach.ipv6Only
					? "every interface, IPv6 only"
					: "every interface"
				: l.reach.interfaces.join(", ") || "no interface";
	return windows ? `${base} + Windows` : base;
}

const addressLabel = (l: Listener) => {
	const a = l.addresses;
	if (a.length === 2 && a.includes("0.0.0.0") && a.includes("::")) return "*";
	// a service bound to each address on its own (Windows' SSDP has six): the first two
	return a.length > 2
		? `${a.slice(0, 2).join(", ")} +${a.length - 2}`
		: a.join(", ");
};

export function peerLabel(p: Peer, remote: string, o?: RenderOptions): string {
	switch (p.kind) {
		case "local": {
			const who = p.listener
				? ownerLabel(p.listener, o)
				: p.process
					? procLabel(p.process)
					: (p.user && `${p.user}'s process`) || "this machine";
			return `${remote} ${who}`;
		}
		case "container":
			return `${remote} container ${p.container.name}`;
		case "remote":
			return remote;
	}
}

const routeVia = (r: RouteResult) =>
	r.kind === "unreachable"
		? "no route"
		: r.gateway
			? `via ${r.iface} → ${r.gateway}`
			: `via ${r.iface}`;

export function renderList(ls: Listener[], o: RenderOptions): string {
	const c = paint(o);
	if (!ls.length) return c.dim("nothing is listening");
	const rows = [
		["PORT", "ADDRESS", "REACHABLE FROM", "CLIENTS", "OWNER"],
		...ls.map((l) => [
			`${l.proto} ${l.port}`,
			addressLabel(l),
			reachLabel(l, o),
			l.clients.length ? String(l.clients.length) : "",
			ownerLabel(l, o),
		]),
	];
	const reach = (s: string) =>
		s.startsWith("this machine")
			? c.green(s)
			: s.startsWith("every")
				? c.yellow(s)
				: s;
	const styles = [c.bold, (s: string) => s, reach, c.cyan, (s: string) => s];
	const [head = ""] = table(
		rows,
		styles.map(() => (s: string) => s),
		o.width,
	).split("\n");
	const styled = table(rows, styles, o.width).split("\n").slice(1);
	return [c.dim(head), ...styled].join("\n");
}

const bytes = (n: number) => {
	const units = ["B", "kB", "MB", "GB", "TB"];
	let i = 0;
	let v = n;
	while (v >= 1000 && i < units.length - 1) {
		v /= 1000;
		i++;
	}
	return `${i ? v.toFixed(1) : v} ${units[i]}`;
};

const cidr = (i: Iface) => i.addresses.map((a) => `${a.address}/${a.prefix}`);

function ifaceHeader(i: Iface, o: RenderOptions, note = ""): string {
	const c = paint(o);
	const state =
		i.state === "up"
			? c.green("up")
			: i.state === "down"
				? c.red("down")
				: c.dim(i.state);
	return [c.bold(i.name), i.kind, state, cidr(i).join(" "), note && c.dim(note)]
		.filter(Boolean)
		.join("  ");
}

/** A bridge docker uses: "docker network NAME". */
const dockerNetwork = (v: IfaceView) => {
	const names = [
		...new Set(
			v.containers.flatMap((x) =>
				x.container.networks
					.filter((n) => n.bridge === v.iface.name)
					.map((n) => n.name),
			),
		),
	];
	return names.length ? `docker network ${names.join(", ")}` : "";
};

/** Routes worth showing: every interface with IPv6 has fe80::/64, which says nothing. */
const shownRoutes = (rs: Route[]) =>
	rs.filter((r) => !(r.family === 6 && r.dest === "fe80::"));

const routeLabel = (r: Route) =>
	(r.prefix === 0 ? "default" : `${r.dest}/${r.prefix}`) +
	(r.gateway ? ` via ${r.gateway}` : "");

export function renderInterfaces(
	views: IfaceView[],
	idle: string[],
	o: RenderOptions,
): string {
	const c = paint(o);
	const out: string[] = [];
	for (const v of views) {
		const i = v.iface;
		out.push(ifaceHeader(i, o, dockerNetwork(v)));
		const lines: [string, string][] = [];
		if (shownRoutes(v.routes).length)
			lines.push(["routes", shownRoutes(v.routes).map(routeLabel).join(", ")]);
		if (i.members.length) {
			const veth = i.members.filter((m) => m.startsWith("veth")).length;
			lines.push([
				"ports",
				veth === i.members.length ? `${veth} veth` : i.members.join(", "),
			]);
		}
		if (v.containers.length)
			lines.push([
				"containers",
				v.containers
					.map((x) => `${x.container.name}${x.ip ? ` ${x.ip}` : ""}`)
					.join(", "),
			]);
		const ls = v.listeners.length;
		if (ls)
			lines.push(["listening", `${ls} port${ls > 1 ? "s" : ""} bound here`]);
		if (v.outbound.length)
			lines.push([
				"out",
				`${v.outbound.length} connection${v.outbound.length > 1 ? "s" : ""}`,
			]);
		const meta = [
			i.mac,
			i.mtu ? `mtu ${i.mtu}` : "",
			`↓ ${bytes(i.rxBytes)}  ↑ ${bytes(i.txBytes)}`,
		].filter(Boolean);
		lines.push(["", meta.join("  ")]);
		for (const [k, val] of lines)
			out.push(`  ${c.dim(k.padEnd(10))} ${fit(val, o.width && o.width - 13)}`);
		out.push("");
	}
	if (idle.length) out.push(c.dim(`down, no address: ${idle.join(", ")}`));
	return out.join("\n").trimEnd();
}

/** Connections grouped by the process on our side. */
export function renderConnections(
	conns: Connection[],
	o: RenderOptions,
): string {
	const c = paint(o);
	if (!conns.length) return c.dim("no connections");
	const groups = new Map<string, Connection[]>();
	for (const x of conns) {
		const k = connOwner(x);
		groups.set(k, [...(groups.get(k) ?? []), x]);
	}
	const out: string[] = [];
	for (const [who, list] of [...groups].sort(
		(a, b) => b[1].length - a[1].length,
	)) {
		out.push(
			`${c.bold(who)}  ${c.dim(`${list.length} connection${list.length > 1 ? "s" : ""}`)}`,
		);
		// identical lines (several sockets to one server) once, with a count
		const lines = new Map<string, number>();
		for (const x of list) {
			const arrow = x.direction === "in" ? c.magenta("←") : c.cyan("→");
			const mine = x.direction === "in" ? `:${x.local.port} ` : "";
			const where =
				x.peer.kind === "remote" ? c.dim(routeVia(x.peer.route)) : "";
			const state = x.state === "ESTABLISHED" ? "" : c.yellow(x.state);
			const line = [
				`  ${mine}${arrow} ${peerLabel(x.peer, endpoint(x.remote), o)}`,
				where,
				state,
			]
				.filter(Boolean)
				.join("  ");
			lines.set(line, (lines.get(line) ?? 0) + 1);
		}
		for (const [line, n] of lines)
			out.push(n > 1 ? `${line}  ${c.dim(`×${n}`)}` : line);
	}
	return out.join("\n");
}

export function renderWho(
	r: WhoReport,
	o: RenderOptions & { home?: string; now?: number },
	snap?: Snapshot,
): string {
	const c = paint(o);
	const out: string[] = [];
	if (!r.listeners.length && !r.outbound.length && !r.inside.length)
		return `nothing listens on port ${r.port}, and nothing here talks to it`;
	for (const l of r.listeners) {
		out.push(`${c.bold(`${l.proto} ${l.port}`)}  ${ownerLabel(l, o)}`);
		const kv: [string, string][] = [];
		if (l.process)
			kv.push([
				"process",
				`${l.process.cmd}  ${c.dim(`(pid ${l.process.pid}${l.user ? `, ${l.user}` : ""})`)}`,
			]);
		const p = l.process;
		if (p?.git)
			kv.push([
				"checkout",
				`${tilde(p.git.root, o.home)}  ${p.git.branch ? `branch ${p.git.branch}` : "detached HEAD"}${p.git.worktree ? c.dim("  (worktree)") : ""}`,
			]);
		if (p?.project)
			kv.push([
				"project",
				`${tilde(p.project.root, o.home)}  ${p.project.removed ? c.yellow("removed") : p.project.branch ? `branch ${p.project.branch}` : ""}${c.dim(p.project.via === "session" ? "  (from its Claude session)" : "  (from what started it)")}`,
			]);
		if (p?.cwd && p.cwd !== p.git?.root)
			kv.push(["directory", tilde(p.cwd, o.home)]);
		if (p?.app) kv.push(["app", p.app]);
		if (p?.orphan)
			kv.push([
				"",
				c.yellow(
					`its Claude session has ended: probably left behind (nethound kill ${l.port})`,
				),
			]);
		if (p && snap) {
			const up = startedBy(snap, p.pid).slice(0, 3);
			if (up.length) kv.push(["started by", up.map(procLabel).join(" ← ")]);
		}
		if (p?.started) kv.push(["up since", new Date(p.started).toLocaleString()]);
		else if (!l.container)
			kv.push([
				"process",
				c.yellow(
					`owned by ${l.user ?? "another user"}: ${elevate(o)} to see which process`,
				),
			]);
		if (l.container) {
			const ct = l.container;
			kv.push([
				"container",
				`${ct.name}  ${c.dim(ct.image)}${ct.project ? c.dim(`  compose project ${ct.project}`) : ""}`,
			]);
			for (const n of ct.networks)
				kv.push([
					"",
					`→ ${n.ip ?? "?"}:${l.published?.containerPort ?? l.port} on ${n.name}${n.bridge ? c.dim(` (${n.bridge})`) : ""}`,
				]);
		}
		if (snap && l.container && l.published) {
			const t = publishedTarget(snap, l.container, l.published);
			const cp = l.published.containerPort;
			if (t.state === "nothing")
				kv.push([
					"inside",
					c.red(
						`nothing listens on ${cp} in the container: connections are reset`,
					),
				]);
			else if (t.state === "loopback")
				kv.push([
					"inside",
					c.red(
						`${insideOwner(t.inside[0])} listens on ${t.inside[0]?.addresses.join(", ")} only: the published port can't reach it`,
					),
				]);
			else if (t.state === "ok")
				kv.push([
					"inside",
					t.inside
						.map(
							(x) =>
								`${insideOwner(x)} on ${x.addresses.map((a) => endpoint({ address: a, port: cp })).join(", ")}`,
						)
						.join(", "),
				]);
		}
		kv.push(["bound to", l.addresses.join(", ")]);
		kv.push([
			"reachable",
			reachLabel(l, o) +
				(l.reach.scope === "everywhere"
					? c.dim(`: ${l.reach.interfaces.join(", ")}`)
					: ""),
		]);
		const via = snap ? outside(snap, l) : [];
		const fw = snap && via.length ? verdictFor(snap, l, via) : undefined;
		if (fw)
			kv.push([
				"firewall",
				fw.result === "blocked"
					? c.green(`blocks other machines: ${fw.why}`)
					: fw.result === "unknown"
						? c.dim(fw.why)
						: c.yellow(
								`${fw.result === "open" ? "lets other machines in" : "lets some machines in"}: ${fw.why}`,
							),
			]);
		else if (l.reach.scope === "everywhere")
			kv.push([
				"",
				c.yellow(
					"any machine that can reach one of those interfaces can connect",
				),
			]);
		if (l.clients.length) {
			kv.push(["clients", `${l.clients.length}`]);
			for (const x of l.clients)
				kv.push(["", `← ${peerLabel(x.peer, endpoint(x.remote), o)}`]);
		} else kv.push(["clients", c.dim("none right now")]);
		// docker-proxy's side: one connection to the container for each client, not clients of their own
		const relays = r.relayed.filter(
			(x) => x.relay?.container.id === l.container?.id,
		);
		const to = relays[0];
		if (to)
			kv.push([
				"",
				c.dim(
					`each relayed by docker-proxy to ${endpoint(to.remote)} in ${to.relay?.container.name} (${relays.length} connection${relays.length > 1 ? "s" : ""})`,
				),
			]);
		for (const [k, v] of kv) out.push(`  ${c.dim(k.padEnd(10))} ${v}`);
		out.push("");
	}
	// inside containers and other namespaces, unless a published port above already says it
	const shown = new Set(
		r.listeners.flatMap((l) =>
			l.container && l.published
				? [`${l.container.id} ${l.proto} ${l.published.containerPort}`]
				: [],
		),
	);
	for (const x of r.inside) {
		if (x.container && shown.has(`${x.container.id} ${x.proto} ${x.port}`))
			continue;
		const where = snap ? namespaceLabel(snap, x.namespace) : "a namespace";
		const ip = x.container?.networks.find((n) => n.ip)?.ip;
		const pub = x.published.map((p) => `:${p.hostPort}`).join(" ");
		out.push(
			`${c.bold(`${x.proto} ${x.port}`)}  inside ${where}${pub ? c.dim(`  published on ${pub}`) : c.dim("  not published")}`,
		);
		const kv: [string, string][] = [];
		kv.push(["process", insideOwner(x)]);
		kv.push(["bound to", x.addresses.join(", ")]);
		const local = x.addresses.every(isLoopback);
		kv.push([
			"reachable",
			local
				? "inside it only"
				: x.container
					? `from its network's containers${ip ? `, and from this machine at ${endpoint({ address: ip, port: x.port })}` : ""}`
					: "from that namespace's interfaces",
		]);
		out.push(...kv.map(([k, v]) => `  ${c.dim(k.padEnd(10))} ${v}`), "");
	}
	if (r.outbound.length) {
		out.push(c.bold(`connections to port ${r.port} elsewhere`));
		for (const x of r.outbound) {
			const who = connOwner(x);
			const where =
				x.peer.kind === "remote" ? `  ${c.dim(routeVia(x.peer.route))}` : "";
			out.push(
				`  ${who} → ${peerLabel(x.peer, endpoint(x.remote), o)}${where}`,
			);
		}
	}
	return out.join("\n").trimEnd();
}

export function renderRoute(
	r: RouteResult,
	host: string,
	o: RenderOptions,
): string {
	const c = paint(o);
	const name = host === r.dest ? r.dest : `${host} (${r.dest})`;
	const kv: [string, string][] = [];
	switch (r.kind) {
		case "loopback":
			return `${c.bold(name)} is this machine, through the loopback ${c.dim("(lo)")}`;
		case "local":
			return `${c.bold(name)} is this machine: an address of ${r.iface}, delivered through the loopback`;
		case "unreachable":
			return `${c.bold(name)}: ${c.red("no route")}: packets to it are dropped`;
		case "container":
			kv.push(["is", `container ${r.container?.name}, on this machine`]);
			break;
		case "network":
			kv.push(["is", `on the network of ${r.iface}, reached directly`]);
			break;
		case "gateway":
			kv.push(["is", `beyond ${r.gateway}, the gateway on ${r.iface}`]);
	}
	kv.push(["interface", r.iface ?? ""]);
	if (r.route)
		kv.push([
			"route",
			`${routeLabel(r.route)}${r.route.metric ? ` metric ${r.route.metric}` : ""}`,
		]);
	if (r.source) kv.push(["from", r.source]);
	return [
		c.bold(name),
		...kv.map(([k, v]) => `  ${c.dim(k.padEnd(10))} ${v}`),
	].join("\n");
}

export function renderMap(m: MapReport, o: RenderOptions): string {
	const c = paint(o);
	const out: string[] = [];
	out.push(
		`${c.bold(m.hostname)}${m.environment === "wsl" ? c.dim("  (WSL: Windows reaches ports on 127.0.0.1 and every interface through its localhost)") : ""}`,
	);
	out.push("");
	const listenLine = (l: Listener) =>
		`${c.bold(`${l.proto} ${l.port}`.padEnd(9))} ${ownerLabel(l, o)}${l.clients.length ? c.cyan(`  ← ${l.clients.length} client${l.clients.length > 1 ? "s" : ""}`) : ""}`;
	if (m.everywhere.length) {
		out.push(`${c.yellow("listening on every interface")}`);
		for (const l of m.everywhere) out.push(`  ${listenLine(l)}`);
		out.push("");
	}
	for (const v of m.interfaces) {
		const i = v.iface;
		const net = dockerNetwork(v);
		out.push(ifaceHeader(i, o, net));
		if (shownRoutes(v.routes).length)
			out.push(
				`  ${c.dim("routes")}  ${shownRoutes(v.routes).map(routeLabel).join(", ")}`,
			);
		for (const l of v.listeners)
			out.push(`  ${c.green("listen")}  ${listenLine(l)}`);
		for (const x of v.containers)
			out.push(
				`  ${c.blue("holds")}   ${x.container.name}${x.ip ? ` ${x.ip}` : ""}${insidePorts(m.inside, x.container)}${portsOf(x.container)}`,
			);
		if (i.members.length)
			out.push(
				c
					.dim(
						`  ${i.members.length} port${i.members.length > 1 ? "s" : ""}: ${i.members.join(" ")}`,
					)
					.slice(0, o.width ?? Infinity),
			);
		out.push(...grouped(v.outbound, "out", o));
		out.push(...grouped(v.local, "local", o));
		out.push("");
	}
	if (m.idle.length) out.push(c.dim(`down, no address: ${m.idle.join(", ")}`));
	// namespaces that are no container: ip netns', a sandbox's, rootless podman's
	const others = m.inside.filter((x) => !x.container);
	if (others.length) {
		if (out.at(-1) !== "") out.push("");
		out.push(c.yellow("in other network namespaces"));
		for (const x of others)
			out.push(
				`  ${c.bold(`${x.proto} ${x.port}`.padEnd(9))} ${insideOwner(x)}  ${c.dim(`${x.addresses.join(", ")}${x.namespace.name ? `, netns ${x.namespace.name}` : ""}`)}`,
			);
		out.push("");
	}
	if (m.dns.length) {
		out.push(
			`${c.dim("dns")}  ${m.dns.map((d) => `${d.server} ${c.dim(d.route.kind === "loopback" || d.route.kind === "local" ? "(local resolver)" : routeVia(d.route))}`).join(", ")}`,
		);
	}
	if (m.hidden)
		out.push(
			c.dim(
				`${m.hidden} processes of other users hidden: ${elevate(o)} to see their sockets`,
			),
		);
	return out.join("\n").trimEnd();
}

/** What a container listens on, its loopback left out: "  listens 5432 udp 53". */
function insidePorts(all: InsideListener[], ct: Container): string {
	const ports = [
		...new Set(
			all
				.filter(
					(x) => x.container?.id === ct.id && !x.addresses.every(isLoopback),
				)
				.map((x) => (x.proto === "tcp" ? `${x.port}` : `udp ${x.port}`)),
		),
	];
	return ports.length ? `  listens ${ports.join(" ")}` : "";
}

function portsOf(ct: Container): string {
	const p = ct.ports.filter(
		(x, i, a) =>
			a.findIndex((y) => y.hostPort === x.hostPort && y.proto === x.proto) ===
			i,
	);
	return p.length
		? `  ← host ${p.map((x) => `:${x.hostPort}${x.hostPort !== x.containerPort ? `→${x.containerPort}` : ""}`).join(" ")}`
		: "";
}

/** Connections per process, remote ends listed once each, for the map. */
function grouped(
	conns: Connection[],
	label: "out" | "local",
	o: RenderOptions,
): string[] {
	const c = paint(o);
	const by = new Map<string, Map<string, number>>();
	for (const x of conns) {
		const who = connOwner(x);
		const to =
			label === "local"
				? peerLabel(x.peer, `:${x.remote.port}`, o)
				: endpoint(x.remote);
		const m = by.get(who) ?? new Map<string, number>();
		m.set(to, (m.get(to) ?? 0) + 1);
		by.set(who, m);
	}
	const tag = label === "out" ? c.cyan("out") : c.magenta("local");
	return [...by].map(([who, tos]) => {
		const list = [...tos]
			.map(([to, n]) => (n > 1 ? `${to} ×${n}` : to))
			.join(", ");
		return `  ${tag}${label === "out" ? "     " : "   "}${fit(`${who} → ${list}`, o.width && o.width - 10)}`;
	});
}

// --json: plain data, without the links between listeners and connections (they form cycles)

const procJson = (p?: Process) => p && { pid: p.pid, name: p.name, cmd: p.cmd };
const containerJson = (ct?: Container) =>
	ct && { id: ct.id, name: ct.name, image: ct.image, project: ct.project };

export function peerJson(p: Peer) {
	switch (p.kind) {
		case "local":
			return {
				kind: p.kind,
				process: procJson(p.process),
				user: p.user,
				listener: p.listener && {
					proto: p.listener.proto,
					port: p.listener.port,
					container: p.listener.container?.name,
				},
			};
		case "container":
			return {
				kind: p.kind,
				container: containerJson(p.container),
				network: p.network,
			};
		case "remote":
			return { kind: p.kind, route: routeJson(p.route) };
	}
}

export const routeJson = (r: RouteResult) => ({
	...r,
	container: containerJson(r.container),
});

export const connectionJson = (x: Connection) => ({
	...x,
	process: procJson(x.process),
	peer: peerJson(x.peer),
	relay: x.relay && {
		container: x.relay.container.name,
		hostPort: x.relay.published.hostPort,
	},
});

export function renderDoctor(findings: Finding[], o: RenderOptions): string {
	const c = paint(o);
	if (!findings.length) return c.green("✓ no problems found");
	const mark = { error: c.red("✗"), warning: c.yellow("!"), info: c.cyan("·") };
	const blocks = findings.map((f) =>
		[
			`${mark[f.severity]} ${f.title}`,
			...f.details.map((d) => c.dim(`  ${d}`)),
			`  ${c.dim("fix:")} ${f.fix}`,
		].join("\n"),
	);
	const n = (severity: Finding["severity"], word: string) => {
		const k = findings.filter((f) => f.severity === severity).length;
		return k ? [`${k} ${word}${k === 1 ? "" : "s"}`] : [];
	};
	const summary = [
		...n("error", "error"),
		...n("warning", "warning"),
		...n("info", "note"),
	].join(", ");
	return `${blocks.join("\n\n")}\n\n${c.bold(summary)}`;
}

export const insideJson = (x: InsideListener) => ({
	proto: x.proto,
	port: x.port,
	addresses: x.addresses,
	namespace: {
		inode: x.namespace.inode,
		container: x.namespace.container,
		name: x.namespace.name,
	},
	container: containerJson(x.container),
	process: procJson(x.process),
	published: x.published,
});

export const listenerJson = (l: Listener) => ({
	proto: l.proto,
	port: l.port,
	addresses: l.addresses,
	reach: l.reach,
	process: procJson(l.process),
	user: l.user,
	container: containerJson(l.container),
	published: l.published,
	clients: l.clients.map(connectionJson),
});

export const ifaceViewJson = (v: IfaceView) => ({
	...v.iface,
	routes: v.routes,
	listeners: v.listeners.map((l) => ({ proto: l.proto, port: l.port })),
	outbound: v.outbound.map(connectionJson),
	local: v.local.map(connectionJson),
	containers: v.containers.map((x) => ({
		...containerJson(x.container),
		ip: x.ip,
	})),
});

export const mapJson = (m: MapReport) => ({
	...m,
	everywhere: m.everywhere.map(listenerJson),
	interfaces: m.interfaces.map(ifaceViewJson),
	dns: m.dns.map((d) => ({ server: d.server, route: routeJson(d.route) })),
	inside: m.inside.map(insideJson),
});
