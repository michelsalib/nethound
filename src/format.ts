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
	VPN_KINDS,
	type WhoReport,
	widest,
} from "./analyze.ts";
import type { Finding } from "./doctor.ts";
import { outside, verdictFor } from "./firewall.ts";
import type { Container, Iface, Process, Route, Snapshot } from "./model.ts";
import { endpoint, isLinkLocal, isLoopback, isWildcard } from "./net.ts";
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

export const ESC = "\x1b";

/** Characters a terminal shows: colour codes (ESC [ … m) left out. */
export function visibleLength(s: string): number {
	let n = 0;
	for (let i = 0; i < s.length; i++) {
		if (s[i] === ESC) i = s.indexOf("m", i);
		else n++;
		if (i < 0) break;
	}
	return n;
}

/** `s` cut to `w` visible characters, its colour codes kept whole. */
export function cut(s: string, w: number): string {
	if (visibleLength(s) <= w) return s;
	let out = "";
	let shown = 0;
	for (let i = 0; i < s.length && shown < w - 1; i++) {
		if (s[i] === ESC) {
			const end = s.indexOf("m", i);
			out += s.slice(i, end + 1);
			i = end;
			continue;
		}
		out += s[i];
		shown++;
	}
	// a cut colour is closed; plain text stays plain
	return s.includes(ESC) ? `${out}…${ESC}[0m` : `${out}…`;
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
		: `via ${r.iface}${r.gateway ? ` → ${r.gateway}` : ""}${
				r.vpn
					? " (VPN)"
					: r.windows?.vpn
						? ` → Windows' VPN on ${r.windows.iface}`
						: ""
			}`;

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

function ifaceHeader(
	i: Iface,
	o: RenderOptions,
	note = "",
	addresses = i.addresses,
): string {
	const c = paint(o);
	const state =
		i.state === "up"
			? c.green("up")
			: i.state === "down"
				? c.red("down")
				: c.dim(i.state);
	const vpn = VPN_KINDS.includes(i.kind)
		? ["VPN", i.description].filter(Boolean).join(": ")
		: "";
	return [
		c.bold(i.name),
		i.kind,
		state,
		addresses.map((a) => `${a.address}/${a.prefix}`).join(" "),
		vpn && c.cyan(vpn),
		note && c.dim(note),
	]
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

/** An interface's routes; a VPN's hundreds cut to the widest: "282 routes via 10.8.0.1:
 * 10.20.0.0/16, … and 276 more". */
function routesText(rs: Route[], width?: number): string {
	const all = shownRoutes(rs);
	// the widest that fit `width`
	for (let max = 6; max > 1; max--) {
		const text = routesOf(all, max);
		if (!width || text.length <= width) return text;
	}
	return routesOf(all, 1);
}

function routesOf(all: Route[], max: number): string {
	const { shown, more } = widest(all, max);
	if (!more) return shown.map(routeLabel).join(", ");
	// the routes a VPN pushes share its gateway: said once
	const gateways = new Set(all.flatMap((r) => (r.gateway ? [r.gateway] : [])));
	const one = gateways.size === 1 ? [...gateways][0] : undefined;
	const labels = shown.map((r) =>
		r.gateway === one
			? routeLabel({ ...r, gateway: undefined })
			: routeLabel(r),
	);
	return `${all.length} routes${one ? ` via ${one}` : ""}: ${labels.join(", ")} and ${more} more`;
}

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
			lines.push(["routes", routesText(v.routes)]);
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
	switch (r.kind) {
		case "loopback":
			return `${c.bold(name)} is this machine, through the loopback ${c.dim("(lo)")}`;
		case "local":
			return `${c.bold(name)} is this machine: an address of ${r.iface}, delivered through the loopback`;
		case "unreachable":
			return `${c.bold(name)}: ${c.red("no route")}: packets to it are dropped`;
	}
	const lines = (r: RouteResult) => {
		const kv: [string, string][] = [];
		if (r.kind === "container")
			kv.push(["is", `container ${r.container?.name}, on this machine`]);
		else if (r.kind === "network")
			kv.push(["is", `on the network of ${r.iface}, reached directly`]);
		else if (r.kind === "gateway")
			kv.push(["is", `beyond ${r.gateway}, the gateway on ${r.iface}`]);
		kv.push(["interface", r.iface ?? ""]);
		if (r.route)
			kv.push([
				"route",
				`${routeLabel(r.route)}${r.route.metric ? ` metric ${r.route.metric}` : ""}`,
			]);
		if (r.source) kv.push(["from", r.source]);
		if (r.vpn) kv.push(["vpn", c.green(`through ${r.vpn}`)]);
		else if (r.outside)
			kv.push(["vpn", c.yellow(`not through ${r.outside.join(", ")}`)]);
		return kv.map(([k, v]) => `  ${c.dim(k.padEnd(10))} ${v}`);
	};
	const w = r.windows;
	return [
		c.bold(name),
		...lines(r),
		...(w
			? w.kind === "unreachable"
				? [`then Windows: ${c.red("no route")}: it drops packets to it`]
				: [`then Windows ${c.dim(`(${r.gateway})`)} sends it on`, ...lines(w)]
			: []),
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
	// what each interface holds, a label in a column of its own: values start at the same place
	const room = o.width && o.width - LABEL - 4;
	const row = (label: string, color: (s: string) => string, text: string) =>
		`  ${color(label.padEnd(LABEL))}  ${text}`;
	for (const v of m.interfaces) {
		const i = v.iface;
		out.push(mapHeader(i, o, dockerNetwork(v)));
		if (shownRoutes(v.routes).length)
			out.push(row("routes", c.dim, routesText(v.routes, room)));
		for (const [owner, ls] of byOwner(v.listeners, o))
			out.push(row("listen", c.green, listenGroup(owner, ls, o)));
		for (const x of v.containers)
			out.push(
				row(
					"holds",
					c.blue,
					`${x.container.name}${x.ip ? ` ${x.ip}` : ""}${insidePorts(m.inside, x.container)}${portsOf(x.container)}`,
				),
			);
		if (i.members.length)
			out.push(row("ports", c.dim, c.dim(i.members.join(" "))));
		if (v.neighbours.length)
			out.push(row("neighbours", c.dim, neighboursText(v, room)));
		for (const [who, to] of grouped(v.outbound, "out", o))
			out.push(row("out", c.cyan, `${who} → ${to}`));
		for (const [who, to] of grouped(v.local, "local", o))
			out.push(row("local", c.magenta, `${who} → ${to}`));
		out.push("");
	}
	if (m.idle.length) {
		out.push(c.yellow("down"));
		const w = Math.max(...m.idle.map((i) => i.name.length));
		for (const i of m.idle) {
			const purpose = PURPOSES.find(([re]) => re.test(i.description ?? ""));
			out.push(
				`  ${i.name.padEnd(w)}  ${c.dim(i.description ?? "")}${purpose ? `: ${purpose[1]}` : ""}`.trimEnd(),
			);
		}
		out.push("");
	}
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
		if (out.at(-1) !== "") out.push("");
		out.push(c.yellow("dns servers"));
		const w = Math.max(...m.dns.map((d) => d.server.length));
		for (const d of m.dns)
			out.push(`  ${d.server.padEnd(w)}  ${dnsWay(d.server, d.route, o)}`);
		out.push("");
	}
	// Windows' own networks, which WSL behind its NAT doesn't see: the machines on them
	if (m.windowsNeighbours?.length) {
		if (out.at(-1) !== "") out.push("");
		out.push(c.yellow("on Windows"));
		for (const w of m.windowsNeighbours) {
			out.push(
				`${c.bold(w.iface.name)}  ${w.iface.addresses.map((a) => a.address).join(" ")}`,
			);
			out.push(row("neighbours", c.dim, neighboursText(w, room)));
		}
		out.push("");
	}
	for (const w of m.windowsVpns ?? []) {
		out.push(
			`${c.dim("windows")}  ${c.cyan(`VPN ${w.vpn}`)}: ${w.all ? "all traffic through it, WSL's too" : `${w.networks} network${w.networks === 1 ? "" : "s"} through it, WSL's traffic to them too; the rest by ${w.internet ?? "no route"}`} ${c.dim("(nethound route HOST says which way)")}`,
		);
	}
	if (m.hidden)
		out.push(
			c.dim(
				`${m.hidden} processes of other users hidden: ${elevate(o)} to see their sockets`,
			),
		);
	// every line on one line of the terminal: cut, never wrapped
	return out
		.map((l) => cut(l, o.width ?? Infinity))
		.join("\n")
		.trimEnd();
}

/** "192.168.1.1 gateway, 192.168.1.23 and 40 more": the gateway marked, as many as fit `width`. */
function neighboursText(
	v: Pick<IfaceView, "routes" | "neighbours">,
	width?: number,
): string {
	const gateways = new Set(v.routes.flatMap((r) => r.gateway ?? []));
	const all = v.neighbours.map((n) =>
		gateways.has(n.address) ? `${n.address} gateway` : n.address,
	);
	let shown = all.length;
	const text = (k: number) =>
		all.slice(0, k).join(", ") +
		(k < all.length ? ` and ${all.length - k} more` : "");
	while (width && shown > 1 && text(shown).length > width) shown--;
	return text(shown);
}

/** What a down adapter is for, by its description: Windows names them all "Connexion au réseau
 * local* 3" or "Local Area Connection* 3". */
const PURPOSES: [RegExp, string][] = [
	[
		/wi-fi direct/i,
		"Mobile Hotspot, casting to a screen (Miracast), Nearby Sharing",
	],
	[/bluetooth/i, "a network over Bluetooth (tethering to a phone)"],
];

/** How a DNS server is reached, in words: "through eth0, gateway 172.20.80.1". */
function dnsWay(server: string, r: RouteResult, o: RenderOptions): string {
	const c = paint(o);
	if (r.kind === "unreachable") return c.red("no route to it");
	if (r.kind === "loopback" || r.kind === "local")
		return server === "127.0.0.53"
			? "on this machine: systemd-resolved, which asks the others"
			: "on this machine";
	if (r.kind === "container") return `container ${r.container?.name}`;
	// fe80:: is on every interface: the route can't say which, the router that gave it is on one
	if (isLinkLocal(server))
		return "link-local: a router on the network that gave it";
	const way =
		r.kind === "network"
			? `on ${r.iface}'s network`
			: `through ${r.iface}, gateway ${r.gateway}`;
	const vpn = r.vpn
		? c.cyan(" (VPN)")
		: r.windows?.vpn
			? c.cyan(`, then Windows' VPN on ${r.windows.iface}`)
			: "";
	return way + vpn;
}

/** The width of the map's labels: "neighbours". */
const LABEL = 10;

/** An interface's line on the map: name, kind, state, then its addresses, IPv4 first, without the
 * link-local ones every interface has (fe80::). */
function mapHeader(i: Iface, o: RenderOptions, note: string): string {
	const addresses = [
		...i.addresses.filter((a) => a.family === 4),
		...i.addresses.filter((a) => a.family === 6 && !isLinkLocal(a.address)),
	];
	return ifaceHeader(i, o, note, addresses);
}

/** An interface's listeners by what holds them: one line for System's dozen. */
function byOwner(ls: Listener[], o: RenderOptions): Map<string, Listener[]> {
	const by = new Map<string, Listener[]>();
	for (const l of ls) {
		const owner = ownerLabel(l, o);
		by.set(owner, [...(by.get(owner) ?? []), l]);
	}
	return by;
}

/** "System 4  tcp 139 · udp 137 138  ← 2 clients": its ports by protocol, its clients counted. */
function listenGroup(owner: string, ls: Listener[], o: RenderOptions): string {
	const c = paint(o);
	const ports = (["tcp", "udp"] as const)
		.map((p) => ls.filter((l) => l.proto === p).map((l) => l.port))
		.map((ps, i) => (ps.length ? `${i ? "udp" : "tcp"} ${ps.join(" ")}` : ""))
		.filter(Boolean)
		.join(" · ");
	const clients = ls.reduce((n, l) => n + l.clients.length, 0);
	return `${owner}  ${c.bold(ports)}${clients ? c.cyan(`  ← ${clients} client${clients > 1 ? "s" : ""}`) : ""}`;
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
): [string, string][] {
	const c = paint(o);
	const by = new Map<string, Map<string, number>>();
	for (const x of conns) {
		const who = connOwner(x);
		// through a VPN: this machine's, or in WSL Windows'
		const vpn =
			x.peer.kind === "remote" &&
			(x.peer.route.vpn || x.peer.route.windows?.vpn);
		const to =
			label === "local"
				? peerLabel(x.peer, `:${x.remote.port}`, o)
				: `${endpoint(x.remote)}${vpn ? c.cyan(" (VPN)") : ""}`;
		const m = by.get(who) ?? new Map<string, number>();
		m.set(to, (m.get(to) ?? 0) + 1);
		by.set(who, m);
	}
	return [...by].map(([who, tos]) => [
		who,
		[...tos].map(([to, n]) => (n > 1 ? `${to} ×${n}` : to)).join(", "),
	]);
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

export const routeJson = (r: RouteResult): object => ({
	...r,
	container: containerJson(r.container),
	windows: r.windows && routeJson(r.windows),
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
	neighbours: v.neighbours,
});

export const mapJson = (m: MapReport) => ({
	...m,
	idle: m.idle.map((i) => i.name),
	everywhere: m.everywhere.map(listenerJson),
	interfaces: m.interfaces.map(ifaceViewJson),
	dns: m.dns.map((d) => ({ server: d.server, route: routeJson(d.route) })),
	inside: m.inside.map(insideJson),
});
