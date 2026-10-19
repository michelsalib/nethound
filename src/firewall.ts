// Would the firewall let another machine in to a listener? Each system's firewall is read in its own
// terms (src/*/firewall.ts); here, one answer for a listener: open, blocked, open to some sources
// only, or unknown. Netfilter's chains are walked as the kernel walks them for a new connection.

import type { Listener } from "./analyze.ts";
import type {
	Family,
	Firewall,
	FirewallProfile,
	Iface,
	NfChain,
	NfMatch,
	NfRule,
	NfTable,
	Proto,
	Snapshot,
} from "./model.ts";
import { inNetwork, isLoopback, isWildcard } from "./net.ts";

export interface Verdict {
	/** partial: only from some sources, or under conditions nethound can't judge. */
	result: "open" | "blocked" | "partial" | "unknown";
	/** Why, in a finding's words: "ufw lets it in: -A ufw-user-input -p tcp --dport 22 -j ACCEPT". */
	why: string;
}

/** A new connection, as a firewall sees it. */
export interface Packet {
	family: Family;
	proto: Proto;
	dport: number;
	/** The interface it comes in on. */
	iif: string;
	/** Forwarded to a container: the bridge it leaves on. */
	oif?: string;
	/** Where it goes: the container's address, or the addresses of this machine it may be sent
	 * to (those of `iif`, for a listener on every address). */
	daddrs: string[];
}

type Tri = true | false | "maybe";

/** "eth+" (iptables) and "eth*" (nft) match every eth interface. */
const ifaceMatches = (pattern: string, name: string) =>
	/[+*]$/.test(pattern)
		? name.startsWith(pattern.slice(0, -1))
		: pattern === name;

/** 22, "8000-8080", "8000:8080". */
function portIn(value: string, port: number): boolean {
	const [a = "", b] = value.split(/[-:]/);
	const lo = Number(a);
	const hi = b === undefined ? lo : Number(b);
	return port >= lo && port <= hi;
}

const PROTOS: Record<string, Proto> = { "6": "tcp", "17": "udp" };

function addressIn(value: string, ip: string): boolean {
	const [net = "", len] = value.split("/");
	const prefix = len ? Number(len) : net.includes(":") ? 128 : 32;
	return inNetwork(ip, net, prefix);
}

/** Whether one condition holds for the packet: maybe when it depends on what nethound can't know. */
function holds(m: NfMatch, p: Packet): Tri {
	const any = (f: (v: string) => boolean) => m.values.some(f);
	let r: Tri;
	switch (m.kind) {
		case "proto":
			r = any((v) => (PROTOS[v] ?? v) === p.proto);
			break;
		case "dport":
			r = any((v) => portIn(v, p.dport));
			break;
		case "iif":
			r = any((v) => ifaceMatches(v, p.iif));
			break;
		case "oif":
			// on the input hook, a packet leaves on no interface
			r = p.oif !== undefined && any((v) => ifaceMatches(v, p.oif ?? ""));
			break;
		case "daddr": {
			// several addresses: which one depends on the client
			const hits = p.daddrs.filter((d) => any((v) => addressIn(v, d)));
			if (hits.length && hits.length < p.daddrs.length && !m.not)
				return "maybe";
			r = hits.length > 0;
			break;
		}
		case "dnat":
			r = p.oif !== undefined;
			break;
		case "ct":
			// a new connection: the first packet
			r = any((v) => v.toUpperCase() === "NEW");
			break;
		case "dsttype":
			// unicast to this machine, or forwarded to a container
			r = any((v) => v.toUpperCase() === (p.oif ? "UNICAST" : "LOCAL"));
			break;
		case "nfproto":
			r = any((v) => v === `ipv${p.family}`);
			break;
		default:
			// the source address, rate limits, marks: they depend on the client
			return "maybe";
	}
	return m.not ? !r : r;
}

function allHold(ms: NfMatch[], p: Packet): Tri {
	let out: Tri = true;
	for (const m of ms) {
		const r = holds(m, p);
		if (r === false) return false;
		if (r === "maybe") out = "maybe";
	}
	return out;
}

/** What a vmap's key is for this packet. */
function keyOf(kind: NfMatch["kind"], p: Packet): string | undefined {
	if (kind === "ct") return "new";
	if (kind === "iif") return p.iif;
	if (kind === "oif") return p.oif;
	if (kind === "proto") return p.proto;
	if (kind === "dport") return String(p.dport);
	if (kind === "nfproto") return `ipv${p.family}`;
	return undefined;
}

interface Outcome {
	verdict: "accept" | "drop";
	rule?: NfRule;
	chain: string;
	/** A rule that would have decided otherwise for some clients. */
	unless?: NfRule;
}

/** Walks a chain; undefined when the packet falls through (or returns) without a verdict. */
function walk(
	chains: Map<string, NfChain>,
	chain: NfChain,
	p: Packet,
	depth: number,
	state: { unless?: NfRule },
): Outcome | undefined {
	if (depth > 32) return undefined;
	for (const rule of chain.rules) {
		const m = allHold(rule.matches, p);
		if (m === false) continue;
		let r: NfRule = rule;
		if (rule.vmap) {
			const key = keyOf(rule.vmap.key, p);
			if (key === undefined) {
				state.unless ??= rule;
				continue;
			}
			const hit = rule.vmap.entries.find(([vs]) =>
				vs.some((v) =>
					rule.vmap?.key === "dport"
						? portIn(v, Number(key))
						: rule.vmap?.key === "iif" || rule.vmap?.key === "oif"
							? ifaceMatches(v, key)
							: v.toLowerCase() === key.toLowerCase(),
				),
			);
			if (!hit) continue;
			r = { ...hit[1], text: rule.text };
		}
		if (!r.verdict) continue;
		if (m === "maybe") {
			// for some clients only: note it, and go on as for the others
			if (r.verdict === "accept" || r.verdict === "drop") state.unless ??= r;
			continue;
		}
		if (r.verdict === "return") return undefined;
		if (r.verdict === "jump" || r.verdict === "goto") {
			const next = chains.get(r.target ?? "");
			const out = next && walk(chains, next, p, depth + 1, state);
			if (out) return out;
			// goto doesn't come back: the chain that jumped here ends too
			if (r.verdict === "goto") return undefined;
			continue;
		}
		return {
			verdict: r.verdict,
			rule: r,
			chain: chain.name,
			unless: state.unless,
		};
	}
	return undefined;
}

export interface NfVerdict {
	verdict: "accept" | "drop";
	rule?: NfRule;
	/** The chain of the deciding rule. */
	chain?: string;
	/** The base chain whose policy decided, when no rule did. */
	policy?: string;
	unless?: NfRule;
}

/** What netfilter does with a new connection: every base chain on its hook must accept it. */
export function evaluate(
	tables: NfTable[],
	hook: "input" | "forward",
	p: Packet,
): NfVerdict {
	const bases = tables
		.filter((t) => t.family === "both" || t.family === p.family)
		.flatMap((t) =>
			t.chains.filter((c) => c.hook === hook).map((c) => ({ t, c })),
		)
		.sort((a, b) => (a.c.priority ?? 0) - (b.c.priority ?? 0));
	let accepted: NfVerdict = { verdict: "accept" };
	for (const { t, c } of bases) {
		const chains = new Map(t.chains.map((x) => [x.name, x]));
		const state: { unless?: NfRule } = {};
		const out = walk(chains, c, p, 0, state);
		const v: NfVerdict = out
			? {
					verdict: out.verdict,
					rule: out.rule,
					chain: out.chain,
					unless: out.unless,
				}
			: {
					verdict: c.policy ?? "accept",
					policy: c.name,
					unless: state.unless,
				};
		if (v.verdict === "drop") return v;
		// the deciding accept is the most telling one: a rule over a policy
		if (v.rule || !accepted.rule) accepted = v;
	}
	return accepted;
}

/** Kinds of interface that lead nowhere off this machine. */
export const INTERNAL: Iface["kind"][] = [
	"loopback",
	"bridge",
	"veth",
	"virtual",
];

/** The interfaces that lead off this machine: not the loopback, docker's bridges or VM switches. */
export function outside(snap: Snapshot, l: Listener): string[] {
	const kind = new Map(snap.interfaces.map((i) => [i.name, i.kind]));
	return l.reach.interfaces.filter((n) => {
		const k = kind.get(n);
		return k !== undefined && !INTERNAL.includes(k);
	});
}

/** The families a listener takes: a socket on :: takes IPv4 too unless it is IPv6 only. */
const families = (l: Listener): Family[] => {
	const fs = new Set<Family>();
	for (const a of l.addresses) {
		if (a === "0.0.0.0") fs.add(4);
		else if (a === "::") {
			fs.add(6);
			if (!l.sockets.some((s) => s.local.address === "::" && s.v6only))
				fs.add(4);
		} else fs.add(a.includes(":") ? 6 : 4);
	}
	return [...fs];
};

const quote = (r: NfRule) => r.text;

/** The conditions of a rule that hold for some clients only: "from 10.0.0.0/8". */
function condition(r: NfRule): string {
	const parts = r.matches
		.filter((m) => m.kind === "saddr" || m.kind === "other")
		.map((m) =>
			m.kind === "saddr"
				? `from ${m.not ? "anywhere but " : ""}${m.values.join(", ")}`
				: `when ${m.values.join(" ")}`,
		);
	return parts.join(" ") || "for some clients";
}

function netfilterVerdict(
	fw: Extract<Firewall, { kind: "netfilter" }>,
	snap: Snapshot,
	l: Listener,
	iface: string,
): Verdict {
	const name = fw.name;
	const container = l.container && l.published;
	const net = l.container?.networks.find((n) => n.bridge && n.ip);
	if (container && !net)
		return {
			result: "unknown",
			why: "its container's network is not on this machine",
		};
	// the addresses a client on `iface` reaches it at
	const own =
		snap.interfaces
			.find((i) => i.name === iface)
			?.addresses.map((a) => a.address) ?? [];
	const out: Verdict[] = families(l).map((family) => {
		const at = l.addresses.some(isWildcard)
			? own.filter((a) => a.includes(":") === (family === 6))
			: l.addresses.filter((a) => a.includes(":") === (family === 6));
		const p: Packet = container
			? {
					family,
					proto: l.proto,
					dport: l.published?.containerPort ?? l.port,
					iif: iface,
					oif: net?.bridge,
					daddrs: net?.ip ? [net.ip] : [],
				}
			: { family, proto: l.proto, dport: l.port, iif: iface, daddrs: at };
		const v = evaluate(fw.tables, container ? "forward" : "input", p);
		return describe(name, v, !!container);
	});
	return combine(out);
}

function describe(name: string, v: NfVerdict, forwarded: boolean): Verdict {
	if (v.verdict === "accept") {
		if (v.unless)
			return {
				result: "partial",
				why: `${name} lets it in, except ${condition(v.unless)}: ${quote(v.unless)}`,
			};
		return {
			result: "open",
			why: v.rule
				? `${name}'s rules let it in: ${quote(v.rule)}`
				: forwarded
					? `${name} forwards it to the container (FORWARD's policy)`
					: name === "docker"
						? "no rule filters incoming connections"
						: `${name} lets in what no rule decides (${v.policy}'s policy)`,
		};
	}
	if (v.unless)
		return {
			result: "partial",
			why: `${name} lets it in only ${condition(v.unless)}: ${quote(v.unless)}`,
		};
	return {
		result: "blocked",
		why: v.rule?.matches.length
			? `${name}'s rules block it: ${quote(v.rule)}`
			: v.rule
				? `${name} blocks it: no rule lets it in, and ${v.chain} ends with ${quote(v.rule).replace(/^\S+: /, "")}`
				: `${name} blocks it: no rule lets it in, and ${v.policy}'s policy is DROP`,
	};
}

/** One verdict for several ways in: open when one is. */
function combine(vs: Verdict[]): Verdict {
	for (const r of ["open", "partial", "unknown", "blocked"] as const) {
		const v = vs.find((x) => x.result === r);
		if (v) return v;
	}
	return { result: "unknown", why: "no way in to judge" };
}

/** ufw puts docker's published ports before its own rules, and so does firewalld. */
const DOCKER_FIRST =
	"docker's rules let published ports in before the firewall's own (only a DOCKER-USER rule would stop it)";

function ufwVerdict(
	fw: Extract<Firewall, { kind: "ufw" }>,
	l: Listener,
): Verdict {
	if (!fw.enabled)
		return { result: "open", why: "ufw is installed but not enabled" };
	if (l.container)
		return { result: "open", why: `ufw is on, but ${DOCKER_FIRST}` };
	if (!fw.defaultBlock)
		return {
			result: "open",
			why: "ufw lets in what no rule of its own denies",
		};
	return {
		result: "unknown",
		why: "ufw is on and denies by default: whether a rule of its own lets it in takes sudo to read",
	};
}

function firewalldVerdict(
	fw: Extract<Firewall, { kind: "firewalld" }>,
	l: Listener,
	iface: string,
): Verdict {
	if (l.container)
		return { result: "open", why: `firewalld is on, but ${DOCKER_FIRST}` };
	const zone =
		fw.zones.find((z) => z.interfaces.includes(iface)) ??
		fw.zones.find((z) => z.name === fw.defaultZone);
	if (!zone)
		return {
			result: "unknown",
			why: `firewalld's zone for ${iface} (${fw.defaultZone}) has no file nethound can read`,
		};
	const what = `firewalld's zone ${zone.name}`;
	if (zone.target === "ACCEPT")
		return { result: "open", why: `${what} accepts everything` };
	const port = zone.ports.find((x) => {
		const [proto, range = ""] = x.split("/");
		return proto === l.proto && portIn(range, l.port);
	});
	if (port) return { result: "open", why: `${what} opens ${port}` };
	if (zone.rich)
		return {
			result: "partial",
			why: `${what} doesn't open ${l.proto}/${l.port}, but has ${zone.rich} rich rule${zone.rich > 1 ? "s" : ""} that may, for some sources (sudo to judge)`,
		};
	return {
		result: "blocked",
		why: `${what} doesn't open ${l.proto}/${l.port}${zone.target === "DROP" ? " and drops the rest" : ""} (changes made without --permanent take sudo to see)`,
	};
}

/** "80,443,8000-8080" against a port; keywords such as RPC match none of ours. */
const windowsPorts = (ports: string, port: number) =>
	ports === "*" ||
	ports === "" ||
	ports.split(",").some((v) => /^\d+(-\d+)?$/.test(v) && portIn(v, port));

const PROFILE_BIT: Record<FirewallProfile, number> = {
	domain: 1,
	private: 2,
	public: 4,
};

function windowsVerdict(
	fw: Extract<Firewall, { kind: "windows" }>,
	l: Listener,
	iface: string,
): Verdict {
	const profile = fw.ifaceProfiles[iface] ?? "public";
	const settings = fw.profiles[profile];
	if (!settings.enabled)
		return fw.products.length
			? {
					result: "unknown",
					why: `Windows' firewall is off for the ${profile} profile; ${fw.products.join(", ")} filters instead, with rules nethound can't read`,
				}
			: {
					result: "open",
					why: `Windows' firewall is off for the ${profile} profile (${iface}'s)`,
				};
	if (settings.blockAll)
		return {
			result: "blocked",
			why: `Windows' firewall blocks every incoming connection on the ${profile} profile`,
		};
	const exe = l.process?.exe?.toLowerCase();
	const applies = fw.rules.filter(
		(r) =>
			r.profiles & PROFILE_BIT[profile] &&
			(r.proto === undefined || r.proto === l.proto) &&
			windowsPorts(r.ports, l.port) &&
			(r.program === undefined ||
				r.program === exe ||
				// the kernel's own (file sharing on 445): a program called System, with no path
				(r.program === "system" && l.process?.name === "System")) &&
			r.package === undefined &&
			// a service's rule is for svchost's
			(r.service === undefined || l.process?.name.toLowerCase() === "svchost"),
	);
	const block = applies.find((r) => !r.allow);
	if (block)
		return {
			result: "blocked",
			why: `Windows' firewall blocks it: rule "${block.name}"`,
		};
	const allow =
		applies.find((r) => r.allow && r.remote === "*") ??
		applies.find((r) => r.allow);
	if (allow)
		return allow.remote === "*"
			? {
					result: "open",
					why: `Windows' firewall lets it in: rule "${allow.name}"`,
				}
			: {
					result: "partial",
					why: `Windows' firewall lets it in from ${allow.remote} only: rule "${allow.name}"`,
				};
	return settings.defaultBlock
		? {
				result: "blocked",
				why: `Windows' firewall blocks it on the ${profile} profile: no rule lets it in`,
			}
		: {
				result: "open",
				why: `Windows' firewall lets in what no rule blocks, on the ${profile} profile`,
			};
}

function macVerdict(
	fw: Extract<Firewall, { kind: "macos" }>,
	l: Listener,
): Verdict {
	if (!fw.enabled) return { result: "open", why: "macOS's firewall is off" };
	if (fw.blockAll)
		return {
			result: "blocked",
			why: "macOS's firewall blocks every incoming connection",
		};
	const cmd = l.process?.cmd ?? "";
	const app = fw.apps.find((a) => cmd.startsWith(a.path));
	if (app)
		return app.allow
			? { result: "open", why: `macOS's firewall lets ${app.path} in` }
			: { result: "blocked", why: `macOS's firewall blocks ${app.path}` };
	if (fw.allowSigned && /^\/(System|usr)\//.test(cmd))
		return {
			result: "open",
			why: "macOS's firewall lets built-in software in",
		};
	return {
		result: "unknown",
		why: "macOS's firewall asks whether to let it in the first time it listens (or lets it in if it is signed)",
	};
}

/** Whether another machine can get in to a listener through `iface`, as the firewall says. */
export function verdictVia(
	snap: Snapshot,
	l: Listener,
	iface: string,
): Verdict | undefined {
	const fw = snap.firewall;
	if (!fw) return undefined;
	switch (fw.kind) {
		case "netfilter":
			return netfilterVerdict(fw, snap, l, iface);
		case "ufw":
			return ufwVerdict(fw, l);
		case "firewalld":
			return firewalldVerdict(fw, l, iface);
		case "windows":
			return windowsVerdict(fw, l, iface);
		case "macos":
			return macVerdict(fw, l);
		default:
			if (l.container && snap.environment !== "macos")
				return {
					result: "open",
					why: "docker's rules let published ports in (only a DOCKER-USER rule would stop it: sudo to read)",
				};
			return {
				result: "unknown",
				why: `unknown: its rules take ${snap.environment === "windows" ? "an administrator" : "sudo"} to read`,
			};
	}
}

/** The firewall's answer for every interface in `via`: open when one lets it in. */
export function verdictFor(
	snap: Snapshot,
	l: Listener,
	via: string[],
): Verdict | undefined {
	if (!snap.firewall) return undefined;
	// only this machine reaches it: not the firewall's business
	if (l.addresses.every(isLoopback)) return undefined;
	const vs = via.flatMap((i) => {
		const v = verdictVia(snap, l, i);
		return v ? [{ ...v, why: via.length > 1 ? `${i}: ${v.why}` : v.why }] : [];
	});
	return vs.length ? combine(vs) : undefined;
}
