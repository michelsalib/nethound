// Linux's firewall. As root, netfilter's rules themselves: iptables-save and ip6tables-save, which
// print iptables' rules whichever backend holds them (ufw's and docker's), and `nft -j`, for tables
// iptables doesn't write (firewalld's, /etc/nftables.conf). Without root, only what ufw's and
// firewalld's own files say: their rules are root's.

import { readdirSync } from "node:fs";
import { join } from "node:path";
import type {
	Family,
	Firewall,
	NfChain,
	NfMatch,
	NfRule,
	NfTable,
	Process,
} from "../model.ts";
import type { Run } from "../run.ts";

/** Splits a rule line, keeping "quoted words" whole. */
const words = (line: string) =>
	[...line.matchAll(/"((?:[^"\\]|\\.)*)"|(\S+)/g)].map(
		(m) => m[1] ?? m[2] ?? "",
	);

const TARGETS: Record<string, NfRule["verdict"]> = {
	ACCEPT: "accept",
	DROP: "drop",
	REJECT: "drop",
	RETURN: "return",
};
// targets that change nothing about whether a packet gets in: it goes on
const PASSIVE = new Set([
	"LOG",
	"NFLOG",
	"ULOG",
	"MARK",
	"CONNMARK",
	"TRACE",
	"AUDIT",
	"NOTRACK",
	"CT",
	"TCPMSS",
	"CHECKSUM",
	"DSCP",
	"TOS",
	"SET",
]);
// options that take no value
const FLAGS = new Set([
	"--syn",
	"--rcheck",
	"--update",
	"--set",
	"--remove",
	"--rsource",
	"--rttl",
]);
// matches that hold for every new connection, or only add a rate: logging's
const IGNORED = new Set([
	"--limit",
	"--limit-burst",
	"--comment",
	"--log-prefix",
	"--log-level",
]);

/** One `-A CHAIN …` line of iptables-save. */
export function parseIptablesRule(line: string): {
	chain: string;
	rule: NfRule;
} {
	const w = words(line);
	const chain = w[1] ?? "";
	const matches: NfMatch[] = [];
	// "DOCKER: -d 172.18.0.3/32 -p tcp --dport 5432 -j ACCEPT": the chain, without iptables' -m tcp
	const text = `${chain}: ${line
		.trim()
		.replace(/^-A \S+ /, "")
		.replace(/ -m (tcp|udp)(?= )/g, "")}`;
	const rule: NfRule = { matches, text };
	let not = false;
	const add = (kind: NfMatch["kind"], values: string[]) => {
		matches.push({ kind, values, ...(not && { not: true }) });
		not = false;
	};
	for (let i = 2; i < w.length; i++) {
		const opt = w[i] ?? "";
		const val = w[i + 1] ?? "";
		if (opt === "!") {
			not = true;
			continue;
		}
		switch (opt) {
			case "-p":
			case "--protocol":
				add("proto", [val.toLowerCase()]);
				i++;
				break;
			case "--dport":
			case "--destination-port":
				add("dport", [val]);
				i++;
				break;
			case "--dports":
			case "--destination-ports":
				add("dport", val.split(","));
				i++;
				break;
			case "-i":
			case "--in-interface":
				add("iif", [val]);
				i++;
				break;
			case "-o":
			case "--out-interface":
				add("oif", [val]);
				i++;
				break;
			case "-s":
			case "--source":
				add("saddr", val.split(","));
				i++;
				break;
			case "-d":
			case "--destination":
				add("daddr", val.split(","));
				i++;
				break;
			case "--ctstate":
			case "--state":
				add("ct", val.split(","));
				i++;
				break;
			case "--dst-type":
				add("dsttype", val.split(","));
				i++;
				break;
			case "-m":
			case "--match":
				// the module alone says nothing: its options do
				i++;
				break;
			case "-j":
			case "--jump":
			case "-g":
			case "--goto": {
				i++;
				const t = TARGETS[val];
				if (t) rule.verdict = t;
				else if (!PASSIVE.has(val)) {
					rule.verdict = opt === "-g" || opt === "--goto" ? "goto" : "jump";
					rule.target = val;
				}
				// a target's own options follow: --reject-with, --log-prefix
				i = w.length;
				break;
			}
			default:
				if (IGNORED.has(opt)) {
					i++;
					break;
				}
				if (!opt.startsWith("-")) break;
				// --sport, --icmp-type, -m recent's, marks: they depend on the client
				if (FLAGS.has(opt) || !val || val.startsWith("-")) add("other", [opt]);
				else {
					add("other", [opt, val]);
					i++;
				}
		}
	}
	return { chain, rule };
}

/** iptables-save's filter table, for IPv4 or (ip6tables-save) IPv6. */
export function parseIptablesSave(text: string, family: Family): NfTable[] {
	const out: NfTable[] = [];
	let table: NfTable | undefined;
	const chains = new Map<string, NfChain>();
	for (const line of text.split("\n")) {
		if (line.startsWith("*")) {
			chains.clear();
			table =
				line === "*filter" ? { family, name: "filter", chains: [] } : undefined;
			if (table) out.push(table);
			continue;
		}
		if (!table) continue;
		const head = line.match(/^:(\S+)\s+(\S+)/);
		if (head) {
			const [, name = "", policy = "-"] = head;
			const c: NfChain = {
				name,
				rules: [],
				...(name === "INPUT" && { hook: "input" as const }),
				...(name === "FORWARD" && { hook: "forward" as const }),
				...(policy !== "-" && {
					policy: policy === "ACCEPT" ? "accept" : ("drop" as const),
				}),
			};
			chains.set(name, c);
			table.chains.push(c);
			continue;
		}
		if (line.startsWith("-A ")) {
			const { chain, rule } = parseIptablesRule(line);
			chains.get(chain)?.rules.push(rule);
		}
	}
	return out;
}

// --- nft -j list ruleset ---

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type Obj = { [k: string]: Json };

const isObj = (j: Json | undefined): j is Obj =>
	!!j && typeof j === "object" && !Array.isArray(j);

/** A set, range, prefix or plain value on the right of a match, as text values. */
function values(j: Json | undefined, sets: Map<string, Json>): string[] {
	if (j === null || j === undefined) return [];
	if (typeof j === "string") {
		if (j.startsWith("@")) return values(sets.get(j.slice(1)) ?? [], sets);
		return [j];
	}
	if (typeof j === "number" || typeof j === "boolean") return [String(j)];
	if (Array.isArray(j)) return j.flatMap((x) => values(x, sets));
	if ("set" in j) return values(j.set, sets);
	if ("range" in j && Array.isArray(j.range))
		return [`${values(j.range[0], sets)[0]}-${values(j.range[1], sets)[0]}`];
	if ("prefix" in j && isObj(j.prefix))
		return [`${j.prefix.addr}/${j.prefix.len}`];
	if ("elem" in j && isObj(j.elem)) return values(j.elem.val, sets);
	return [JSON.stringify(j)];
}

/** What the left of a match is about, in NfMatch's terms. */
function kindOfLeft(left: Json | undefined): NfMatch["kind"] {
	if (!isObj(left)) return "other";
	const meta = isObj(left.meta) ? left.meta.key : undefined;
	if (meta === "l4proto") return "proto";
	if (meta === "iifname" || meta === "iif") return "iif";
	if (meta === "oifname" || meta === "oif") return "oif";
	if (meta === "nfproto") return "nfproto";
	if (isObj(left.ct) && left.ct.key === "state") return "ct";
	if (isObj(left.ct) && left.ct.key === "status") return "dnat";
	if (isObj(left.fib) && left.fib.result === "type") return "dsttype";
	if (isObj(left.payload)) {
		const field = left.payload.field;
		if (field === "dport") return "dport";
		if (field === "saddr") return "saddr";
		if (field === "daddr") return "daddr";
		if (field === "protocol" || field === "nexthdr") return "proto";
	}
	return "other";
}

/** The verdict statement of an nft rule, if it has one. */
function verdictOf(e: Obj): Pick<NfRule, "verdict" | "target"> | undefined {
	if ("accept" in e) return { verdict: "accept" };
	if ("drop" in e || "reject" in e) return { verdict: "drop" };
	if ("return" in e) return { verdict: "return" };
	for (const v of ["jump", "goto"] as const) {
		const t = e[v];
		if (isObj(t)) return { verdict: v, target: String(t.target) };
	}
	return undefined;
}

/** The left of a match as nft prints it: "tcp dport", "iifname", "ct state". */
function leftText(left: Json | undefined): string {
	if (!isObj(left)) return JSON.stringify(left);
	if (isObj(left.payload))
		return `${left.payload.protocol} ${left.payload.field}`;
	if (isObj(left.meta)) {
		const key = String(left.meta.key);
		return /^(iifname|oifname|iif|oif|l4proto|nfproto|mark)$/.test(key)
			? key === "l4proto" || key === "nfproto"
				? `meta ${key}`
				: key
			: `meta ${key}`;
	}
	if (isObj(left.ct)) return `ct ${left.ct.key}`;
	if (isObj(left.fib))
		return `fib ${[left.fib.flags].flat().join(" . ")} ${left.fib.result}`;
	return JSON.stringify(left);
}

const rightText = (vs: string[]) =>
	vs.length === 1 ? (vs[0] ?? "") : `{ ${vs.join(", ")} }`;

/** "ip saddr 10.0.0.0/8 tcp dport 5432 accept": a rule as nft prints it, counters and logs left out. */
function nftText(expr: Json[], sets: Map<string, Json>): string {
	const out: string[] = [];
	for (const e of expr) {
		if (!isObj(e)) continue;
		if (isObj(e.match)) {
			const op = e.match.op === "!=" ? "!= " : "";
			out.push(
				`${leftText(e.match.left)} ${op}${rightText(values(e.match.right, sets))}`,
			);
		} else if (isObj(e.vmap)) out.push(`${leftText(e.vmap.key)} vmap { … }`);
		else if ("reject" in e) out.push("reject");
		else {
			const v = verdictOf(e);
			if (v) out.push(`${v.verdict}${v.target ? ` ${v.target}` : ""}`);
		}
	}
	return out.join(" ");
}

/** What a payload match says on its own: "tcp dport" is about tcp, "ip saddr" about IPv4. */
function implied(left: Json | undefined): NfMatch[] {
	const proto =
		isObj(left) && isObj(left.payload) ? left.payload.protocol : undefined;
	if (typeof proto !== "string" || proto === "th") return [];
	if (proto === "ip") return [{ kind: "nfproto", values: ["ipv4"] }];
	if (proto === "ip6") return [{ kind: "nfproto", values: ["ipv6"] }];
	if (proto === "ether" || proto === "vlan" || proto === "arp") return [];
	return [{ kind: "proto", values: [proto] }];
}

function parseNftRule(expr: Json[], sets: Map<string, Json>): NfRule {
	const rule: NfRule = { matches: [], text: "" };
	for (const e of expr) {
		if (!isObj(e)) continue;
		if (isObj(e.match)) {
			rule.matches.push(...implied(e.match.left));
			let kind = kindOfLeft(e.match.left);
			// ct status: only dnat says something about where the packet goes
			if (kind === "dnat" && !values(e.match.right, sets).includes("dnat"))
				kind = "other";
			const op = e.match.op;
			rule.matches.push({
				kind,
				values:
					kind === "other"
						? [JSON.stringify(e.match.left)]
						: values(e.match.right, sets),
				...(op === "!=" && { not: true }),
			});
			continue;
		}
		if (isObj(e.vmap)) {
			const entries: [string[], NfRule][] = [];
			const data = isObj(e.vmap.data) ? e.vmap.data.set : undefined;
			for (const pair of Array.isArray(data) ? data : []) {
				if (!Array.isArray(pair) || !isObj(pair[1])) continue;
				const v = verdictOf(pair[1]);
				if (v)
					entries.push([
						values(pair[0], sets),
						{ matches: [], text: "", ...v },
					]);
			}
			rule.vmap = { key: kindOfLeft(e.vmap.key), entries };
			continue;
		}
		const v = verdictOf(e);
		if (v) Object.assign(rule, v);
	}
	rule.text = nftText(expr, sets);
	return rule;
}

const FAMILIES: Record<string, Family | "both"> = {
	ip: 4,
	ip6: 6,
	inet: "both",
};

/** `nft -j list ruleset`: the filter chains of ip, ip6 and inet tables. `skip`: tables iptables-save
 * already read (iptables-nft's, in the ip and ip6 families). */
export function parseNftRuleset(
	json: string,
	skip: Set<string> = new Set(),
): NfTable[] {
	let items: Json[];
	try {
		const data = JSON.parse(json);
		items = Array.isArray(data?.nftables) ? data.nftables : [];
	} catch {
		return [];
	}
	const tables = new Map<string, NfTable>();
	const key = (o: Obj) => `${o.family} ${o.table ?? o.name}`;
	const sets = new Map<string, Json>();
	for (const item of items) {
		if (!isObj(item)) continue;
		if (isObj(item.table)) {
			const family = FAMILIES[String(item.table.family)];
			if (!family || skip.has(key(item.table))) continue;
			tables.set(key(item.table), {
				family,
				name: String(item.table.name),
				chains: [],
			});
		} else if (isObj(item.set))
			sets.set(String(item.set.name), item.set.elem ?? []);
	}
	const chains = new Map<string, NfChain>();
	for (const item of items) {
		if (!isObj(item) || !isObj(item.chain)) continue;
		const c = item.chain;
		const t = tables.get(key(c));
		if (!t) continue;
		const hook =
			c.type === "filter" && (c.hook === "input" || c.hook === "forward")
				? c.hook
				: undefined;
		const chain: NfChain = {
			name: String(c.name),
			rules: [],
			...(hook && {
				hook,
				priority: typeof c.prio === "number" ? c.prio : 0,
				policy: c.policy === "drop" ? "drop" : "accept",
			}),
		};
		t.chains.push(chain);
		chains.set(`${key(c)} ${c.name}`, chain);
	}
	for (const item of items) {
		if (!isObj(item) || !isObj(item.rule)) continue;
		const r = item.rule;
		const chain = chains.get(`${r.family} ${r.table} ${r.chain}`);
		if (chain && Array.isArray(r.expr))
			chain.rules.push(parseNftRule(r.expr, sets));
	}
	return [...tables.values()];
}

/** Who wrote the rules: ufw, firewalld, docker alone, or by hand with nftables or iptables. */
function writer(tables: NfTable[]): string {
	const names = tables.flatMap((t) => [t.name, ...t.chains.map((c) => c.name)]);
	if (names.some((n) => n.startsWith("ufw-"))) return "ufw";
	if (names.some((n) => n === "firewalld" || n.startsWith("filter_IN_")))
		return "firewalld";
	if (tables.some((t) => t.family === "both")) return "nftables";
	const input = tables.flatMap((t) =>
		t.chains.filter((c) => c.hook === "input"),
	);
	if (
		names.includes("DOCKER") &&
		!input.some((c) => c.rules.length || c.policy === "drop")
	)
		return "docker";
	return "iptables";
}

/** As root: netfilter's rules. */
export function readNetfilter(run: Run): Firewall | undefined {
	const v4 = run("iptables-save", []);
	const v6 = run("ip6tables-save", []);
	const tables = [...parseIptablesSave(v4, 4), ...parseIptablesSave(v6, 6)];
	// iptables-nft's tables are in nft too: read once
	const skip = new Set<string>();
	if (v4.trim())
		for (const n of ["filter", "nat", "mangle", "raw", "security"])
			skip.add(`ip ${n}`);
	if (v6.trim())
		for (const n of ["filter", "nat", "mangle", "raw", "security"])
			skip.add(`ip6 ${n}`);
	tables.push(...parseNftRuleset(run("nft", ["-j", "list", "ruleset"]), skip));
	if (!v4.trim() && !v6.trim() && !tables.length) return undefined;
	return { kind: "netfilter", name: writer(tables), tables };
}

/** /etc/ufw/ufw.conf and /etc/default/ufw, which anyone can read. */
export function readUfw(read: (p: string) => string): Firewall | undefined {
	const conf = read("etc/ufw/ufw.conf");
	if (!conf) return undefined;
	const policy = read("etc/default/ufw").match(
		/^DEFAULT_INPUT_POLICY="?(\w+)/m,
	)?.[1];
	return {
		kind: "ufw",
		enabled: /^ENABLED=yes/m.test(conf),
		defaultBlock: policy !== "ACCEPT",
	};
}

const attr = (tag: string, name: string) =>
	tag.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1];

/** firewalld's zones and services, from /etc/firewalld over /usr/lib/firewalld. */
export function readFirewalld(
	read: (p: string) => string,
	list: (dir: string) => string[],
): Firewall {
	const file = (kind: string, name: string) =>
		read(`etc/firewalld/${kind}/${name}.xml`) ||
		read(`usr/lib/firewalld/${kind}/${name}.xml`);
	const service = (name: string) =>
		[...file("services", name).matchAll(/<port\b[^>]*>/g)].map(
			(m) => `${attr(m[0], "protocol")}/${attr(m[0], "port")}`,
		);
	const conf = read("etc/firewalld/firewalld.conf");
	const defaultZone = conf.match(/^DefaultZone=(\S+)/m)?.[1] ?? "public";
	const names = new Set(
		[...list("etc/firewalld/zones"), ...list("usr/lib/firewalld/zones")]
			.filter((f) => f.endsWith(".xml"))
			.map((f) => f.slice(0, -4)),
	);
	const zones = [...names].map((name) => {
		const xml = file("zones", name);
		const zone = xml.match(/<zone\b[^>]*>/)?.[0] ?? "";
		return {
			name,
			target: attr(zone, "target") ?? "default",
			ports: [
				...[...xml.matchAll(/<service\b[^>]*>/g)].flatMap((m) =>
					service(attr(m[0], "name") ?? ""),
				),
				// a zone's own ports: <port>, not those of its rich rules
				...[
					...xml
						.replace(/<rule\b[\s\S]*?<\/rule>/g, "")
						.matchAll(/<port\b[^>]*>/g),
				].map((m) => `${attr(m[0], "protocol")}/${attr(m[0], "port")}`),
			],
			interfaces: [...xml.matchAll(/<interface\b[^>]*>/g)].map(
				(m) => attr(m[0], "name") ?? "",
			),
			rich: [...xml.matchAll(/<rule\b/g)].length,
		};
	});
	return { kind: "firewalld", defaultZone, zones };
}

/** The firewall, as far as this user can read it. */
export function readLinuxFirewall(
	root: string,
	read: (p: string) => string,
	run: Run,
	processes: Process[],
	uid: number | undefined,
): Firewall {
	if (uid === 0) {
		const nf = readNetfilter(run);
		if (nf) return nf;
	}
	const list = (dir: string) => {
		try {
			return readdirSync(join(root, dir));
		} catch {
			return [];
		}
	};
	if (processes.some((p) => p.name === "firewalld"))
		return readFirewalld(read, list);
	return readUfw(read) ?? { kind: "unknown" };
}
