import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { listeners, who } from "../src/analyze.ts";
import { collect } from "../src/collect.ts";
import { parseListApps, readMacFirewall } from "../src/darwin/firewall.ts";
import { doctor } from "../src/doctor.ts";
import { verdictFor, verdictVia } from "../src/firewall.ts";
import { renderWho } from "../src/format.ts";
import {
	parseIptablesRule,
	parseIptablesSave,
	parseNftRuleset,
	readFirewalld,
	readNetfilter,
	readUfw,
} from "../src/linux/firewall.ts";
import type { Firewall, Snapshot } from "../src/model.ts";
import { parseFirewall } from "../src/windows/collect.ts";
import { fixture, windowsFixture } from "./helpers.ts";

const dir = join(import.meta.dir, "fixtures", "firewall");
const file = (p: string) => readFileSync(join(dir, p), "utf8");

/** The Linux fixture behind a firewall: sshd on 22, a container on 5432, node on eth0:8080. */
function behind(firewall: Firewall): Snapshot {
	const snap = structuredClone(fixture());
	snap.firewall = firewall;
	return snap;
}

const listener = (snap: Snapshot, port: number, proto = "tcp") => {
	const l = listeners(snap).find((x) => x.port === port && x.proto === proto);
	if (!l) throw new Error(`no listener on ${proto} ${port}`);
	return l;
};

/** The recorded ufw's rules, with what the fixture's sshd and node listen on. */
const ufw = (): Firewall => ({
	kind: "netfilter",
	name: "ufw",
	tables: [
		...parseIptablesSave(file("ufw/iptables-save.txt"), 4),
		...parseIptablesSave(file("ufw/ip6tables-save.txt"), 6),
	],
});

test("iptables-save's rules, in the terms a new connection is judged by", () => {
	const { chain, rule } = parseIptablesRule(
		'-A ufw-user-input -s 10.0.0.0/8 -p tcp -m tcp --dport 5432 -m comment --comment "a b" -j ACCEPT',
	);
	expect(chain).toBe("ufw-user-input");
	expect(rule).toEqual({
		matches: [
			{ kind: "saddr", values: ["10.0.0.0/8"] },
			{ kind: "proto", values: ["tcp"] },
			{ kind: "dport", values: ["5432"] },
		],
		verdict: "accept",
		text: 'ufw-user-input: -s 10.0.0.0/8 -p tcp --dport 5432 -m comment --comment "a b" -j ACCEPT',
	});
	expect(
		parseIptablesRule("-A DOCKER ! -i br-x -o br-x -j DROP").rule.matches,
	).toEqual([
		{ kind: "iif", values: ["br-x"], not: true },
		{ kind: "oif", values: ["br-x"] },
	]);
	expect(parseIptablesRule("-A INPUT -j ufw-before-input").rule).toMatchObject({
		verdict: "jump",
		target: "ufw-before-input",
	});
	expect(
		parseIptablesRule('-A X -j LOG --log-prefix "[UFW] "').rule.verdict,
	).toBeUndefined();
});

test("ufw, as root: its own rules, a source-limited one, its deny, and its default", () => {
	const snap = behind(ufw());
	snap.processes.push({ pid: 600, name: "redis-server", cmd: "redis-server" });
	snap.sockets.push({
		proto: "tcp",
		family: 4,
		local: { address: "0.0.0.0", port: 6379 },
		remote: { address: "0.0.0.0", port: 0 },
		state: "LISTEN",
		pid: 600,
	});
	const v = (port: number) => verdictVia(snap, listener(snap, port), "eth0");
	expect(v(22)).toEqual({
		result: "open",
		why: "ufw's rules let it in: ufw-user-input: -p tcp --dport 22 -j ACCEPT",
	});
	expect(v(6379)).toEqual({
		result: "blocked",
		why: "ufw's rules block it: ufw-user-input: -p tcp --dport 6379 -j DROP",
	});
	expect(v(8080)).toEqual({
		result: "blocked",
		why: "ufw blocks it: no rule lets it in, and INPUT's policy is DROP",
	});
	// published by docker: forwarded, and ufw's forward chain drops it (no docker here)
	expect(v(5432)?.result).toBe("blocked");
	// from the loopback, ufw lets everything in
	expect(verdictVia(snap, listener(snap, 8080), "lo")?.result).toBe("open");
	snap.sockets.push({
		proto: "tcp",
		family: 4,
		local: { address: "0.0.0.0", port: 5433 },
		remote: { address: "0.0.0.0", port: 0 },
		state: "LISTEN",
		pid: 600,
	});
	const fw = snap.firewall as Extract<Firewall, { kind: "netfilter" }>;
	const user = fw.tables[0]?.chains.find((c) => c.name === "ufw-user-input");
	user?.rules.unshift(
		parseIptablesRule(
			"-A ufw-user-input -s 10.0.0.0/8 -p tcp --dport 5433 -j ACCEPT",
		).rule,
	);
	expect(v(5433)).toEqual({
		result: "partial",
		why: "ufw lets it in only from 10.0.0.0/8: ufw-user-input: -s 10.0.0.0/8 -p tcp --dport 5433 -j ACCEPT",
	});
});

test("firewalld, from nft: zone ports, a rich rule, multicast mDNS, and the final reject", () => {
	const tables = parseNftRuleset(file("firewalld/nft.json"));
	const snap = behind({ kind: "netfilter", name: "firewalld", tables });
	snap.processes.push({ pid: 700, name: "python3", cmd: "python3" });
	for (const [proto, port] of [
		["tcp", 22],
		["tcp", 5432],
		["udp", 5353],
	] as const)
		snap.sockets.push({
			proto,
			family: 4,
			local: { address: "0.0.0.0", port },
			remote: { address: "0.0.0.0", port: 0 },
			state: proto === "tcp" ? "LISTEN" : "UNCONN",
			pid: 700,
		});
	snap.containers = [];
	const v = (port: number, proto = "tcp") =>
		verdictVia(snap, listener(snap, port, proto), "eth0");
	expect(v(22)).toEqual({
		result: "open",
		why: "firewalld's rules let it in: tcp dport 22 accept",
	});
	expect(v(5432)).toEqual({
		result: "partial",
		why: "firewalld lets it in only from 10.0.0.0/8: ip saddr 10.0.0.0/8 tcp dport 5432 accept",
	});
	expect(v(8080)?.why).toBe(
		"firewalld's rules let it in: tcp dport 8080 accept",
	);
	// the zone takes mDNS to its multicast address only: not to this machine's own
	expect(v(5353, "udp")).toEqual({
		result: "blocked",
		why: "firewalld blocks it: no rule lets it in, and filter_INPUT_POLICIES ends with reject",
	});
});

test("docker's own rules: a published port is forwarded; DOCKER-USER can stop it", () => {
	const tables = parseIptablesSave(file("docker-iptables-save.txt"), 4);
	// the fixture's pg on br-abc, at 172.18.0.2, as docker's rules would name it
	const chain = (name: string) =>
		tables[0]?.chains.find((c) => c.name === name);
	chain("DOCKER-BRIDGE")?.rules.push(
		parseIptablesRule("-A DOCKER-BRIDGE -o br-abc -j DOCKER").rule,
	);
	const docker = chain("DOCKER");
	docker?.rules.unshift(
		parseIptablesRule(
			"-A DOCKER -d 172.18.0.2/32 ! -i br-abc -o br-abc -p tcp -m tcp --dport 5432 -j ACCEPT",
		).rule,
	);
	const snap = behind({ kind: "netfilter", name: "docker", tables });
	const pg = listener(snap, 5432);
	expect(verdictVia(snap, pg, "eth0")).toEqual({
		result: "open",
		why: "docker's rules let it in: DOCKER: -d 172.18.0.2/32 ! -i br-abc -o br-abc -p tcp --dport 5432 -j ACCEPT",
	});
	expect(verdictVia(snap, listener(snap, 8080), "eth0")).toEqual({
		result: "open",
		why: "no rule filters incoming connections",
	});
	tables[0]?.chains
		.find((c) => c.name === "DOCKER-USER")
		?.rules.push(parseIptablesRule("-A DOCKER-USER -i eth0 -j DROP").rule);
	expect(verdictVia(snap, pg, "eth0")?.result).toBe("blocked");
});

test("as root, iptables-save then nft; tables iptables wrote are read once", () => {
	const run = (cmd: string, args: string[]) =>
		cmd === "iptables-save"
			? file("ufw/iptables-save.txt")
			: cmd === "ip6tables-save"
				? file("ufw/ip6tables-save.txt")
				: cmd === "nft" && args.join(" ") === "-j list ruleset"
					? file("firewalld/nft.json")
					: "";
	const fw = readNetfilter(run);
	expect(fw).toMatchObject({ kind: "netfilter", name: "ufw" });
	// ufw's two filter tables, and firewalld's inet one (its ip and ip6 tables are skipped)
	expect(
		fw?.kind === "netfilter" && fw.tables.map((t) => `${t.family} ${t.name}`),
	).toEqual(["4 filter", "6 filter", "both firewalld"]);
	expect(readNetfilter(() => "")).toBeUndefined();
});

test("without root: ufw's settings, firewalld's zones", () => {
	const ufwFiles: Record<string, string> = {
		"etc/ufw/ufw.conf": file("ufw/ufw.conf"),
		"etc/default/ufw": file("ufw/default-ufw"),
	};
	const fw = readUfw((p) => ufwFiles[p] ?? "");
	expect(fw).toEqual({ kind: "ufw", enabled: true, defaultBlock: true });
	const snap = behind(fw as Firewall);
	expect(verdictVia(snap, listener(snap, 8080), "eth0")?.result).toBe(
		"unknown",
	);
	// docker publishes around it
	expect(verdictVia(snap, listener(snap, 5432), "eth0")?.why).toStartWith(
		"ufw is on, but docker's rules let published ports in",
	);
	expect(readUfw(() => "")).toBeUndefined();

	const root = join(dir, "firewalld");
	const read = (p: string) => {
		try {
			return readFileSync(join(root, p), "utf8");
		} catch {
			return "";
		}
	};
	const list = (d: string) => (d.endsWith("zones") ? ["public.xml"] : []);
	const fd = readFirewalld(read, list);
	expect(fd).toEqual({
		kind: "firewalld",
		defaultZone: "public",
		zones: [
			{
				name: "public",
				target: "default",
				ports: ["tcp/22", "udp/5353", "udp/546", "tcp/80", "tcp/8080"],
				interfaces: [],
				rich: 1,
			},
		],
	});
	const s2 = behind(fd);
	expect(verdictVia(s2, listener(s2, 8080), "eth0")).toEqual({
		result: "open",
		why: "firewalld's zone public opens tcp/8080",
	});
	expect(verdictVia(s2, listener(s2, 22), "eth0")?.result).toBe("open");
	s2.processes.push({ pid: 1, name: "x", cmd: "x" });
	s2.sockets.push({
		proto: "tcp",
		family: 4,
		local: { address: "0.0.0.0", port: 9999 },
		remote: { address: "0.0.0.0", port: 0 },
		state: "LISTEN",
		pid: 1,
	});
	expect(verdictVia(s2, listener(s2, 9999), "eth0")?.result).toBe("partial");
});

test("Windows: profiles, program rules, block before allow, sources, Store apps", () => {
	const fw = parseFirewall({
		profiles: [
			[true, false, 0],
			[true, false, 0],
			[true, true, 0],
		],
		rules: [
			[
				"Node.js",
				1,
				6,
				"*",
				"C:\\Program Files\\nodejs\\node.exe",
				"",
				7,
				"LocalSubnet",
				"",
			],
			["Postgres", 1, 6, "5432", "", "", 7, "*", ""],
			["No postgres here", 0, 6, "5432", "", "", 2, "*", ""],
			["Some Store app", 1, 256, "", "", "", 7, "*", "S-1-15-2-1"],
			["RPC", 1, 6, "RPC", "", "", 7, "*", ""],
		],
		networks: [
			["Ethernet", "DomainAuthenticated"],
			["Wi-Fi", "Private"],
		],
		products: [],
	});
	expect(fw).toMatchObject({
		kind: "windows",
		ifaceProfiles: { Ethernet: "domain", "Wi-Fi": "private" },
	});
	const snap = structuredClone(windowsFixture());
	snap.firewall = fw;
	const node = listeners(snap).find(
		(l) => l.process?.name === "node" && l.port === 3000,
	);
	if (!node?.process) throw new Error("no node in the fixture");
	node.process.exe = "C:\\Program Files\\nodejs\\node.exe";
	expect(verdictVia(snap, node, "Ethernet")).toEqual({
		result: "partial",
		why: 'Windows\' firewall lets it in from LocalSubnet only: rule "Node.js"',
	});
	const pg = listeners(snap).find((l) => l.port === 5432);
	if (!pg) throw new Error("no postgres in the fixture");
	// on 127.0.0.1: not the firewall's business
	expect(verdictFor(snap, pg, ["Ethernet"])).toBeUndefined();
	pg.addresses = ["0.0.0.0"];
	expect(verdictVia(snap, pg, "Ethernet")?.why).toBe(
		'Windows\' firewall lets it in: rule "Postgres"',
	);
	expect(verdictVia(snap, pg, "Wi-Fi")?.why).toBe(
		'Windows\' firewall blocks it: rule "No postgres here"',
	);
	// no profile: public, which blocks everything
	expect(verdictVia(snap, pg, "vEthernet (WSL)")?.why).toBe(
		"Windows' firewall blocks every incoming connection on the public profile",
	);
	// neither the Store app's rule nor RPC's applies to another port
	const other = { ...pg, port: 7000 };
	expect(verdictVia(snap, other, "Ethernet")?.why).toBe(
		"Windows' firewall blocks it on the domain profile: no rule lets it in",
	);
	if (fw.kind === "windows") {
		fw.profiles.domain.enabled = false;
		expect(verdictVia(snap, other, "Ethernet")?.result).toBe("open");
		fw.products.push("FortiClient");
		expect(verdictVia(snap, other, "Ethernet")?.why).toContain(
			"FortiClient filters instead",
		);
	}
});

test("macOS: the application firewall's state and apps", () => {
	expect(
		parseListApps(`ALF: total number of apps = 2 

1 :  /Applications/Docker.app 
 	 ( Allow incoming connections ) 

2 :  /usr/local/bin/node 
 	 ( Block incoming connections ) 
`),
	).toEqual([
		{ path: "/Applications/Docker.app", allow: true },
		{ path: "/usr/local/bin/node", allow: false },
	]);
	const answers: Record<string, string> = {
		"--getglobalstate": "Firewall is enabled. (State = 1)",
		"--getblockall": "Firewall has block all state set to disabled.",
		"--getallowsigned":
			"Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software DISABLED.",
		"--listapps":
			"ALF: total number of apps = 1 \n\n1 :  /usr/local/bin/node \n \t ( Block incoming connections ) \n",
	};
	const fw = readMacFirewall((_cmd, args) => answers[args[0] ?? ""] ?? "");
	expect(fw).toEqual({
		kind: "macos",
		enabled: true,
		blockAll: false,
		allowSigned: true,
		apps: [{ path: "/usr/local/bin/node", allow: false }],
	});
	const off = readMacFirewall(() => "Firewall is disabled. (State = 0)");
	expect(off).toMatchObject({ enabled: false, blockAll: false });
	expect(readMacFirewall(() => "")).toBeUndefined();
});

test("doctor: what the firewall blocks is a note; what it lets in says so", () => {
	const snap = behind(ufw());
	snap.processes.push({ pid: 800, name: "postgres", cmd: "postgres" });
	snap.sockets.push({
		proto: "tcp",
		family: 4,
		local: { address: "0.0.0.0", port: 5433 },
		remote: { address: "0.0.0.0", port: 0 },
		state: "LISTEN",
		pid: 800,
	});
	const f = doctor(snap).find((x) => x.port === 5433);
	expect(f).toMatchObject({
		severity: "info",
		title:
			"PostgreSQL on tcp 5433 is bound to every interface, but the firewall blocks it",
	});
	expect(f?.details).toContain(
		"firewall: ufw blocks it: no rule lets it in, and INPUT's policy is DROP",
	);
	// no firewall read: as before
	const plain = structuredClone(snap);
	plain.firewall = undefined;
	expect(doctor(plain).find((x) => x.port === 5433)?.details[1]).toEndWith(
		"unless a firewall stops it",
	);
	// who shows it too
	const text = renderWho(who(snap, 22), { color: false }, snap);
	expect(text).toContain(
		"firewall   lets other machines in: ufw's rules let it in: ufw-user-input: -p tcp --dport 22 -j ACCEPT",
	);
});

// the real firewalls of CI's machines: what each system prints is read
test.skipIf(process.platform !== "darwin")(
	"macOS: socketfilterfw, live",
	() => {
		const raw = Bun.spawnSync([
			"/usr/libexec/ApplicationFirewall/socketfilterfw",
			"--getglobalstate",
		]).stdout.toString();
		const fw = readMacFirewall((cmd, args) =>
			Bun.spawnSync([cmd, ...args]).stdout.toString(),
		);
		// says what it printed, if it isn't read
		expect({ raw, fw: fw?.kind }).toEqual({ raw, fw: "macos" });
		expect(typeof (fw?.kind === "macos" && fw.enabled)).toBe("boolean");
	},
);

test.skipIf(process.platform !== "win32")("Windows: the firewall, live", () => {
	const snap = collect({ platform: "win32", containers: [], firewall: true });
	expect(snap.firewall?.kind).toBe("windows");
	if (snap.firewall?.kind === "windows")
		expect(Object.keys(snap.firewall.profiles)).toEqual([
			"domain",
			"private",
			"public",
		]);
});
