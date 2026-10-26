import { expect, test } from "bun:test";
import { connections, listeners, map, routeTo, who } from "../src/analyze.ts";
import {
	listenerJson,
	mapJson,
	renderConnections,
	renderInterfaces,
	renderList,
	renderMap,
	renderRoute,
	renderWho,
} from "../src/format.ts";
import { fixture } from "./helpers.ts";

const snap = fixture();
const o = { color: false };

test("list", () => {
	expect(renderList(listeners(snap), o)).toBe(
		[
			"PORT      ADDRESS       REACHABLE FROM     CLIENTS  OWNER",
			"tcp 22    *             every interface    1        root's process (sudo to see it)",
			"udp 53    127.0.0.53    this machine only           systemd-resolve's process (sudo to see it)",
			"tcp 5000  127.0.0.1     this machine only  1        node 300",
			"tcp 5432  0.0.0.0       every interface             container pg :5432",
			"tcp 8080  192.168.1.10  eth0                        node 300",
		].join("\n"),
	);
});

test("in WSL, ports Windows reaches through its localhost say so", () => {
	const out = renderList(listeners(snap), { ...o, wsl: true });
	expect(out).toContain("this machine only + Windows");
	expect(out).toContain("every interface + Windows");
	// bound to eth0's address only: not forwarded
	expect(out).toMatch(/tcp 8080 +192\.168\.1\.10 +eth0 /);
});

test("the last column is cut to the terminal", () => {
	for (const line of renderList(listeners(snap), { ...o, width: 70 }).split(
		"\n",
	))
		expect(line.length).toBeLessThanOrEqual(70);
});

test("map", () => {
	const out = renderMap(map(snap), o);
	expect(out).toContain(
		"listening on every interface\n  tcp 22    root's process (sudo to see it)  ← 1 client",
	);
	expect(out).toContain("  local       curl 400 → :5000 node 300");
	expect(out).toContain("  out         curl 400 → 140.82.121.4:443");
	expect(out).toContain(
		"  holds       pg 172.18.0.2  listens 5432  ← host :5432",
	);
	// a namespace that is no container's
	expect(out).toContain(
		"in other network namespaces\n  tcp 8765  python3 610  0.0.0.0",
	);
	expect(out).toContain("  neighbours  192.168.1.1 gateway, 192.168.1.50\n");
	expect(out).toContain("down\n  docker0\n");
	expect(out).toContain(
		"dns servers\n  127.0.0.53   on this machine: systemd-resolved, which asks the others\n  192.168.1.1  on eth0's network",
	);
	expect(out).toContain("  listen      node 300  tcp 8080");
	// fe80:: on every interface says nothing
	expect(out).toContain("eth0  ethernet  up  192.168.1.10/24\n");
	// a closing socket is not a connection
	expect(out).not.toContain("closing");
});

test("map: no line wider than the terminal; a down adapter with only link-local addresses folded", () => {
	const wide = {
		...snap,
		interfaces: [
			...snap.interfaces,
			{
				name: "Connexion au réseau local* 3",
				index: 9,
				kind: "virtual" as const,
				description: "Microsoft Wi-Fi Direct Virtual Adapter #3",
				state: "down" as const,
				mtu: 1500,
				addresses: [
					{ family: 4 as const, address: "169.254.218.70", prefix: 16 },
					{
						family: 6 as const,
						address: "fe80::db2d:fecf:ff12:65ff",
						prefix: 64,
					},
				],
				members: [],
				rxBytes: 0,
				txBytes: 0,
			},
		],
	};
	const out = renderMap(map(wide), { ...o, width: 50 });
	for (const line of out.split("\n"))
		expect(line.length).toBeLessThanOrEqual(50);
	// folded with what it is, and what it is for
	expect(renderMap(map(wide), o)).toContain(
		"down\n  docker0\n  Connexion au réseau local* 3  Microsoft Wi-Fi Direct Virtual Adapter #3: Mobile Hotspot, casting to a screen (Miracast), Nearby Sharing",
	);
});

test("map: a link-local DNS server is said to be one, not given an interface", () => {
	const out = renderMap(map({ ...snap, dns: ["fe80::1"] }), o);
	expect(out).toContain(
		"dns servers\n  fe80::1  link-local: a router on the network that gave it",
	);
});

test("map: a busy network's neighbours cut to the terminal, the rest counted", () => {
	const lan = {
		...snap,
		neighbours: Array.from({ length: 40 }, (_, i) => ({
			address: `192.168.1.${100 + i}`,
			mac: "02:00:00:00:00:01",
			iface: "eth0",
		})),
	};
	const line = renderMap(map(lan), { ...o, width: 80 })
		.split("\n")
		.find((l) => l.startsWith("  neighbours"));
	expect(line).toBe(
		"  neighbours  192.168.1.100, 192.168.1.101, 192.168.1.102 and 37 more",
	);
});

test("who", () => {
	const out = renderWho(who(snap, 5000), o);
	expect(out).toContain("tcp 5000  node 300");
	expect(out).toContain("reachable  this machine only");
	expect(out).toContain("← 127.0.0.1:40000 curl 400");
	expect(renderWho(who(snap, 22), o)).toContain(
		"owned by root: run with sudo to see which process",
	);
	expect(renderWho(who(snap, 9), o)).toBe(
		"nothing listens on port 9, and nothing here talks to it",
	);
});

test("conns groups by process and names the other end", () => {
	const out = renderConnections(connections(snap), o);
	expect(out).toContain(
		"curl 400  2 connections\n  → 127.0.0.1:5000 node 300\n  → 140.82.121.4:443  via eth0 → 192.168.1.1",
	);
	expect(out).toContain(
		"node 300  1 connection\n  :5000 ← 127.0.0.1:40000 curl 400",
	);
	expect(out).toContain("closing, no process");
});

test("route", () => {
	expect(renderRoute(routeTo(snap, "8.8.8.8"), "dns.google", o)).toBe(
		[
			"dns.google (8.8.8.8)",
			"  is         beyond 192.168.1.1, the gateway on eth0",
			"  interface  eth0",
			"  route      default via 192.168.1.1 metric 100",
			"  from       192.168.1.10",
		].join("\n"),
	);
	expect(renderRoute(routeTo(snap, "172.18.0.2"), "172.18.0.2", o)).toContain(
		"container pg, on this machine",
	);
});

test("JSON has no cycles between listeners and their clients", () => {
	expect(() => JSON.stringify(mapJson(map(snap)))).not.toThrow();
	const [l] = listeners(snap)
		.filter((x) => x.port === 5000)
		.map(listenerJson);
	expect(l?.clients[0]?.peer).toMatchObject({
		kind: "local",
		process: { name: "curl" },
	});
});

test("interfaces: a VPN's hundreds of routes cut to the widest, its gateway said once", () => {
	const s = structuredClone(snap);
	s.interfaces.push({
		name: "tun0",
		index: 9,
		kind: "tun",
		state: "up",
		mtu: 1400,
		addresses: [{ family: 4, address: "10.8.0.2", prefix: 32 }],
		members: [],
		rxBytes: 0,
		txBytes: 0,
	});
	for (let n = 0; n < 200; n++)
		s.routes.push({
			family: 4,
			dest: `10.${n}.0.0`,
			prefix: n === 150 ? 8 : 24,
			gateway: "10.8.0.1",
			iface: "tun0",
			metric: 0,
		});
	const m = map(s);
	const out = renderInterfaces(
		m.interfaces,
		m.idle.map((i) => i.name),
		o,
	);
	expect(out).toContain("tun0  tun  up  10.8.0.2/32  VPN");
	expect(out).toContain(
		"routes     200 routes via 10.8.0.1: 10.150.0.0/8, 10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24, 10.3.0.0/24, 10.4.0.0/24 and 194 more",
	);
});
