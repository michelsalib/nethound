import { expect, test } from "bun:test";
import { connections, listeners, map, routeTo, who } from "../src/analyze.ts";
import {
	listenerJson,
	mapJson,
	renderConnections,
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
	expect(out).toContain("  local   curl 400 → :5000 node 300");
	expect(out).toContain("  out     curl 400 → 140.82.121.4:443");
	expect(out).toContain("  holds   pg 172.18.0.2  listens 5432  ← host :5432");
	// a namespace that is no container's
	expect(out).toContain(
		"in other network namespaces\n  tcp 8765  python3 610  0.0.0.0",
	);
	expect(out).toContain("down, no address: docker0");
	// a closing socket is not a connection
	expect(out).not.toContain("closing");
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
