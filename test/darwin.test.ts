// macOS, from recorded command output: test/fixtures/macos.
import { expect, test } from "bun:test";
import { connections, listeners, routeTo, unowned } from "../src/analyze.ts";
import {
	elapsed,
	parseLsof,
	parseNetstatSockets,
	parsePs,
} from "../src/darwin/collect.ts";
import { macFixture } from "./helpers.ts";

const snap = macFixture();
const by = Object.fromEntries(snap.interfaces.map((i) => [i.name, i]));

test("neighbours: from arp -an, MACs padded, unresolved, broadcast and multicast left out", () => {
	expect(snap.neighbours).toEqual([
		{ address: "192.168.1.1", mac: "3c:22:fb:aa:bb:cc", iface: "en0" },
		{ address: "192.168.1.42", mac: "08:00:27:01:02:03", iface: "en0" },
	]);
});

test("interfaces: kinds from names and networksetup, state from status:, bridge members", () => {
	expect(snap.environment).toBe("macos");
	expect(snap.interfaces.map((i) => `${i.name} ${i.kind} ${i.state}`)).toEqual([
		"lo0 loopback up",
		"gif0 virtual down",
		"stf0 virtual down",
		"en0 wifi up",
		"en1 ethernet down",
		"bridge0 bridge down",
		"awdl0 virtual up",
		"utun4 tun up",
	]);
	expect(by.en0).toMatchObject({
		index: 11,
		mtu: 1500,
		mac: "3c:22:fb:12:34:56",
		rxBytes: 1234567890,
		txBytes: 987654321,
	});
	expect(by.en0?.addresses).toContainEqual({
		family: 4,
		address: "192.168.1.20",
		prefix: 24,
	});
	expect(by.lo0?.addresses).toContainEqual({
		family: 6,
		address: "fe80::1",
		prefix: 64,
	});
	// a point-to-point address: "inet 10.8.0.2 --> 10.8.0.2 netmask 0xffff0000"
	expect(by.utun4?.addresses).toEqual([
		{ family: 4, address: "10.8.0.2", prefix: 16 },
	]);
	expect(by.utun4?.rxBytes).toBe(100000);
	expect(by.bridge0?.members).toEqual(["en1"]);
	expect(by.en1?.master).toBe("bridge0");
});

test("routes: abbreviated networks, no neighbours, scoped copies, multicast or broadcast", () => {
	expect(
		snap.routes.map(
			(r) => `${r.dest}/${r.prefix} ${r.gateway ?? "-"} ${r.iface}`,
		),
	).toEqual([
		"0.0.0.0/0 192.168.1.1 en0",
		"10.8.0.0/16 - utun4",
		"127.0.0.0/8 - lo0",
		"127.0.0.1/32 - lo0",
		"169.254.0.0/16 - en0",
		"192.168.1.0/24 - en0",
		"::/0 fe80::1 en0",
		"2001:db8::/64 - en0",
	]);
	expect(routeTo(snap, "140.82.121.4")).toMatchObject({
		kind: "gateway",
		iface: "en0",
		gateway: "192.168.1.1",
		source: "192.168.1.20",
	});
	expect(routeTo(snap, "10.8.3.4")).toMatchObject({
		kind: "network",
		iface: "utun4",
	});
	expect(routeTo(snap, "127.0.0.1").iface).toBe("lo0");
});

test("netstat sockets: tcp46 takes both families, tcp6 on * IPv6 only, udp has no state", () => {
	const s =
		parseNetstatSockets(`tcp46      0      0  *.8080                 *.*                    LISTEN
tcp6       0      0  *.9090                 *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.5432       *.*                    LISTEN
udp4       0      0  192.168.1.20.60000     192.168.1.1.53
udp6       0      0  *.5353                 *.*                               `);
	expect(
		s.map((x) => [x.proto, x.local.address, x.local.port, x.state, !!x.v6only]),
	).toEqual([
		["tcp", "::", 8080, "LISTEN", false],
		["tcp", "::", 9090, "LISTEN", true],
		["tcp", "fe80::1", 5432, "LISTEN", false],
		["udp", "192.168.1.20", 60000, "ESTABLISHED", false],
		["udp", "::", 5353, "UNCONN", true],
	]);
});

test("lsof: processes by socket, with their uid", () => {
	expect(
		parseLsof(
			"p7\nu501\nf3\ntIPv6\nPTCP\nn[::1]:5000\nf4\ntIPv4\nPUDP\nn*:5353\n",
		),
	).toEqual([
		{
			pid: 7,
			uid: 501,
			proto: "tcp",
			local: { address: "::1", port: 5000 },
			remote: undefined,
		},
		{
			pid: 7,
			uid: 501,
			proto: "udp",
			local: { address: "0.0.0.0", port: 5353 },
			remote: undefined,
		},
	]);
});

test("without root: our sockets have their process, other users' none, and say so", () => {
	const ls = Object.fromEntries(
		listeners(snap).map((l) => [`${l.proto} ${l.port}`, l]),
	);
	expect(ls["tcp 8080"]?.process?.cmd).toBe("node server.js --token=s3cret");
	expect(ls["tcp 8080"]?.user).toBe("me");
	expect(ls["tcp 8080"]?.reach.ipv6Only).toBeUndefined();
	// tcp6 on *: IPv6 only, so not the interfaces with only IPv4
	expect(ls["tcp 9090"]?.reach).toMatchObject({
		scope: "everywhere",
		ipv6Only: true,
	});
	expect(ls["tcp 9090"]?.reach.interfaces).not.toContain("utun4");
	expect(ls["tcp 9090"]?.process?.name).toBe("My App");
	expect(ls["tcp 5000"]?.reach).toEqual({
		scope: "local",
		interfaces: ["lo0"],
	});
	expect(ls["tcp 5432"]?.process).toBeUndefined();
	expect(ls["tcp 5432"]?.user).toBeUndefined();
	// the server's end of the connection; the client is at the other end
	expect(
		ls["tcp 5432"]?.clients.map(
			(c) => c.peer.kind === "local" && c.peer.process?.name,
		),
	).toEqual(["node"]);
	expect(ls["tcp 22"]?.addresses).toEqual(["0.0.0.0", "::"]);
	// postgres' end of node's connection, sshd and mDNSResponder (twice); TIME_WAIT is nobody's
	expect(unowned(snap)).toBe(6);
	const out = connections(snap).filter((c) => c.direction === "out");
	expect(
		out.map(
			(c) =>
				`${c.process?.name ?? "-"} ${c.remote.address}:${c.remote.port} ${c.state}`,
		),
	).toEqual([
		"curl 140.82.121.4:443 ESTABLISHED",
		"node 127.0.0.1:5432 ESTABLISHED",
		"- 140.82.121.4:443 TIME_WAIT",
		"curl 192.168.1.1:53 ESTABLISHED",
	]);
});

test("processes and users from ps; DNS from /etc/resolv.conf", () => {
	expect(snap.processes.find((p) => p.pid === 3200)).toMatchObject({
		pid: 3200,
		name: "My App",
		cmd: "/Applications/My App.app/Contents/MacOS/My App --port 9090",
		uid: 501,
	});
	expect(snap.users).toMatchObject({ 0: "root", 216: "_postgres", 501: "me" });
	expect(snap.dns).toEqual(["192.168.1.1", "2001:db8::1"]);
});

test("ps: parents, and start times from etime, whatever the locale", () => {
	expect(elapsed("05")).toBe(5000);
	expect(elapsed("10:05")).toBe(605_000);
	expect(elapsed("01:02:03")).toBe(3_723_000);
	expect(elapsed("2-00:00:01")).toBe(172_801_000);
	const { processes } = parsePs(
		" 3000  2950   501 me   10:00 node\n",
		" 3000 node server.js\n",
		1_000_000,
	);
	expect(processes).toEqual([
		{
			pid: 3000,
			name: "node",
			cmd: "node server.js",
			uid: 501,
			ppid: 2950,
			started: 400_000,
		},
	]);
	// lsof gave the servers' working directories
	expect(snap.processes.find((p) => p.pid === 3000)?.cwd).toBe(
		"/Users/me/src/app-feature",
	);
});
