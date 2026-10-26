// Windows, from what nethound's PowerShell script prints: test/fixtures/windows.
import { expect, test } from "bun:test";
import { connections, listeners, routeTo, unowned } from "../src/analyze.ts";
import { ownerLabel } from "../src/format.ts";
import { windowsFixture } from "./helpers.ts";

const snap = windowsFixture();
const by = Object.fromEntries(snap.interfaces.map((i) => [i.name, i]));

test("neighbours: from Get-NetNeighbor, broadcast and multicast left out", () => {
	expect(
		snap.neighbours?.map((n) => `${n.address} ${n.mac} ${n.iface}`),
	).toEqual([
		"192.168.1.1 50:39:2f:0a:4c:20 Ethernet",
		"192.168.1.25 a0:6f:aa:4c:df:02 Ethernet",
		"172.20.83.30 00:15:5d:07:29:5f vEthernet (WSL (Hyper-V firewall))",
	]);
});

test("interfaces: kinds from type and description", () => {
	expect(snap.environment).toBe("windows");
	expect(snap.interfaces.map((i) => `${i.name}: ${i.kind} ${i.state}`)).toEqual(
		[
			"Loopback Pseudo-Interface 1: loopback up",
			"Ethernet: ethernet up",
			"Wi-Fi: wifi down",
			"vEthernet (WSL (Hyper-V firewall)): virtual up",
		],
	);
	expect(by.Ethernet).toMatchObject({
		index: 7,
		mtu: 1500,
		mac: "3c:22:fb:12:34:56",
		rxBytes: 325108574,
		addresses: [
			{ family: 6, address: "fe80::1234:5678:9abc:def0", prefix: 64 },
			{ family: 4, address: "192.168.1.20", prefix: 24 },
		],
	});
	// the loopback's MTU is -1
	expect(by["Loopback Pseudo-Interface 1"]?.mtu).toBe(0);
});

test("routes: no multicast, broadcast or own-address host routes; metrics include the interface's", () => {
	expect(
		snap.routes.map(
			(r) => `${r.dest}/${r.prefix} ${r.gateway ?? "-"} ${r.iface} ${r.metric}`,
		),
	).toEqual([
		"0.0.0.0/0 192.168.1.1 Ethernet 35",
		"192.168.1.0/24 - Ethernet 281",
		"127.0.0.0/8 - Loopback Pseudo-Interface 1 331",
		"172.20.80.0/20 - vEthernet (WSL (Hyper-V firewall)) 5256",
		"::/0 fe80::1 Ethernet 51",
		"fe80::/64 - Ethernet 281",
	]);
	expect(routeTo(snap, "8.8.8.8")).toMatchObject({
		kind: "gateway",
		iface: "Ethernet",
		source: "192.168.1.20",
	});
	expect(routeTo(snap, "172.20.90.2")).toMatchObject({
		kind: "network",
		iface: "vEthernet (WSL (Hyper-V firewall))",
	});
	expect(routeTo(snap, "127.0.0.1").iface).toBe("Loopback Pseudo-Interface 1");
});

test("sockets: every one has its process; :: takes IPv6 only; Bound ones are not listening", () => {
	const ls = Object.fromEntries(
		listeners(snap).map((l) => [`${l.proto} ${l.port}`, l]),
	);
	expect(Object.keys(ls)).toEqual([
		"tcp 135",
		"tcp 445",
		"udp 546",
		"tcp 3000",
		"udp 5353",
		"tcp 5432",
		"tcp 8080",
	]);
	expect(ls["tcp 135"]?.reach.ipv6Only).toBeUndefined();
	// one dual-stack socket: Get-NetTCPConnection lists it on :: only, Windows' IPv4 table on 0.0.0.0
	expect(ls["tcp 445"]?.addresses).toEqual(["::"]);
	expect(ls["tcp 445"]?.reach.ipv6Only).toBeUndefined();
	expect(ls["tcp 445"]?.reach.interfaces).toContain("Ethernet");
	// IPv6 only: the interfaces with an IPv6 address, link-local included; Wi-Fi is down
	expect(ls["tcp 8080"]?.reach).toEqual({
		scope: "everywhere",
		ipv6Only: true,
		interfaces: [
			"Loopback Pseudo-Interface 1",
			"Ethernet",
			"vEthernet (WSL (Hyper-V firewall))",
		],
	});
	expect(ls["tcp 5432"]?.reach).toEqual({
		scope: "local",
		interfaces: ["Loopback Pseudo-Interface 1"],
	});
	// the server's end of the connection; the client is at the other end
	expect(
		ls["tcp 5432"]?.clients.map(
			(c) => c.peer.kind === "local" && c.peer.process?.name,
		),
	).toEqual(["node"]);
	expect(ls["tcp 5432"]?.user).toBeUndefined();
	expect(unowned(snap)).toBe(0);
	// TIME_WAIT belongs to pid 0 (System Idle): nobody
	const closing = connections(snap).find((c) => c.state === "TIME_WAIT");
	expect(closing?.process).toBeUndefined();
	expect(closing?.user).toBeUndefined();
});

test("processes: no .exe, the name when the command line is hidden; DNS without placeholders", () => {
	expect(snap.processes.find((p) => p.pid === 3000)).toMatchObject({
		pid: 3000,
		name: "node",
		cmd: "node server.js --token=s3cret",
	});
	expect(snap.processes.find((p) => p.pid === 1500)?.cmd).toBe("svchost");
	// fec0:0:0:ffff::* are Windows' stand-ins; Wi-Fi is down
	expect(snap.dns).toEqual(["192.168.1.1"]);
});

test("hints name an administrator terminal for a Windows snapshot, sudo otherwise, wherever it runs", () => {
	const [first] = listeners(snap);
	if (!first) throw new Error("no listener");
	const l = {
		...first,
		process: undefined,
		sockets: [],
		user: undefined,
	};
	expect(ownerLabel(l, { color: false, windows: true })).toBe(
		"another user's process (run as administrator to see it)",
	);
	expect(ownerLabel(l, { color: false })).toBe(
		"another user's process (sudo to see it)",
	);
});

test("processes: their parent and start time, from Win32_Process", () => {
	expect(snap.processes.find((p) => p.pid === 3000)).toMatchObject({
		ppid: 2900,
		started: 1760000600000,
	});
	// pid 0 and System have neither
	expect(snap.processes.find((p) => p.pid === 4)?.ppid).toBeUndefined();
});
