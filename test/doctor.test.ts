import { expect, test } from "bun:test";
import { doctor } from "../src/doctor.ts";
import { renderDoctor } from "../src/format.ts";
import type { Route, Snapshot, Socket } from "../src/model.ts";
import { fixture, macFixture, windowsFixture } from "./helpers.ts";

const summary = (snap: Snapshot) =>
	doctor(snap).map((f) => `${f.severity} ${f.rule} ${f.proto} ${f.port}`);

const listen = (address: string, port: number, pid: number): Socket => ({
	proto: "tcp",
	family: address.includes(":") ? 6 : 4,
	local: { address, port },
	remote: { address: address.includes(":") ? "::" : "0.0.0.0", port: 0 },
	state: "LISTEN",
	pid,
	uid: 1000,
});

test("each system's fixture: a published database, dev servers off this machine", () => {
	expect(summary(fixture())).toEqual([
		"warning exposed tcp 5432",
		"info exposed tcp 8080",
	]);
	// node on * (tcp46); the database is on 127.0.0.1 only; My App on :: and another on ::1, IPv6 only
	expect(summary(macFixture())).toEqual([
		"warning ipv6-only tcp 9090",
		// utun4 carries 10.8.0.0/16
		"info vpn-split undefined undefined",
		"info ipv6-only tcp 5000",
		"info exposed tcp 8080",
	]);
	// node on the Ethernet address, and on :: (IPv6 only)
	expect(summary(windowsFixture())).toEqual([
		"warning ipv6-only tcp 8080",
		"info exposed tcp 3000",
		"info exposed tcp 8080",
	]);
});

test("a published container: the fix is to publish it on 127.0.0.1", () => {
	const [pg] = doctor(fixture());
	expect(pg?.title).toBe(
		"PostgreSQL on tcp 5432 is reachable from every interface",
	);
	expect(pg?.details[0]).toBe("container pg, bound to 0.0.0.0");
	expect(pg?.fix).toContain("-p 127.0.0.1:5432:5432");
});

test("debuggers and the docker API off this machine are errors; containers known by image", () => {
	const snap = structuredClone(fixture([]));
	snap.processes.push({
		pid: 700,
		name: "node",
		cmd: "node --inspect=0.0.0.0 app.js",
	});
	snap.sockets.push(listen("0.0.0.0", 9229, 700));
	const [inspector] = doctor(snap);
	expect(inspector).toMatchObject({ severity: "error", port: 9229 });
	expect(inspector?.fix).toContain("--inspect=127.0.0.1");
	// a redis container published on 6380: its image says what it is
	const withRedis = fixture([
		{
			id: "r",
			name: "cache",
			image: "redis:7-alpine",
			networks: [],
			ports: [
				{
					proto: "tcp",
					hostIp: "0.0.0.0",
					hostPort: 6380,
					containerPort: 6379,
				},
			],
		},
	]);
	expect(doctor(withRedis).find((f) => f.port === 6380)).toMatchObject({
		title: "Redis on tcp 6380 is reachable from every interface",
		fix: expect.stringContaining("-p 127.0.0.1:6380:6379"),
	});
});

test("localhost split between IPv4 and IPv6: who answers each way", () => {
	const snap = structuredClone(windowsFixture());
	// postgres 2000 has 127.0.0.1:5432; node 3000 takes [::1]:5432
	snap.sockets.push({ ...listen("::1", 5432, 3000), v6only: true });
	const [f] = doctor(snap).filter((x) => x.rule === "port-shared");
	expect(f?.title).toBe(
		"localhost:5432 reaches postgres 2000 over IPv4 and node 3000 over IPv6",
	);
	expect(f?.details).toContain(
		"localhost over IPv4 (127.0.0.1:5432) → postgres 2000",
	);
	expect(f?.details).toContain("localhost over IPv6 ([::1]:5432) → node 3000");
});

test("a local server in front of a published container, for this machine's clients", () => {
	const snap = structuredClone(fixture());
	snap.processes.push({
		pid: 800,
		name: "postgres",
		cmd: "postgres -D /var/lib/pg",
	});
	snap.sockets.push(listen("127.0.0.1", 5432, 800));
	const f = doctor(snap).find((x) => x.rule === "port-shared");
	expect(f?.details).toEqual(
		expect.arrayContaining([
			"localhost over IPv4 (127.0.0.1:5432) → postgres 800",
			"localhost over IPv6 ([::1]:5432) → nobody",
			"other machines → container pg",
		]),
	);
});

test("not a conflict: distinct addresses of their own, or one server's workers", () => {
	const snap = structuredClone(fixture([]));
	snap.processes.push(
		{ pid: 901, name: "resolved", cmd: "resolved" },
		{ pid: 902, name: "dnsstub", cmd: "dnsstub" },
		{ pid: 903, name: "nginx", cmd: "nginx: worker process" },
		{ pid: 904, name: "nginx", cmd: "nginx: worker process" },
	);
	snap.sockets.push(
		listen("127.0.0.53", 53, 901),
		listen("10.255.255.254", 53, 902),
		listen("0.0.0.0", 8443, 903),
		listen("0.0.0.0", 8443, 904),
	);
	expect(doctor(snap).filter((x) => x.rule === "port-shared")).toEqual([]);
});

test("rendered: one block per finding, a summary; nothing to say says so", () => {
	const text = renderDoctor(doctor(fixture()), { color: false });
	expect(text).toContain(
		"! PostgreSQL on tcp 5432 is reachable from every interface\n  container pg",
	);
	expect(text).toContain(
		"· a development server on tcp 8080 is reachable from eth0",
	);
	expect(text).toEndWith("1 warning, 1 note");
	expect(renderDoctor([], { color: false })).toBe("✓ no problems found");
});

const route = (r: Partial<Route> & { iface: string }): Route => ({
	family: 4,
	dest: "0.0.0.0",
	prefix: 0,
	metric: 0,
	...r,
});

const byRule = (snap: Snapshot, rule: string) =>
	doctor(snap).filter((f) => f.rule === rule);

test("IPv6 only: on :: it refuses IPv4, on ::1 it refuses 127.0.0.1; fine when another takes IPv4", () => {
	const snap = structuredClone(windowsFixture());
	snap.processes.push({ pid: 5000, name: "api", cmd: "api" });
	snap.sockets.push(
		{ ...listen("::", 7000, 5000), v6only: true },
		{ ...listen("::1", 7001, 5000), v6only: true },
		{ ...listen("::", 7002, 5000), v6only: true },
		listen("0.0.0.0", 7002, 3000),
	);
	expect(
		byRule(snap, "ipv6-only").map((f) => `${f.severity} ${f.port}`),
	).toEqual(["warning 7000", "warning 8080", "info 7001"]);
	expect(byRule(snap, "ipv6-only")[0]?.details[0]).toContain(
		"Windows' default",
	);
});

test("WSL: a Windows program on a port WSL serves takes Windows' localhost; forwarders don't", () => {
	const snap = structuredClone(fixture([]));
	snap.environment = "wsl";
	snap.windowsPorts = [
		// node 300 has 127.0.0.1:5000 in WSL
		{ address: "127.0.0.1", port: 5000, pid: 42, name: "Code" },
		// wslrelay forwarding WSL's 8080, a port proxy, a server on Windows' LAN address only
		{ address: "127.0.0.1", port: 8080, pid: 7, name: "wslrelay" },
		{ address: "0.0.0.0", port: 22, pid: 8, name: "svchost", proxy: true },
		{ address: "192.168.1.20", port: 22, pid: 9, name: "sshd" },
	];
	const found = byRule(snap, "wsl-port-shadowed");
	expect(found.map((f) => f.port)).toEqual([5000]);
	expect(found[0]?.title).toBe(
		"localhost:5000 in Windows reaches Code 42, not node 300 in WSL",
	);
	expect(found[0]?.fix).toContain("WSL's is still at 192.168.1.10:5000");
	// one program's two halves: its WSL relay names it
	const node = snap.processes.find((p) => p.pid === 300);
	if (node) node.cmd = "node /home/me/.code-wsl/relay.js";
	expect(byRule(snap, "wsl-port-shadowed")).toEqual([]);
	// not WSL, or Windows' ports unread: nothing to compare
	snap.environment = "linux";
	expect(byRule(snap, "wsl-port-shadowed")).toEqual([]);
});

test("no default route: what is left, and DNS said once", () => {
	const snap = structuredClone(fixture([]));
	snap.routes = snap.routes.filter((r) => r.prefix > 0);
	snap.dns = ["8.8.8.8"];
	const found = doctor(snap).filter((f) => f.port === undefined);
	expect(found.map((f) => f.rule)).toEqual(["no-default-route"]);
	expect(found[0]?.details).toEqual([
		"this machine reaches only 192.168.1.0/24 on eth0, 172.18.0.0/16 on br-abc",
		"name lookups wait for DNS servers they can't reach, and fail",
	]);
});

test("two default routes with the same metric; not on macOS, which has none", () => {
	const snap = structuredClone(fixture([]));
	snap.interfaces.push({
		...structuredClone(snap.interfaces.find((i) => i.name === "eth0")),
		name: "wlan0",
		kind: "wifi",
		addresses: [{ family: 4, address: "10.0.0.5", prefix: 24 }],
	} as Snapshot["interfaces"][number]);
	snap.routes.push(route({ iface: "wlan0", gateway: "10.0.0.1", metric: 100 }));
	const [tie] = byRule(snap, "default-routes");
	expect(tie?.title).toBe(
		"2 default routes for IPv4 with the same metric: eth0, wlan0",
	);
	expect(tie?.fix).toContain("ipv4.route-metric");
	// a lower metric decides
	const wlan = snap.routes.at(-1);
	if (wlan) wlan.metric = 600;
	expect(byRule(snap, "default-routes")).toEqual([]);
	expect(byRule(macFixture(), "default-routes")).toEqual([]);
});

test("a VPN taking all traffic, with 0.0.0.0/1 and 128.0.0.0/1; the LAN stays off it", () => {
	const snap = structuredClone(fixture([]));
	snap.interfaces.push({
		name: "tun0",
		index: 9,
		kind: "tun",
		state: "up",
		mtu: 1400,
		addresses: [{ family: 4, address: "10.8.0.2", prefix: 24 }],
		members: [],
		rxBytes: 0,
		txBytes: 0,
	});
	snap.routes.push(
		route({ iface: "tun0", prefix: 1 }),
		route({ iface: "tun0", dest: "128.0.0.0", prefix: 1 }),
	);
	const [vpn] = byRule(snap, "vpn-all-traffic");
	expect(vpn).toMatchObject({
		severity: "info",
		title: "all internet traffic goes through the VPN on tun0",
	});
	expect(vpn?.details).toEqual([
		"IPv4: 0.0.0.0/1 on tun0",
		"stays off it: 192.168.1.0/24 on eth0",
	]);
	// a split tunnel: only its own networks
	snap.routes = snap.routes.filter((r) => r.prefix !== 1);
	snap.routes.push(route({ iface: "tun0", dest: "10.70.0.0", prefix: 16 }));
	expect(byRule(snap, "vpn-all-traffic")).toEqual([]);
});

test("a split-tunnel VPN: what it carries, the internet around it, the DNS servers it takes", () => {
	const snap = structuredClone(fixture([]));
	snap.interfaces.push({
		name: "Ethernet",
		index: 9,
		kind: "tun",
		description: "Fortinet SSL VPN Virtual Ethernet Adapter",
		state: "up",
		mtu: 1300,
		addresses: [{ family: 4, address: "10.8.0.2", prefix: 32 }],
		members: [],
		rxBytes: 0,
		txBytes: 0,
	});
	for (let n = 0; n < 8; n++)
		snap.routes.push(
			route({
				iface: "Ethernet",
				dest: `10.${20 + n}.0.0`,
				prefix: n < 2 ? 16 : 24,
				gateway: "10.8.0.1",
			}),
		);
	snap.dns = ["10.20.0.53", "192.168.1.1", "fe80::1"];
	const [split] = byRule(snap, "vpn-split");
	expect(split).toMatchObject({
		severity: "info",
		title:
			"the VPN on Ethernet (Fortinet SSL VPN Virtual Ethernet Adapter) carries 8 networks, the rest goes around it",
		details: [
			"through it: 10.20.0.0/16, 10.21.0.0/16, 10.22.0.0/24, 10.23.0.0/24, 10.24.0.0/24, 10.25.0.0/24 and 2 more",
			"the internet: default via 192.168.1.1 on eth0",
			"DNS servers through it: 10.20.0.53: lookups to them fail while it is down",
		],
	});
	// in WSL, the same VPN on Windows' side, and WSL's traffic with it
	const wsl = structuredClone(fixture([]));
	wsl.environment = "wsl";
	wsl.windowsRouting = {
		interfaces: snap.interfaces.filter((i) => i.name === "Ethernet"),
		routes: snap.routes.filter((r) => r.iface === "Ethernet"),
	};
	const [win] = byRule(wsl, "vpn-split");
	expect(win?.title).toStartWith("Windows: the VPN on Ethernet");
	expect(win?.details.at(-1)).toBe(
		"WSL's traffic leaves through Windows, and takes the same way",
	);
	// all traffic through it: vpn-all-traffic says so instead
	snap.routes.push(
		route({ iface: "Ethernet", prefix: 1, gateway: "10.8.0.1" }),
	);
	expect(byRule(snap, "vpn-split")).toEqual([]);
	expect(byRule(snap, "vpn-all-traffic")).toHaveLength(1);
});

test("DNS: a server with no route; a private one only the default route reaches", () => {
	const snap = structuredClone(fixture([]));
	// IPv4 only: an IPv6 server can't be reached
	snap.dns = ["127.0.0.53", "192.168.1.1", "2001:4860:4860::8888"];
	const [lost] = byRule(snap, "dns-unreachable");
	expect(lost).toMatchObject({
		severity: "warning",
		title: "DNS server 2001:4860:4860::8888 has no route",
		details: [
			"a lookup that tries it waits for it to time out, then goes on to 192.168.1.1",
		],
	});
	expect(lost?.fix).toStartWith("this network has no IPv6");
	// a VPN's, left behind
	snap.dns = ["10.70.125.100"];
	const [astray] = byRule(snap, "dns-private");
	expect(astray?.title).toBe(
		"DNS server 10.70.125.100 is a private address on none of this machine's networks",
	);
	expect(astray?.details[0]).toBe(
		"queries leave by the default route, via 192.168.1.1 on eth0",
	);
	// none reachable: an error
	snap.dns = ["fd00::53"];
	expect(byRule(snap, "dns-unreachable")[0]?.severity).toBe("error");
});

test("routing findings render with the others, before the ports", () => {
	const snap = structuredClone(fixture([]));
	snap.dns = ["fd00::53"];
	const text = renderDoctor(doctor(snap), { color: false });
	expect(text).toStartWith(
		"✗ DNS server fd00::53 has no route\n  every name lookup fails",
	);
	expect(text).toEndWith("1 error, 1 warning, 1 note");
});

test("the same program in two checkouts is two servers: localhost split between them", () => {
	const snap = structuredClone(fixture([]));
	snap.processes.push(
		{ pid: 951, name: "node", cmd: "vite --host 127.0.0.1", cwd: "/src/shop" },
		{ pid: 952, name: "node", cmd: "vite", cwd: "/src/shop-checkout" },
	);
	snap.sockets.push(listen("127.0.0.1", 5173, 951), {
		...listen("::1", 5173, 952),
		v6only: true,
	});
	expect(byRule(snap, "port-shared")[0]?.title).toBe(
		"localhost:5173 reaches node 951 over IPv4 and node 952 over IPv6",
	);
});
