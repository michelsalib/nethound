import { expect, test } from "bun:test";
import { map, routeTo, throughWindows } from "../src/analyze.ts";
import { collect } from "../src/collect.ts";
import { renderMap, renderRoute, routeJson } from "../src/format.ts";
import {
	parseIpconfigDescriptions,
	parseNetshInterfaces,
	parseNetshRoutes,
	parseNetstatListeners,
	parsePortProxy,
	parseTasklist,
	readWindowsPorts,
	readWindowsRouting,
} from "../src/wsl.ts";
import { fixture, fixtureRoot } from "./helpers.ts";

// netstat.exe -ano -p TCP and -p TCPv6 on a French Windows
const NETSTAT = `
Connexions actives

  Proto  Adresse locale         Adresse distante       État
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1832
  TCP    127.0.0.1:5173         0.0.0.0:0              LISTENING       28432
  TCP    127.0.0.1:6768         0.0.0.0:0              LISTENING       25692
  TCP    10.89.100.6:52144      140.82.121.4:443       ESTABLISHED     20108

Connexions actives

  Proto  Adresse locale         Adresse distante       État
  TCP    [::]:135               [::]:0                 LISTENING       1832
  TCP    [::1]:5173             [::]:0                 LISTENING       28432
  TCP    [fe80::1%12]:2869      [::]:0                 LISTENING       4
`;

const TASKLIST = `"System Idle Process","0","Services","0","8 Ko"
"svchost.exe","1832","Services","0","13 400 Ko"
"wslrelay.exe","28432","Console","1","9 120 Ko"
"Orca.exe","25692","Console","1","210 000 Ko"
`;

const PORTPROXY = `
Écouter sur ipv4 :             Connecter à ipv4 :

Adresse         Port        Adresse         Port
--------------- ----------  --------------- ----------
0.0.0.0         2222        172.20.83.30    22
`;

test("Windows' listeners from netstat, whatever its language", () => {
	expect(parseNetstatListeners(NETSTAT)).toEqual([
		{ address: "0.0.0.0", port: 135, pid: 1832 },
		{ address: "127.0.0.1", port: 5173, pid: 28432 },
		{ address: "127.0.0.1", port: 6768, pid: 25692 },
		{ address: "::", port: 135, pid: 1832 },
		{ address: "::1", port: 5173, pid: 28432 },
		{ address: "fe80::1", port: 2869, pid: 4 },
	]);
	expect(parseTasklist(TASKLIST).get(28432)).toBe("wslrelay");
	expect([...parsePortProxy(PORTPROXY)]).toEqual([2222]);
});

test("read in WSL for doctor only; nothing when Windows' programs can't run", () => {
	const answers: Record<string, string> = {
		"netstat.exe -ano -p TCP": NETSTAT,
		"netstat.exe -ano -p TCPv6": "",
		"tasklist.exe /fo csv /nh": TASKLIST,
		"netsh.exe interface portproxy show all": PORTPROXY,
	};
	const run = (cmd: string, args: string[]) =>
		answers[[cmd, ...args].join(" ")] ?? "";
	expect(readWindowsPorts(run)?.[2]).toEqual({
		address: "127.0.0.1",
		port: 6768,
		pid: 25692,
		name: "Orca",
	});
	expect(readWindowsPorts(() => "")).toBeUndefined();
	// the fixture is plain Linux: not asked
	const snap = collect({
		platform: "linux",
		root: fixtureRoot,
		addresses: {},
		containers: [],
		run,
		windows: true,
	});
	expect(snap.windowsPorts).toBeUndefined();
});

// netsh.exe interface ipv4 show …, and ipconfig.exe /all, on a French Windows connected to a
// split-tunnel VPN; WSL's gateway is Windows' 192.168.1.1, as in the Linux fixture
const NETSH_INTERFACES = `
Idx     Mét         MTU          État                Nom
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
 22          35        1500  connected     Wi-Fi
  4           1        1300  connected     Ethernet
 39          15        1500  connected     vEthernet (WSL (Hyper-V firewall))
 20          65        1500  disconnected  Connexion réseau Bluetooth
`;

const NETSH_ADDRESSES = `
Interface 1 : Loopback Pseudo-Interface 1

Addr Type  État DAD    Vie valide Pers. Fav. Adresse
---------  ----------- ---------- ---------- ------------------------
Autre      Préféré       infinite   infinite 127.0.0.1

Interface 22 : Wi-Fi

Addr Type  État DAD    Vie valide Pers. Fav. Adresse
---------  ----------- ---------- ---------- ------------------------
Dhcp       Préféré      21h11m16s  21h11m16s 10.0.0.16

Interface 4 : Ethernet

Addr Type  État DAD    Vie valide Pers. Fav. Adresse
---------  ----------- ---------- ---------- ------------------------
Manuel     Préféré       infinite   infinite 10.8.0.2

Interface 39 : vEthernet (WSL (Hyper-V firewall))

Addr Type  État DAD    Vie valide Pers. Fav. Adresse
---------  ----------- ---------- ---------- ------------------------
Manuel     Préféré       infinite   infinite 192.168.1.1
`;

const NETSH_ROUTES = `
Publier  Type      Mét  Préfixe                   Idx  Nom passerelle/interface
-------  --------  ---  ------------------------  ---  ------------------------
Non      Manuel    0    0.0.0.0/0                  22  10.0.0.1
Non      Manuel    0    10.20.0.0/16                4  10.8.0.1
Non      Système   256  10.0.0.0/24                22  Wi-Fi
Non      Système   256  127.0.0.0/8                 1  Loopback Pseudo-Interface 1
Non      Système   256  192.168.1.0/24             39  vEthernet (WSL (Hyper-V firewall))
Non      Manuel    0    172.30.0.0/16              20  10.0.0.1
Non      Système   256  10.8.0.2/32                 4  Ethernet
Non      Système   256  224.0.0.0/4                 4  Ethernet
Non      Système   256  10.0.0.255/32              22  Wi-Fi
`;

const IPCONFIG = `
Configuration IP de Windows

   Nom de l'hôte . . . . . . . . . . : LAPTOP

Carte Ethernet Ethernet :

   Suffixe DNS propre à la connexion. . . :
   Description. . . . . . . . . . . . . . : Fortinet SSL VPN Virtual Ethernet Adapter

Carte Ethernet vEthernet (WSL (Hyper-V firewall)) :

   Description. . . . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter

Carte réseau sans fil Wi-Fi :

   Description. . . . . . . . . . . . . . : Intel(R) Wi-Fi 6E AX211 160MHz
`;

const windowsRun = (cmd: string, args: string[]) =>
	({
		"netsh.exe interface ipv4 show interfaces": NETSH_INTERFACES,
		"netsh.exe interface ipv4 show ipaddresses": NETSH_ADDRESSES,
		"netsh.exe interface ipv4 show route": NETSH_ROUTES,
		"ipconfig.exe /all": IPCONFIG,
	})[[cmd, ...args].join(" ")] ?? "";

test("Windows' routing from netsh and ipconfig, whatever their language", () => {
	expect(parseNetshInterfaces(NETSH_INTERFACES)[4]).toEqual({
		index: 20,
		metric: 65,
		mtu: 1500,
		up: false,
		name: "Connexion réseau Bluetooth",
	});
	expect(parseNetshRoutes(NETSH_ROUTES).slice(0, 3)).toEqual([
		{ metric: 0, dest: "0.0.0.0", prefix: 0, index: 22, gateway: "10.0.0.1" },
		{ metric: 0, dest: "10.20.0.0", prefix: 16, index: 4, gateway: "10.8.0.1" },
		{ metric: 256, dest: "10.0.0.0", prefix: 24, index: 22 },
	]);
	// "Ethernet" ends "Carte Ethernet vEthernet (…)" too, but not as its name
	expect(
		parseIpconfigDescriptions(IPCONFIG, [
			"Ethernet",
			"vEthernet (WSL (Hyper-V firewall))",
		]),
	).toEqual(
		new Map([
			["Ethernet", "Fortinet SSL VPN Virtual Ethernet Adapter"],
			[
				"vEthernet (WSL (Hyper-V firewall))",
				"Hyper-V Virtual Ethernet Adapter",
			],
		]),
	);
	const win = readWindowsRouting(windowsRun);
	expect(win?.interfaces.map((i) => `${i.name}: ${i.kind} ${i.state}`)).toEqual(
		[
			"Loopback Pseudo-Interface 1: loopback up",
			"Wi-Fi: wifi up",
			"Ethernet: tun up",
			"vEthernet (WSL (Hyper-V firewall)): virtual up",
			"Connexion réseau Bluetooth: ethernet down",
		],
	);
	// no description for Bluetooth, so no telling it from ethernet: only VPNs matter here
	// the interface's metric added; none through an interface that is down, no multicast,
	// broadcast or host route to its own address
	expect(
		win?.routes.map(
			(r) => `${r.dest}/${r.prefix} ${r.gateway ?? "-"} ${r.metric}`,
		),
	).toEqual([
		"0.0.0.0/0 10.0.0.1 35",
		"10.20.0.0/16 10.8.0.1 1",
		"10.0.0.0/24 - 291",
		"127.0.0.0/8 - 331",
		"192.168.1.0/24 - 271",
	]);
	expect(readWindowsRouting(() => "")).toBeUndefined();
});

test("in WSL, route follows Windows' table: through its VPN or not", () => {
	const snap = { ...fixture(), environment: "wsl" as const };
	const win = readWindowsRouting(windowsRun);
	if (!win) throw new Error("no routing");
	const via = (ip: string) => {
		const r = routeTo(snap, ip);
		const next = throughWindows(snap, r, win);
		if (next) r.windows = next;
		return r;
	};
	expect(renderRoute(via("10.20.3.4"), "intranet.corp", { color: false })).toBe(
		[
			"intranet.corp (10.20.3.4)",
			"  is         beyond 192.168.1.1, the gateway on eth0",
			"  interface  eth0",
			"  route      default via 192.168.1.1 metric 100",
			"  from       192.168.1.10",
			"then Windows (192.168.1.1) sends it on",
			"  is         beyond 10.8.0.1, the gateway on Ethernet",
			"  interface  Ethernet",
			"  route      10.20.0.0/16 via 10.8.0.1 metric 1",
			"  from       10.8.0.2",
			"  vpn        through Ethernet (Fortinet SSL VPN Virtual Ethernet Adapter)",
		].join("\n"),
	);
	const out = via("8.8.8.8");
	expect(out.windows).toMatchObject({
		iface: "Wi-Fi",
		outside: ["Ethernet (Fortinet SSL VPN Virtual Ethernet Adapter)"],
	});
	expect(routeJson(out)).toMatchObject({ windows: { gateway: "10.0.0.1" } });
	// a gateway that is not Windows (mirrored networking): nothing more to say
	const elsewhere = {
		...win,
		interfaces: win.interfaces.filter((i) => i.index !== 39),
	};
	expect(
		throughWindows(snap, routeTo(snap, "8.8.8.8"), elsewhere),
	).toBeUndefined();
});

test("in WSL, the map says which VPN Windows runs", () => {
	const win = readWindowsRouting(windowsRun);
	const snap = {
		...fixture(),
		environment: "wsl" as const,
		windowsRouting: win,
	};
	expect(map(snap).windowsVpns).toEqual([
		{
			vpn: "Ethernet (Fortinet SSL VPN Virtual Ethernet Adapter)",
			networks: 1,
			all: false,
			internet: "Wi-Fi",
		},
	]);
	expect(renderMap(map(snap), { color: false })).toContain(
		"windows  VPN Ethernet (Fortinet SSL VPN Virtual Ethernet Adapter): 1 network through it, WSL's traffic to them too; the rest by Wi-Fi",
	);
});
