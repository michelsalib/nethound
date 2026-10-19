import { expect, test } from "bun:test";
import { collect } from "../src/collect.ts";
import {
	parseNetstatListeners,
	parsePortProxy,
	parseTasklist,
	readWindowsPorts,
} from "../src/wsl.ts";
import { fixtureRoot } from "./helpers.ts";

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
