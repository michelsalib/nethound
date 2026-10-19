import { readFileSync } from "node:fs";
import { join } from "node:path";
import { collect } from "../src/collect.ts";
import type { Container } from "../src/model.ts";

export const fixtureRoot = join(import.meta.dir, "fixtures", "root");

export const pg: Container = {
	id: "0123456789ab",
	name: "pg",
	image: "postgres:18",
	project: "app",
	networks: [{ name: "app_default", bridge: "br-abc", ip: "172.18.0.2" }],
	ports: [
		{ proto: "tcp", hostIp: "0.0.0.0", hostPort: 5432, containerPort: 5432 },
		{ proto: "tcp", hostIp: "::", hostPort: 5432, containerPort: 5432 },
	],
	pid: 600,
};

/** The machine scripts/fixture.py describes. */
export const fixture = (containers: Container[] = [pg]) =>
	collect({
		platform: "linux",
		root: fixtureRoot,
		addresses: {
			lo: [
				{ family: 4, address: "127.0.0.1", prefix: 8 },
				{ family: 6, address: "::1", prefix: 128 },
			],
			eth0: [
				{ family: 4, address: "192.168.1.10", prefix: 24 },
				{ family: 6, address: "fe80::5054:ff:fe12:3456", prefix: 64 },
			],
			"br-abc": [{ family: 4, address: "172.18.0.1", prefix: 16 }],
		},
		containers,
		uid: 1000,
		hostname: "box",
	});

const recorded = (dir: string, file: string) =>
	readFileSync(join(import.meta.dir, "fixtures", dir, file), "utf8");

/** The Mac test/fixtures/macos describes, as its commands print it; nethound runs as uid 501. */
export const macFixture = (containers: Container[] = []) =>
	collect({
		platform: "darwin",
		run: (cmd, args) => {
			const files: Record<string, string> = {
				"ifconfig -a": "ifconfig.txt",
				"networksetup -listallhardwareports": "networksetup.txt",
				"netstat -ibn": "netstat-ibn.txt",
				"netstat -an": "netstat-an.txt",
				"netstat -rn": "netstat-rn.txt",
				"lsof -nP -iTCP -iUDP -FpuftPn": "lsof.txt",
				"ps -axo pid=,ppid=,uid=,user=,etime=,comm=": "ps.txt",
				"lsof -a -d cwd -Fn -p 3000,3100,3200": "lsof-cwd.txt",
				"ps -axww -o pid=,args=": "ps-args.txt",
				"cat /etc/resolv.conf": "resolv.conf",
			};
			const file = files[[cmd, ...args].join(" ")];
			if (!file)
				throw new Error(`unexpected command: ${cmd} ${args.join(" ")}`);
			return recorded("macos", file);
		},
		containers,
		uid: 501,
		hostname: "mac",
	});

/** The Windows machine test/fixtures/windows describes, as nethound's PowerShell prints it. */
export const windowsFixture = (containers: Container[] = []) =>
	collect({
		platform: "win32",
		run: (cmd) => {
			if (cmd !== "powershell.exe")
				throw new Error(`unexpected command: ${cmd}`);
			return recorded("windows", "snapshot.json");
		},
		containers,
		hostname: "win",
	});
