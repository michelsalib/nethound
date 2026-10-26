// Windows: one PowerShell call prints everything as JSON. Sockets and their processes from
// Get-NetTCPConnection and Get-NetUDPEndpoint (their states are enum names, the same in every
// language, where netstat translates them), interfaces from .NET's NetworkInterface (one fast
// call for kind, state, addresses, traffic and DNS servers), routes from Get-NetRoute, neighbours
// from Get-NetNeighbor, command
// lines from Win32_Process: without an administrator terminal, other users' are left out.

import type {
	Address,
	Firewall,
	FirewallProfile,
	Iface,
	IfaceKind,
	Neighbour,
	Process,
	Route,
	Snapshot,
	Socket,
	SocketState,
} from "../model.ts";
import { neighbour, plainIP } from "../net.ts";
import type { Run } from "../run.ts";

export const SCRIPT = `
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ifaces = foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
  $p = $n.GetIPProperties()
  $v4 = $null; try { $v4 = $p.GetIPv4Properties() } catch {}
  $v6 = $null; try { $v6 = $p.GetIPv6Properties() } catch {}
  $st = $null; try { $st = $n.GetIPStatistics() } catch {}
  [ordered]@{
    name = $n.Name; description = $n.Description; type = "$($n.NetworkInterfaceType)"
    status = "$($n.OperationalStatus)"; mac = "$($n.GetPhysicalAddress())"
    index = if ($v4) { $v4.Index } elseif ($v6) { $v6.Index } else { 0 }
    mtu = if ($v4) { $v4.Mtu } elseif ($v6) { $v6.Mtu } else { 0 }
    rx = if ($st) { $st.BytesReceived } else { 0 }; tx = if ($st) { $st.BytesSent } else { 0 }
    addresses = @($p.UnicastAddresses | ForEach-Object { ,@("$($_.Address)", $_.PrefixLength) })
    dns = @($p.DnsAddresses | ForEach-Object { "$_" })
  }
}
$fw = $null
if ($firewall) {
  $policy = New-Object -ComObject HNetCfg.FwPolicy2
  $fw = [ordered]@{
    profiles = @(foreach ($b in 1, 2, 4) { ,@($policy.FirewallEnabled($b), $policy.BlockAllInboundTraffic($b), $policy.DefaultInboundAction($b)) })
    rules = @($policy.Rules | Where-Object { $_.Direction -eq 1 -and $_.Enabled -and $_.Protocol -in 6, 17, 256 -and -not $_.LocalUserOwner } | ForEach-Object { ,@($_.Name, $_.Action, $_.Protocol, "$($_.LocalPorts)", [Environment]::ExpandEnvironmentVariables("$($_.ApplicationName)"), "$($_.serviceName)", $_.Profiles, "$($_.RemoteAddresses)", "$($_.LocalAppPackageId)") })
    networks = @(Get-NetConnectionProfile | ForEach-Object { ,@($_.InterfaceAlias, "$($_.NetworkCategory)") })
    products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | ForEach-Object { $_.displayName })
  }
}
$nb = $null
if ($neighbours) {
  $nb = @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { "$($_.State)" -notin 'Unreachable', 'Incomplete' } | ForEach-Object { ,@("$($_.IPAddress)", "$($_.LinkLayerAddress)", $_.InterfaceAlias) })
}
$g = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
[ordered]@{
  tcp4 = @($g.GetActiveTcpListeners() | Where-Object { "$($_.Address)" -eq '0.0.0.0' } | ForEach-Object { $_.Port })
  udp4 = @($g.GetActiveUdpListeners() | Where-Object { "$($_.Address)" -eq '0.0.0.0' } | ForEach-Object { $_.Port })
  tcp = @(Get-NetTCPConnection | ForEach-Object { ,@($_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, "$($_.State)", $_.OwningProcess) })
  udp = @(Get-NetUDPEndpoint | ForEach-Object { ,@($_.LocalAddress, $_.LocalPort, $_.OwningProcess) })
  interfaces = @($ifaces)
  routes = @(Get-NetRoute | ForEach-Object { ,@($_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias, ($_.RouteMetric + $_.InterfaceMetric)) })
  neighbours = $nb
  processes = @(Get-CimInstance Win32_Process -Property ProcessId, Name, CommandLine, ParentProcessId, CreationDate, ExecutablePath | ForEach-Object { ,@($_.ProcessId, $_.Name, $_.CommandLine, $_.ParentProcessId, $(if ($_.CreationDate) { ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } else { 0 }), $_.ExecutablePath) })
  firewall = $fw
} | ConvertTo-Json -Depth 5 -Compress
`;

/** What SCRIPT prints. */
export interface WindowsData {
	/** Ports in Windows' IPv4 tables on 0.0.0.0, dual-stack sockets on :: included. */
	tcp4?: number[];
	udp4?: number[];
	tcp?: [string, number, string, number, string, number][];
	udp?: [string, number, number][];
	interfaces?: {
		name: string;
		description: string;
		type: string;
		status: string;
		mac: string;
		index: number;
		mtu: number;
		rx: number;
		tx: number;
		addresses: [string, number][];
		dns: string[];
	}[];
	routes?: [string, string, string, number][];
	/** Asked for: IPv4 address, MAC (00-15-5D-0D-64-88), interface. */
	neighbours?: [string, string, string][] | null;
	/** pid, image name, command line, parent pid, start time (ms since the epoch, 0 unknown),
	 * executable path. */
	processes?: [
		number,
		string,
		string | null,
		number?,
		number?,
		(string | null)?,
	][];
	/** Asked for: the firewall's profiles (domain, private, public: enabled, block all, default
	 * action 0 block or 1 allow), inbound rules, each network's category, other firewalls. */
	firewall?: {
		profiles: [boolean, boolean, number][];
		/** name, action (0 block, 1 allow), protocol (6, 17, 256 any), local ports, program, service,
		 * profiles, remote addresses, app package (a Store app's) */
		rules: [
			string,
			number,
			number,
			string,
			string,
			string,
			number,
			string,
			string?,
		][];
		networks: [string, string][];
		products: string[];
	} | null;
}

const TCP_STATES: Record<string, SocketState> = {
	Listen: "LISTEN",
	Established: "ESTABLISHED",
	SynSent: "SYN_SENT",
	SynReceived: "SYN_RECV",
	FinWait1: "FIN_WAIT1",
	FinWait2: "FIN_WAIT2",
	TimeWait: "TIME_WAIT",
	CloseWait: "CLOSE_WAIT",
	LastAck: "LAST_ACK",
	Closing: "CLOSING",
	// bound to a port, neither listening nor connected: Linux calls it CLOSE
	Bound: "CLOSE",
	Closed: "CLOSE",
	DeleteTCB: "CLOSE",
};

export function kindOf(type: string, description: string): IfaceKind {
	if (type === "Loopback") return "loopback";
	if (/wireguard/i.test(description)) return "wireguard";
	if (
		/tap-windows|wintun|openvpn|tailscale|vpn/i.test(description) ||
		/Tunnel|Ppp/.test(type)
	)
		return "tun";
	// Hyper-V's vEthernet (WSL, Default Switch), VMware, VirtualBox, Wi-Fi Direct, Bluetooth
	if (/virtual|hyper-v|vmware|bluetooth|wi-fi direct/i.test(description))
		return "virtual";
	if (type === "Wireless80211") return "wifi";
	if (/Ethernet/.test(type)) return "ethernet";
	return "virtual";
}

const mac = (hex: string) =>
	hex.length === 12
		? hex.toLowerCase().replace(/(..)(?!$)/g, "$1:")
		: undefined;

// Windows' stand-in name servers on interfaces that have none (fec0:0:0:ffff::1, 2 and 3)
const placeholderDns = (ip: string) => ip.startsWith("fec0:0:0:ffff::");

const isMulticast = (ip: string) =>
	/^(22[4-9]|23\d)\./.test(ip) || ip.startsWith("ff");

export function parseWindows(
	data: WindowsData,
): Omit<Snapshot, "hostname" | "containers" | "uid"> {
	const interfaces: Iface[] = (data.interfaces ?? []).map((n) => {
		const addresses: Address[] = n.addresses.map(([ip, prefix]) => ({
			...plainIP(ip),
			prefix,
		}));
		return {
			name: n.name,
			index: n.index,
			kind: kindOf(n.type, n.description),
			...(n.description && { description: n.description }),
			state:
				n.status === "Up" ? "up" : n.status === "Down" ? "down" : "unknown",
			mtu: n.mtu > 0 ? n.mtu : 0,
			mac: mac(n.mac),
			addresses,
			members: [],
			rxBytes: n.rx,
			txBytes: n.tx,
		};
	});
	const own = new Set(
		interfaces.flatMap((i) => i.addresses.map((a) => a.address)),
	);
	const routes: Route[] = [];
	for (const [prefixed, hop, iface, metric] of data.routes ?? []) {
		const [net = "", len = "0"] = prefixed.split("/");
		const dest = plainIP(net);
		const prefix = Number(len);
		const host = prefix === (dest.family === 4 ? 32 : 128);
		// multicast and broadcast, and the host routes to this machine's own addresses
		if (isMulticast(dest.address) || dest.address === "255.255.255.255")
			continue;
		if (host && (own.has(dest.address) || dest.address.endsWith(".255")))
			continue;
		const gateway = plainIP(hop).address;
		routes.push({
			family: dest.family,
			dest: dest.address,
			prefix,
			// 0.0.0.0 and :: mean on-link: no gateway
			gateway: gateway === "0.0.0.0" || gateway === "::" ? undefined : gateway,
			iface,
			metric,
		});
	}
	const socket = (
		proto: Socket["proto"],
		local: string,
		lport: number,
		remote: string,
		rport: number,
		state: SocketState,
		pid: number,
	): Socket => {
		const l = plainIP(local);
		return {
			proto,
			family: l.family,
			local: { address: l.address, port: lport },
			remote: { address: plainIP(remote).address, port: rport },
			state,
			// pid 0 is System Idle: what Windows names as the owner of TIME_WAIT sockets
			...(pid === 0 ? { orphan: true } : { pid }),
			...(l.address === "::" && !dual(proto, lport) && { v6only: true }),
		};
	};
	// A socket on :: takes IPv6 only, Windows' default, unless its program asked for both.
	// Get-NetTCPConnection lists such a dual-stack socket once, on ::, but Windows' IPv4 table (what
	// netstat shows) has it on 0.0.0.0 too: a port there with no socket of its own on 0.0.0.0.
	const wildcard4 = new Set([
		...(data.tcp ?? [])
			.filter((t) => t[0] === "0.0.0.0")
			.map((t) => `tcp ${t[1]}`),
		...(data.udp ?? [])
			.filter((u) => u[0] === "0.0.0.0")
			.map((u) => `udp ${u[1]}`),
	]);
	const table4 = new Set([
		...(data.tcp4 ?? []).map((p) => `tcp ${p}`),
		...(data.udp4 ?? []).map((p) => `udp ${p}`),
	]);
	const dual = (proto: Socket["proto"], port: number) =>
		table4.has(`${proto} ${port}`) && !wildcard4.has(`${proto} ${port}`);
	const sockets: Socket[] = [];
	for (const [la, lp, ra, rp, st, pid] of data.tcp ?? []) {
		const state = TCP_STATES[st];
		if (state) sockets.push(socket("tcp", la, lp, ra, rp, state, pid));
	}
	for (const [la, lp, pid] of data.udp ?? [])
		sockets.push(
			socket(
				"udp",
				la,
				lp,
				la.includes(":") ? "::" : "0.0.0.0",
				0,
				"UNCONN",
				pid,
			),
		);
	const processes: Process[] = (data.processes ?? []).map(
		([pid, image, cmd, ppid, started, exe]) => {
			const name = image.replace(/\.exe$/i, "");
			// without an administrator terminal, other users' command lines are not given
			return {
				pid,
				name,
				cmd: cmd?.trim() || name,
				...(ppid && { ppid }),
				...(started && { started }),
				...(exe && { exe }),
			};
		},
	);
	// the name servers of the interfaces that carry traffic
	const dns = [
		...new Set(
			(data.interfaces ?? [])
				.filter((n) => n.status === "Up" && n.type !== "Loopback")
				.flatMap((n) => n.dns.map((d) => plainIP(d).address))
				.filter((d) => !placeholderDns(d)),
		),
	];
	return {
		environment: "windows",
		interfaces,
		routes,
		...(data.neighbours && {
			neighbours: data.neighbours.flatMap(([ip, mac, iface]): Neighbour[] => {
				const n = neighbour(ip, mac, iface);
				return n ? [n] : [];
			}),
		}),
		sockets,
		processes,
		users: {},
		dns,
		hidden: 0,
		...(data.firewall && { firewall: parseFirewall(data.firewall) }),
	};
}

const CATEGORY: Record<string, FirewallProfile> = {
	DomainAuthenticated: "domain",
	Private: "private",
	Public: "public",
};

/** The firewall's part of SCRIPT's answer. */
export function parseFirewall(
	fw: NonNullable<WindowsData["firewall"]>,
): Firewall {
	const profile = (i: number) => {
		const [enabled = false, blockAll = false, action = 0] =
			fw.profiles?.[i] ?? [];
		return { enabled, blockAll, defaultBlock: action === 0 };
	};
	return {
		kind: "windows",
		profiles: { domain: profile(0), private: profile(1), public: profile(2) },
		ifaceProfiles: Object.fromEntries(
			(fw.networks ?? []).map(([iface, category]) => [
				iface,
				CATEGORY[category] ?? "public",
			]),
		),
		rules: (fw.rules ?? []).map(
			([
				name,
				action,
				protocol,
				ports,
				program,
				service,
				profiles,
				remote,
				pkg,
			]) => ({
				name,
				allow: action === 1,
				...(protocol !== 256 && { proto: protocol === 6 ? "tcp" : "udp" }),
				ports: ports || "*",
				...(program && program !== "*" && { program: program.toLowerCase() }),
				...(service && service !== "*" && { service }),
				...(pkg && { package: pkg }),
				profiles,
				remote: remote || "*",
			}),
		),
		products: fw.products ?? [],
	};
}

export function collectWindows(run: Run, firewall = false, neighbours = false) {
	const script =
		(firewall ? "$firewall = $true\n" : "") +
		(neighbours ? "$neighbours = $true\n" : "") +
		SCRIPT;
	const encoded = Buffer.from(script, "utf16le").toString("base64");
	const out = run("powershell.exe", [
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		encoded,
	]);
	let data: WindowsData = {};
	try {
		data = JSON.parse(out.replace(/^﻿/, ""));
	} catch {}
	return parseWindows(data);
}
