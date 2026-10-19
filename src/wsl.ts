// In WSL: the TCP ports Windows itself listens on, read through Windows' own commands, which WSL
// can run. Windows forwards its localhost to WSL only for ports it doesn't hold, so a Windows
// program on the same port as a WSL server takes localhost from it. netstat, tasklist and netsh
// answer in half a second, where PowerShell takes several.

import type { WindowsPort } from "./model.ts";
import { plainIP } from "./net.ts";
import type { Run } from "./run.ts";

/** Listening sockets from `netstat -ano -p TCP` and `-p TCPv6`. The state is translated (ÉCOUTE in
 * French), so a listener is told by its remote end, 0.0.0.0:0 or [::]:0. */
export function parseNetstatListeners(
	text: string,
): Omit<WindowsPort, "name">[] {
	const out: Omit<WindowsPort, "name">[] = [];
	for (const line of text.split("\n")) {
		const m = line.match(
			/^\s*TCP\s+(\S+):(\d+)\s+(?:0\.0\.0\.0|\[::\]):0\s+\S+\s+(\d+)\s*$/,
		);
		if (!m) continue;
		const [, address = "", port = "", pid = ""] = m;
		out.push({
			address: plainIP(address.replace(/^\[|\]$/g, "")).address,
			port: Number(port),
			pid: Number(pid),
		});
	}
	return out;
}

/** Image names by pid, from `tasklist /fo csv /nh`, without .exe. */
export function parseTasklist(text: string): Map<number, string> {
	const out = new Map<number, string>();
	for (const m of text.matchAll(/^"([^"]*)","(\d+)"/gm))
		out.set(Number(m[2]), (m[1] ?? "").replace(/\.exe$/i, ""));
	return out;
}

/** The ports `netsh interface portproxy` forwards: often to WSL, on purpose. Its headers are
 * translated, its rows are four columns of addresses and ports. */
export function parsePortProxy(text: string): Set<number> {
	const out = new Set<number>();
	for (const line of text.split("\n")) {
		const f = line.trim().split(/\s+/);
		if (f.length === 4 && /^\d+$/.test(f[1] ?? "") && /^\d+$/.test(f[3] ?? ""))
			out.add(Number(f[1]));
	}
	return out;
}

/** What Windows listens on; undefined when WSL can't run Windows' programs (interop off). */
export function readWindowsPorts(run: Run): WindowsPort[] | undefined {
	const netstat = ["TCP", "TCPv6"]
		.map((p) => run("netstat.exe", ["-ano", "-p", p]))
		.join("\n");
	if (!netstat.trim()) return undefined;
	const names = parseTasklist(run("tasklist.exe", ["/fo", "csv", "/nh"]));
	const proxied = parsePortProxy(
		run("netsh.exe", ["interface", "portproxy", "show", "all"]),
	);
	return parseNetstatListeners(netstat).map((p) => ({
		...p,
		name: names.get(p.pid),
		...(proxied.has(p.port) && { proxy: true }),
	}));
}
