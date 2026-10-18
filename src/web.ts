// Which ports a browser can open: each is asked for / over HTTP, then HTTPS, and what answers is a
// page (HTML, or a redirect to one) or an API. Databases and the like are never asked: Redis takes an
// HTTP request for an attack and logs it. And opening a URL in the browser, wherever nethound runs.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { delimiter, join } from "node:path";
import type { Listener } from "./analyze.ts";
import type { Snapshot } from "./model.ts";
import { isLoopback, isWildcard } from "./net.ts";

export type Web =
	| {
			kind: "page" | "api";
			url: string;
			status: number;
			type?: string;
			/** HTTPS with a certificate this machine doesn't trust (a dev server's own): not read. */
			untrusted?: boolean;
	  }
	// --no-probe: never asked, so only its likely URL
	| { kind: "unchecked"; url: string }
	| { kind: "none" };

/** Ports that speak something other than HTTP: databases, brokers, mail, ssh, DNS. */
const NOT_WEB_PORTS = new Set([
	21, 22, 23, 25, 53, 110, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 1521,
	1883, 2181, 3306, 3389, 4222, 5432, 5433, 5672, 6379, 6380, 9042, 9092, 11211,
	27017, 27018, 27019, 33060,
]);
// process names (without .exe; Linux cuts them to 15 characters) and container images
const NOT_WEB =
	/^(postgres|postmaster|mysqld|mariadbd|redis-server|valkey-server|mongod|memcached|sshd|dnsmasq|systemd-resolve|named|unbound|beam\.smp|zookeeper|kafka|nats-server|mosquitto|cassandra|postgis|timescaledb\S*|mysql|mariadb|redis|valkey|mongo|rabbitmq)$/i;

/** Why a listener is not asked over HTTP: what it is ("redis-server", "postgres"), or nothing. */
export function notWeb(l: Listener): string | undefined {
	if (l.proto !== "tcp") return "udp";
	// postgres:18, bitnami/redis, timescale/timescaledb-ha:pg16
	const image = l.container?.image
		.replace(/[:@].*$/, "")
		.split("/")
		.pop();
	if (image && NOT_WEB.test(image)) return image;
	const name = l.process?.name.replace(/\.exe$/i, "");
	if (name && NOT_WEB.test(name)) return name;
	const inside = l.published?.containerPort ?? l.port;
	if (NOT_WEB_PORTS.has(inside)) return `port ${inside}`;
	return undefined;
}

/** Where to reach a listener: the address to connect to, and the host a browser is given. */
export function hostOf(l: Listener): { address: string; host: string } {
	const a = l.addresses;
	if (a.some((x) => isWildcard(x) || isLoopback(x)))
		return {
			// bound to IPv6 alone (:: with v6only, or ::1): IPv4's loopback would be refused
			address:
				l.reach.ipv6Only || a.every((x) => x.includes(":"))
					? "::1"
					: "127.0.0.1",
			host: "localhost",
		};
	const first = a[0] ?? "127.0.0.1";
	return { address: first, host: first.includes(":") ? `[${first}]` : first };
}

interface Answer {
	status: number;
	type?: string;
	untrusted?: boolean;
}

/** A TLS error about the certificate: a server answered HTTPS with one this machine doesn't trust. */
export const certificateError = (code: unknown) =>
	typeof code === "string" &&
	/CERT|SELF_SIGNED|UNABLE_TO_(VERIFY|GET_ISSUER)/.test(code);

/** One GET /, answered or not within `timeout` ms. */
function ask(
	secure: boolean,
	address: string,
	port: number,
	timeout: number,
): Promise<Answer | undefined> {
	return new Promise((resolve) => {
		const options = {
			host: address,
			port,
			path: "/",
			method: "GET",
			headers: { accept: "text/html,*/*", "user-agent": "nethound" },
			agent: false,
		};
		const req = secure ? https.request(options) : http.request(options);
		// a timer of its own: Bun, which builds the standalone binaries, ignores request's timeout
		const timer = setTimeout(() => {
			req.destroy();
			resolve(undefined);
		}, timeout);
		const settle = (a?: Answer) => {
			clearTimeout(timer);
			resolve(a);
		};
		req.on("response", (res) => {
			settle({
				status: res.statusCode ?? 0,
				type: res.headers["content-type"],
			});
			res.destroy();
		});
		// certificates are checked: one not trusted still says HTTPS answers, though not what with
		req.on("error", (e: NodeJS.ErrnoException) =>
			settle(
				secure && certificateError(e.code)
					? { status: 0, untrusted: true }
					: undefined,
			),
		);
		req.end();
	});
}

/** A page: HTML, or a redirect or a login on the way to one. Any other answer is an API. */
export const classify = (a: Answer): "page" | "api" =>
	// what is behind an untrusted certificate is unknown: a browser is where to find out
	a.untrusted ||
	/html/i.test(a.type ?? "") ||
	(a.status >= 300 && a.status < 400) ||
	a.status === 401
		? "page"
		: "api";

/** Whether `l` answers HTTP or HTTPS, and at which URL. */
export async function probe(l: Listener, timeout = 800): Promise<Web> {
	if (notWeb(l)) return { kind: "none" };
	const { address, host } = hostOf(l);
	for (const secure of [false, true]) {
		const a = await ask(secure, address, l.port, timeout);
		if (a)
			return {
				kind: classify(a),
				url: `${secure ? "https" : "http"}://${host}:${l.port}`,
				status: a.status,
				type: a.type?.split(";")[0],
				...(a.untrusted && { untrusted: true }),
			};
	}
	return { kind: "none" };
}

/** What `l` is taken to be without asking it (--no-probe): a web server, unless it is a database or
 * the like. */
export const unchecked = (l: Listener): Web =>
	notWeb(l)
		? { kind: "none" }
		: { kind: "unchecked", url: `http://${hostOf(l).host}:${l.port}` };

/** "page", "API (404 application/json)": what a probe found, in a few words. */
export function webLabel(w: Web): string {
	if (w.kind === "none") return "";
	if (w.kind === "unchecked") return "not checked";
	if (w.untrusted) return "HTTPS, untrusted certificate";
	if (w.kind === "page")
		return w.status === 200 ? "page" : `page (${w.status})`;
	return `API (${[w.status, w.type].filter(Boolean).join(" ")})`;
}

/** WSL: Windows forwards its localhost to ports bound to 127.0.0.1 or every interface, no other. */
export function windowsReaches(l: Listener): boolean {
	return l.addresses.some((a) => isWildcard(a) || a.startsWith("127."));
}

const onPath = (cmd: string) =>
	(process.env.PATH ?? "")
		.split(delimiter)
		.some((d) => d && existsSync(join(d, cmd)));

/** The command that opens `url` in the browser: in WSL, Windows' browser. */
export function openCommand(
	url: string,
	environment: Snapshot["environment"],
	has: (cmd: string) => boolean = onPath,
): [string, string[]] {
	switch (environment) {
		case "windows":
			return ["cmd.exe", ["/d", "/c", "start", '""', url]];
		case "macos":
			return ["open", [url]];
		case "wsl":
			return has("wslview") ? ["wslview", [url]] : ["explorer.exe", [url]];
		default:
			return ["xdg-open", [url]];
	}
}

/**
 * Opens `url` in the browser, or says why it can't: in WSL, a port Windows doesn't reach. Resolves
 * once the opener started, with an error message or nothing.
 */
export function openUrl(
	url: string,
	l: Listener,
	environment: Snapshot["environment"],
): Promise<string | undefined> {
	if (
		environment === "wsl" &&
		hostOf(l).host === "localhost" &&
		!windowsReaches(l)
	)
		return Promise.resolve(
			`${l.proto} ${l.port} is bound to ${l.addresses.join(", ")}: Windows' browser can't reach it (bind it to 127.0.0.1 or 0.0.0.0)`,
		);
	const [cmd, args] = openCommand(url, environment);
	return new Promise((resolve) => {
		const child = spawn(cmd, args, {
			detached: true,
			stdio: "ignore",
			windowsHide: true,
			// cmd's start: the quotes of its empty title kept as they are
			windowsVerbatimArguments: cmd === "cmd.exe",
		});
		child.on("error", (e) => resolve(`could not run ${cmd}: ${e.message}`));
		child.on("spawn", () => {
			child.unref();
			resolve(undefined);
		});
	});
}
