import { afterAll, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer as createHttp } from "node:http";
import { createServer as createHttps } from "node:https";
import { createServer as createTcp, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Listener } from "../src/analyze.ts";
import {
	certificateError,
	classify,
	hostOf,
	notWeb,
	openCommand,
	openUrl,
	probe,
	webLabel,
} from "../src/web.ts";
import { pg } from "./helpers.ts";

const listener = (
	port: number,
	addresses = ["127.0.0.1"],
	extra: Partial<Listener> = {},
): Listener => ({
	proto: "tcp",
	port,
	addresses,
	reach: { scope: "local", interfaces: [] } as unknown as Listener["reach"],
	sockets: [],
	clients: [],
	...extra,
});
const proc = (name: string) =>
	({ pid: 1, name, cmd: name }) as Listener["process"];

const servers: Server[] = [];
const listen = (s: Server) =>
	new Promise<number>((ok) => {
		servers.push(s);
		s.listen(0, "127.0.0.1", () => {
			const a = s.address();
			ok(typeof a === "object" && a ? a.port : 0);
		});
	});
afterAll(() => {
	for (const s of servers) s.close();
});

test("databases, DNS and UDP are never asked; dev servers are", () => {
	expect(
		notWeb(listener(6379, ["127.0.0.1"], { process: proc("redis-server") })),
	).toBe("redis-server");
	// a database on a port of its own: its process says what it is
	expect(
		notWeb(listener(5434, ["0.0.0.0"], { process: proc("postgres") })),
	).toBe("postgres");
	// a container by its image, whatever host port it is published on
	expect(notWeb(listener(5434, ["0.0.0.0"], { container: pg }))).toBe(
		"postgres",
	);
	// another user's, on a known port
	expect(notWeb(listener(53))).toBe("port 53");
	expect(notWeb({ ...listener(5353), proto: "udp" })).toBe("udp");
	expect(
		notWeb(listener(3000, ["::"], { process: proc("bun") })),
	).toBeUndefined();
});

test("the address to ask, and the host a browser is given", () => {
	expect(hostOf(listener(3000, ["0.0.0.0", "::"]))).toEqual({
		address: "127.0.0.1",
		host: "localhost",
	});
	expect(hostOf(listener(3000, ["::1"]))).toEqual({
		address: "::1",
		host: "localhost",
	});
	expect(hostOf(listener(3000, ["192.168.1.10"]))).toEqual({
		address: "192.168.1.10",
		host: "192.168.1.10",
	});
	expect(hostOf(listener(3000, ["fd00::1"])).host).toBe("[fd00::1]");
});

test("a page is HTML or a redirect; any other answer is an API", () => {
	expect(classify({ status: 200, type: "text/html; charset=utf-8" })).toBe(
		"page",
	);
	expect(classify({ status: 302 })).toBe("page");
	expect(classify({ status: 401, type: "text/plain" })).toBe("page");
	expect(classify({ status: 404, type: "application/json" })).toBe("api");
	expect(
		webLabel({ kind: "api", url: "", status: 404, type: "application/json" }),
	).toBe("API (404 application/json)");
	expect(webLabel({ kind: "page", url: "", status: 302 })).toBe("page (302)");
});

test("probing real servers: a page, an API, and one that never speaks", async () => {
	const page = await listen(
		createHttp((_, res) => {
			res.writeHead(200, { "content-type": "text/html" }).end("<p>hi</p>");
		}),
	);
	const api = await listen(
		createHttp((_, res) => {
			res.writeHead(404, { "content-type": "application/json" }).end("{}");
		}),
	);
	// accepts, then says nothing: a database waiting for its handshake
	const silent = await listen(createTcp(() => {}));
	const [p, a, s] = await Promise.all([
		probe(listener(page)),
		probe(listener(api)),
		probe(listener(silent), 200),
	]);
	expect(p).toEqual({
		kind: "page",
		url: `http://localhost:${page}`,
		status: 200,
		type: "text/html",
	});
	expect(a.kind).toBe("api");
	expect(s).toEqual({ kind: "none" });
});

test("opening: each system's opener; in WSL, a port Windows can't reach is said, not tried", async () => {
	const url = "http://localhost:3000";
	expect(openCommand(url, "macos")).toEqual(["open", [url]]);
	expect(openCommand(url, "linux")).toEqual(["xdg-open", [url]]);
	expect(openCommand(url, "wsl", () => true)).toEqual(["wslview", [url]]);
	expect(openCommand(url, "wsl", () => false)).toEqual(["explorer.exe", [url]]);
	expect(openCommand(url, "windows")[0]).toBe("cmd.exe");
	expect(await openUrl(url, listener(3000, ["::1"]), "wsl")).toContain(
		"Windows' browser can't reach it",
	);
});

const openssl = spawnSync("openssl", ["version"]).status === 0;
test.skipIf(!openssl)(
	"HTTPS with a certificate nobody trusts: checked, not turned off, and still found",
	async () => {
		const dir = mkdtempSync(join(tmpdir(), "nethound-tls-"));
		const [key, cert] = [join(dir, "key.pem"), join(dir, "cert.pem")];
		const made = spawnSync("openssl", [
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-days",
			"1",
			"-subj",
			"/CN=localhost",
			"-keyout",
			key,
			"-out",
			cert,
		]);
		expect(made.status).toBe(0);
		const port = await listen(
			createHttps(
				{ key: readFileSync(key), cert: readFileSync(cert) },
				(_, res) => {
					res.writeHead(200, { "content-type": "text/html" }).end("hi");
				},
			),
		);
		const w = await probe(listener(port));
		expect(w).toMatchObject({
			kind: "page",
			url: `https://localhost:${port}`,
			untrusted: true,
		});
		expect(webLabel(w)).toBe("HTTPS, untrusted certificate");
	},
);

test("certificate errors, as Node and Bun name them, and others that aren't", () => {
	for (const code of [
		"DEPTH_ZERO_SELF_SIGNED_CERT",
		"SELF_SIGNED_CERT_IN_CHAIN",
		"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
		"ERR_TLS_CERT_ALTNAME_INVALID",
		"CERT_HAS_EXPIRED",
	])
		expect(certificateError(code)).toBe(true);
	for (const code of ["ECONNRESET", "EPROTO", "ECONNREFUSED", undefined])
		expect(certificateError(code)).toBe(false);
});
