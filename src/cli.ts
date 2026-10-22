#!/usr/bin/env node
import { lookup } from "node:dns/promises";
import { realpathSync } from "node:fs";
import { isIP } from "node:net";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import pkg from "../package.json" with { type: "json" };
import {
	connections,
	listeners,
	map,
	routeTo,
	throughWindows,
	unowned,
	who,
} from "./analyze.ts";
import { collect } from "./collect.ts";
import {
	type CompletionShell,
	complete,
	completionScript,
	type PortCandidate,
	SHELLS,
} from "./completion.ts";
import { doctor } from "./doctor.ts";
import {
	connectionJson,
	elevate,
	ifaceViewJson,
	insideJson,
	listenerJson,
	mapJson,
	paint,
	place,
	procLabel,
	type RenderOptions,
	renderConnections,
	renderDoctor,
	renderInterfaces,
	renderList,
	renderMap,
	renderRoute,
	renderWho,
	routeJson,
} from "./format.ts";
import { ALIASES, COMMAND_HELP, commandHelp, overview } from "./help.ts";
import { killPort } from "./kill.ts";
import { banner } from "./logo.ts";
import { maskCmd, type Snapshot } from "./model.ts";
import { openPort } from "./open.ts";
import { run } from "./run.ts";
import {
	binaryName,
	compiled,
	fetchLatest,
	installKind,
	latestRelease,
	newer,
	type Release,
	renameNotice,
	replaceBinary,
	replaceScript,
	selfPath,
	stateFile,
	updateNotice,
	upgradeCommand,
} from "./update.ts";
import { runWatch } from "./watch/terminal.ts";
import { parseNslookup } from "./wsl.ts";

const TAGLINE =
	"see what listens on each port, who reaches it, and how everything connects";

let usageHint = "nethound --help";

function usage(message: string): number {
	console.error(`nethound: ${message}\nsee: ${usageHint}`);
	return 2;
}

/** A newer version, said once a week after a command; or that netbeagle is now nethound. */
let notice: string | undefined;

async function main(argv: string[]): Promise<number> {
	// hidden, called by the completion scripts on every <Tab>
	if (argv[0] === "__complete") {
		for (const c of complete(argv.slice(1), portCandidates)) console.log(c);
		return 0;
	}
	// the PowerShell script's form: "_" + the word being typed, then the words before it
	if (argv[0] === "__complete-powershell") {
		const words = [...argv.slice(2), (argv[1] ?? "_").slice(1)];
		for (const c of complete(words, portCandidates)) console.log(c);
		return 0;
	}
	// hidden, started in the background by updateNotice
	if (argv[0] === "__update-check") {
		await fetchLatest(argv[1] ?? stateFile());
		return 0;
	}
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			json: { type: "boolean" },
			tcp: { type: "boolean" },
			udp: { type: "boolean" },
			all: { type: "boolean", short: "a" },
			"no-docker": { type: "boolean" },
			"show-secrets": { type: "boolean" },
			"no-probe": { type: "boolean" },
			tree: { type: "boolean" },
			force: { type: "boolean" },
			yes: { type: "boolean", short: "y" },
			// what nethound watch reads each time, from a nethound of its own: the raw snapshot
			snapshot: { type: "boolean" },
			help: { type: "boolean", short: "h" },
			version: { type: "boolean", short: "v" },
		},
	});
	// the logo only for a person at a terminal; scripts get the plain text, e.g. $(nethound --version)
	const art = process.stdout.isTTY;
	const logo = () =>
		banner(
			[
				`nethound ${pkg.version}`,
				"",
				"see what listens on each",
				"port, who reaches it, and",
				"how everything connects",
			],
			{
				color: !process.env.NO_COLOR,
				truecolor: /^(truecolor|24bit)$/i.test(process.env.COLORTERM ?? ""),
				columns: process.stdout.columns,
			},
		);
	const asked = positionals[0] === "help";
	const topic =
		(asked ? positionals[1] : values.help ? positionals[0] : undefined) ??
		undefined;
	if (values.help || asked) {
		if (topic) {
			const text = commandHelp(topic);
			if (!text) return usage(`no command '${topic}'`);
			process.stdout.write(text);
			return 0;
		}
		process.stdout.write(
			art
				? `${logo()}\n${overview()}`
				: `nethound ${pkg.version}\n${TAGLINE}\n\n${overview()}`,
		);
		return 0;
	}
	if (values.version) {
		process.stdout.write(art ? logo() : `${pkg.version}\n`);
		return 0;
	}
	const [given = "list", ...args] = positionals;
	const command = ALIASES[given] ?? given;
	if (!COMMAND_HELP[command]) return usage(`no command '${given}'`);
	usageHint = `nethound ${command} --help`;
	if (!["linux", "darwin", "win32"].includes(process.platform)) {
		console.error(
			`nethound runs on Linux, macOS and Windows, not ${process.platform}`,
		);
		return 2;
	}

	// only for a person at a terminal; never in scripts, CI, with --json, or in watch's own refreshes
	const env = process.env;
	const person =
		process.stderr.isTTY && !values.json && !values.snapshot && !env.CI;
	if (person) {
		try {
			notice = renameNotice(realpathSync(selfPath()));
		} catch {}
	}
	if (
		person &&
		!env.NETHOUND_NO_UPDATE_CHECK &&
		!env.NO_UPDATE_NOTIFIER &&
		command !== "upgrade"
	) {
		const update = updateNotice(pkg.version, selfPath(), stateFile());
		notice = notice && update ? `${notice}\n\n${update}` : (notice ?? update);
	}
	if (command === "upgrade") return upgrade();
	if (command === "completion") {
		const shell = args[0];
		if (!SHELLS.includes(shell as CompletionShell))
			return usage(`completion takes one of: ${SHELLS.join(", ")}`);
		process.stdout.write(completionScript(shell as CompletionShell));
		return 0;
	}

	const tty = process.stdout.isTTY;
	if (command === "watch") {
		if (!process.stdin.isTTY || !tty)
			return usage("watch needs a terminal: use nethound list in scripts");
		await runWatch({
			color: !process.env.NO_COLOR,
			args: [
				...(values["no-docker"] ? ["--no-docker"] : []),
				...(values["show-secrets"] ? ["--show-secrets"] : []),
			],
			// PowerShell takes a couple of seconds to start: refresh less often on Windows
			interval: process.platform === "win32" ? 3000 : 1500,
			probe: !values["no-probe"],
		});
		return 0;
	}
	const snap: Snapshot = collect({
		...(values["no-docker"] && { containers: [] }),
		windows: command === "doctor",
		windowsRouting: ["doctor", "map", "route", "conns", "who"].includes(
			command ?? "",
		),
		firewall: command === "doctor" || command === "who",
	});
	if (!values["show-secrets"])
		for (const p of snap.processes) p.cmd = maskCmd(p.cmd);
	if (values.snapshot) {
		process.stdout.write(JSON.stringify(snap));
		return 0;
	}
	const opts: RenderOptions = {
		color: tty && !process.env.NO_COLOR,
		width: tty ? process.stdout.columns : undefined,
		wsl: snap.environment === "wsl",
		windows: snap.environment === "windows",
	};
	const print = (render: () => string, data: () => unknown) =>
		console.log(values.json ? JSON.stringify(data(), null, 2) : render());
	const proto = (p: "tcp" | "udp") =>
		values.tcp || values.udp ? !!values[p] : true;
	const hiddenNote = () => {
		const n = unowned(snap);
		if (n && !values.json)
			console.error(
				paint({
					...opts,
					color: !!process.stderr.isTTY && !process.env.NO_COLOR,
				}).dim(
					`\n${n} sockets belong to other users' processes: ${elevate(opts)} to see which`,
				),
			);
	};

	switch (command) {
		case "list": {
			const ls = listeners(snap).filter((l) => proto(l.proto));
			print(
				() => renderList(ls, opts),
				() => ls.map(listenerJson),
			);
			hiddenNote();
			return 0;
		}
		case "who": {
			const port = Number(args[0]?.replace(/^:/, ""));
			if (!args[0] || !Number.isInteger(port) || port < 1 || port > 65535)
				return usage("who takes a port number, e.g. nethound who 5432");
			const r = who(snap, port);
			print(
				() => renderWho(r, { ...opts, home: homedir() }, snap),
				() => ({
					port,
					listeners: r.listeners.map(listenerJson),
					inside: r.inside.map(insideJson),
					outbound: r.outbound.map(connectionJson),
					relayed: r.relayed.map(connectionJson),
				}),
			);
			return r.listeners.length || r.outbound.length || r.inside.length ? 0 : 1;
		}
		case "conns": {
			const cs = connections(snap)
				.filter((c) => proto(c.proto))
				.filter((c) => values.all || c.state === "ESTABLISHED");
			print(
				() => renderConnections(cs, opts),
				() => cs.map(connectionJson),
			);
			hiddenNote();
			return 0;
		}
		case "interfaces": {
			const m = map(snap);
			print(
				() => renderInterfaces(m.interfaces, m.idle, opts),
				() => m.interfaces.map(ifaceViewJson),
			);
			return 0;
		}
		case "route": {
			const host = args[0];
			if (!host)
				return usage(
					"route takes a host name or an address, e.g. nethound route github.com",
				);
			let ip = host;
			// in WSL, a name only Windows' DNS servers know (a VPN's): Windows resolves it
			let byWindows = false;
			if (!isIP(host)) {
				try {
					ip = (await lookup(host)).address;
				} catch {
					const found =
						snap.environment === "wsl"
							? parseNslookup(run("nslookup.exe", [host]))
							: [];
					const first = found.find((a) => isIP(a) === 4) ?? found[0];
					if (!first) {
						console.error(`nethound: cannot resolve ${host}`);
						return 1;
					}
					ip = first;
					byWindows = true;
				}
			}
			const r = routeTo(snap, ip);
			const next = throughWindows(snap, r);
			if (next) r.windows = next;
			print(
				() =>
					renderRoute(r, host, opts) +
					(byWindows
						? `\n${paint(opts).yellow(`resolved by Windows: WSL can't resolve ${host} (nethound doctor says why)`)}`
						: ""),
				() => ({
					host,
					...(byWindows && { resolvedBy: "windows" }),
					...routeJson(r),
				}),
			);
			return r.kind === "unreachable" ? 1 : 0;
		}
		case "doctor": {
			const findings = doctor(snap);
			print(
				() => renderDoctor(findings, opts),
				() => findings,
			);
			hiddenNote();
			return findings.some((f) => f.severity === "error") ? 1 : 0;
		}
		case "kill": {
			const port = Number(args[0]?.replace(/^:/, ""));
			if (!args[0] || !Number.isInteger(port) || port < 1 || port > 65535)
				return usage("kill takes a port number, e.g. nethound kill 3000");
			return killPort(snap, port, {
				tree: !!values.tree,
				force: !!values.force,
				yes: !!values.yes,
				opts,
			});
		}
		case "open": {
			const port = Number(args[0]?.replace(/^:/, ""));
			if (args[0] && (!Number.isInteger(port) || port < 1 || port > 65535))
				return usage("open takes a port number, e.g. nethound open 3000");
			if (!args[0] && values["no-probe"])
				return usage(
					"open lists the ports that answer HTTP, which means asking them: give a PORT to open it unchecked",
				);
			return openPort(snap, args[0] ? port : undefined, {
				json: !!values.json,
				probe: !values["no-probe"],
				opts: { ...opts, width: undefined },
			});
		}
		case "map": {
			const m = map(snap);
			print(
				() => renderMap(m, opts),
				() => mapJson(m),
			);
			return 0;
		}
	}
	return usage(`no command '${given}'`);
}

/** The ports listening now, for `who`, `kill` and `open` completion: what holds each, and where it runs. */
function portCandidates(): PortCandidate[] {
	const home = homedir();
	const by = new Map<number, string>();
	for (const l of listeners(collect()))
		if (!by.has(l.port))
			by.set(
				l.port,
				l.container
					? `container ${l.container.name}`
					: l.process
						? `${procLabel(l.process)}  ${place(l.process, home)}`
						: `${l.user ?? "another user"}'s process`,
			);
	return [...by]
		.sort((a, b) => a[0] - b[0])
		.map(([port, about]) => ({ port, about }));
}

/**
 * Replaces this nethound with the latest release, checked against SHA256SUMS and against npm's copy,
 * when it was installed with install.sh or install.ps1; other installs get the command to run.
 */
async function upgrade(): Promise<number> {
	const script = realpathSync(selfPath());
	const kind = installKind(script);
	const binary = compiled();
	const file = binary ? binaryName() : "nethound.js";
	if (!file) {
		console.error("nethound: no nethound binary is built for this platform");
		return 1;
	}
	if (kind !== "standalone") {
		console.log(
			`This nethound was not installed with ${process.platform === "win32" ? "install.ps1" : "install.sh"}. Update it with:\n  ${upgradeCommand(kind)}`,
		);
		return 0;
	}
	let release: Release;
	try {
		release = await latestRelease(process.env, file);
	} catch (e) {
		console.error(
			`nethound: ${e instanceof Error ? e.message : e}; nothing was changed`,
		);
		return 1;
	}
	if (!newer(release.version, pkg.version)) {
		console.log(`nethound ${pkg.version} is the latest version`);
		return 0;
	}
	if (binary) replaceBinary(script, release.data);
	else replaceScript(script, release.data);
	console.log(
		`upgraded nethound ${pkg.version} to ${release.version} in ${dirname(script)}`,
	);
	return 0;
}

main(process.argv.slice(2)).then(
	(code) => {
		process.exitCode = code;
		if (notice) process.stderr.write(`\n${notice}\n`);
	},
	(e: unknown) => {
		if (
			e instanceof Error &&
			"code" in e &&
			String(e.code).startsWith("ERR_PARSE_ARGS")
		)
			process.exitCode = usage(e.message);
		else {
			console.error(`nethound: ${e instanceof Error ? e.message : String(e)}`);
			process.exitCode = 1;
		}
	},
);
