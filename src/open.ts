// nethound open [PORT]: open what listens on PORT in the browser, once it answered HTTP or HTTPS;
// without PORT, list every port a browser can open, with its URL and what holds it.

import { homedir } from "node:os";
import { type Listener, listeners, who } from "./analyze.ts";
import { paint, place, type RenderOptions } from "./format.ts";
import type { Snapshot } from "./model.ts";
import {
	notWeb,
	openUrl,
	probe,
	unchecked,
	type Web,
	webLabel,
} from "./web.ts";

const owner = (l: Listener, home: string) =>
	l.container
		? `container ${l.container.name}`
		: l.process
			? `${l.process.name} ${l.process.pid}  ${place(l.process, home)}`.trim()
			: `${l.user ?? "another user"}'s process`;

/** Every TCP port that answers HTTP, asked all at once. */
async function webPorts(snap: Snapshot): Promise<[Listener, Web][]> {
	const ls = listeners(snap).filter((l) => !notWeb(l));
	const answers = await Promise.all(ls.map((l) => probe(l)));
	return ls
		.map((l, i) => [l, answers[i]] as [Listener, Web])
		.filter(([, w]) => w.kind !== "none");
}

export async function openPort(
	snap: Snapshot,
	port: number | undefined,
	o: { json: boolean; probe: boolean; opts: RenderOptions },
): Promise<number> {
	const c = paint(o.opts);
	const home = homedir();
	if (port === undefined) {
		const found = await webPorts(snap);
		if (o.json)
			console.log(
				JSON.stringify(
					found.map(([l, w]) => ({ port: l.port, ...w })),
					null,
					2,
				),
			);
		else if (!found.length)
			console.error("nethound: nothing here answers HTTP");
		else {
			const widest = (f: (w: Web) => string) =>
				Math.max(...found.map(([, w]) => f(w).length));
			const url = (w: Web) => (w.kind === "none" ? "" : w.url);
			const [urls, labels] = [widest(url), widest(webLabel)];
			// pages plain, APIs faded: what a person opens stands out
			for (const [l, w] of found) {
				const label = webLabel(w).padEnd(labels);
				console.log(
					`${c.cyan(url(w).padEnd(urls))}  ${w.kind === "page" ? label : c.dim(label)}  ${owner(l, home)}`,
				);
			}
			console.log(c.dim("\nnethound open PORT opens one in the browser"));
		}
		return found.length ? 0 : 1;
	}
	const ls = who(snap, port).listeners.filter((l) => l.proto === "tcp");
	if (!ls.length) {
		console.error(`nethound: nothing listens on tcp ${port}`);
		return 1;
	}
	for (const l of ls) {
		const w = o.probe ? await probe(l) : unchecked(l);
		if (w.kind === "none") continue;
		if (o.json) {
			console.log(JSON.stringify({ port, ...w }, null, 2));
			return 0;
		}
		console.log(
			`opening ${c.cyan(w.url)}  ${c.dim(`${webLabel(w)}  ${owner(l, home)}`)}`,
		);
		const error = await openUrl(w.url, l, snap.environment);
		if (error) {
			console.error(`nethound: ${error}`);
			return 1;
		}
		return 0;
	}
	const l = ls[0] as Listener;
	const what = notWeb(l);
	console.error(
		`nethound: tcp ${port} (${owner(l, home)}) ${
			!what
				? "doesn't answer HTTP or HTTPS"
				: what.startsWith("port ")
					? "is on a port that doesn't speak HTTP (a database, ssh, DNS…)"
					: `is ${what}, not a web server`
		}`,
	);
	return 1;
}
