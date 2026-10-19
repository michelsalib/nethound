import { expect, test } from "bun:test";
import { insideListeners, publishedTarget, who } from "../src/analyze.ts";
import { doctor } from "../src/doctor.ts";
import { renderWho } from "../src/format.ts";
import type { Snapshot } from "../src/model.ts";
import { fixture, pg } from "./helpers.ts";

const o = { color: false };

test("a container's own sockets, and another namespace's; docker's DNS left out", () => {
	const snap = fixture();
	expect(snap.namespaces).toEqual([
		{
			inode: 4026532100,
			container: pg.id,
			pids: [600],
			sockets: [
				expect.objectContaining({
					local: { address: "0.0.0.0", port: 5432 },
					state: "LISTEN",
					pid: 600,
				}),
			],
		},
		{
			inode: 4026532200,
			pids: [610],
			sockets: [
				expect.objectContaining({ local: { address: "0.0.0.0", port: 8765 } }),
			],
		},
	]);
	expect(
		insideListeners(snap).map(
			(l) => `${l.proto} ${l.port} ${l.process?.name} ${l.container?.name}`,
		),
	).toEqual(["tcp 5432 postgres pg", "tcp 8765 python3 undefined"]);
	// docker inspect gave no pid, or the container is on the host's network: postgres 600 is
	// found by its own namespace, but not as pg's
	for (const c of [
		{ ...pg, pid: undefined },
		{ ...pg, networks: [{ name: "host" }] },
	])
		expect(fixture([c]).namespaces?.map((n) => n.container)).toEqual([
			undefined,
			undefined,
		]);
});

test("who: what listens behind a published port, and ports inside only", () => {
	const snap = fixture();
	expect(renderWho(who(snap, 5432), o, snap)).toContain(
		"  inside     postgres 600 on 0.0.0.0:5432",
	);
	const out = renderWho(who(snap, 8765), o, snap);
	expect(out).toStartWith(
		"tcp 8765  inside the namespace of python3 610  not published",
	);
	expect(out).toContain("reachable  from that namespace's interfaces");
});

/** pg with its server on another port, or on its own loopback. */
function serving(address: string, port: number): Snapshot {
	const snap = structuredClone(fixture());
	const ns = snap.namespaces?.find((n) => n.container === pg.id);
	const s = ns?.sockets?.[0];
	if (s) s.local = { address, port };
	return snap;
}

test("doctor: a published port where nothing listens, or only the container's loopback", () => {
	expect(
		doctor(fixture()).filter((f) => f.rule === "published-nowhere"),
	).toEqual([]);
	const moved = serving("0.0.0.0", 5433);
	const pgPort = pg.ports[0];
	if (!pgPort) throw new Error("pg publishes nothing");
	expect(publishedTarget(moved, pg, pgPort).state).toBe("nothing");
	const [f] = doctor(moved).filter((x) => x.rule === "published-nowhere");
	expect(f).toMatchObject({
		severity: "warning",
		title: "tcp 5432 goes to 5432 in container pg, where nothing listens",
		fix: 'publish the port it listens on: -p 5432:5433 (in compose: "5432:5433")',
	});
	expect(f?.details[1]).toBe("in the container, 5433 listens instead");
	const local = serving("127.0.0.1", 5432);
	expect(
		doctor(local).find((x) => x.rule === "published-nowhere"),
	).toMatchObject({
		title:
			"tcp 5432 goes to container pg, where 5432 listens on 127.0.0.1 only",
		details: [
			"docker forwards to the container's own address (172.18.0.2), which its server doesn't take: connections are reset",
		],
	});
	expect(renderWho(who(local, 5432), o, local)).toContain(
		"inside     postgres 600 listens on 127.0.0.1 only: the published port can't reach it",
	);
	// sockets not read (Docker Desktop's VM): nothing said
	const unread = structuredClone(fixture());
	unread.namespaces = [];
	expect(publishedTarget(unread, pg, pgPort).state).toBe("unknown");
	expect(doctor(unread).filter((x) => x.rule === "published-nowhere")).toEqual(
		[],
	);
});
