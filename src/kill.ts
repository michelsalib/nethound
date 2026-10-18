// nethound kill PORT: stop what listens on a port, after saying exactly what that is (which
// worktree's dev server), and asking.

import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import { who } from "./analyze.ts";
import { paint, place, type RenderOptions } from "./format.ts";
import type { Process, Snapshot } from "./model.ts";
import { alive, startedBy, stop, treeOf } from "./stop.ts";

export interface KillOptions {
	/** With the runners that started it (bun run dev, npm), so nothing starts it again. */
	tree: boolean;
	/** SIGKILL rather than SIGTERM. */
	force: boolean;
	/** Without asking. */
	yes: boolean;
	opts: RenderOptions;
}

const sleep = (ms: number) => new Promise((ok) => setTimeout(ok, ms));

export async function killPort(
	snap: Snapshot,
	port: number,
	o: KillOptions,
): Promise<number> {
	const c = paint(o.opts);
	const home = homedir();
	const ls = who(snap, port).listeners;
	if (!ls.length) {
		console.error(`nethound: nothing listens on ${port}`);
		return 1;
	}
	const pids = new Set<number>();
	const containers = new Set<string>();
	const plan: string[] = [];
	let unreachable = 0;
	const describe = (p: Process) => {
		const parent = startedBy(snap, p.pid)[0];
		return `${c.bold(`${p.name} ${p.pid}`)}  ${place(p, home)}${parent ? c.dim(`  started by ${parent.name} ${parent.pid}`) : ""}`;
	};
	for (const l of ls) {
		const on = c.dim(`${l.proto} ${l.port}`);
		if (l.container) {
			containers.add(l.container.name);
			plan.push(
				`${on}  container ${c.bold(l.container.name)}  ${c.dim(`docker stop ${l.container.name}`)}`,
			);
		} else if (l.process) {
			const ps = o.tree ? treeOf(snap, l.process.pid) : [l.process];
			plan.push(`${on}  ${describe(l.process)}`);
			for (const p of ps) {
				if (p.pid !== l.process.pid)
					plan.push(`         ${c.dim("and")} ${describe(p)}`);
				pids.add(p.pid);
			}
		} else {
			unreachable++;
			plan.push(
				`${on}  ${l.user ?? "another user"}'s process: ${o.opts.windows ? "run as administrator" : "run with sudo"} to stop it`,
			);
		}
	}
	console.log(plan.join("\n"));
	if (!pids.size && !containers.size) return 1;
	if (!o.yes) {
		if (!process.stdin.isTTY) {
			console.error("nethound: pass -y (--yes) to stop without asking");
			return 2;
		}
		const rl = createInterface({
			input: process.stdin,
			output: process.stdout,
		});
		const answer = await rl.question(
			`${o.force ? "force-stop (SIGKILL)" : "stop"} ${[...pids, ...containers].length === 1 ? "it" : "them"}? [y/N] `,
		);
		rl.close();
		if (!/^y(es)?$/i.test(answer.trim())) {
			console.log("nothing stopped");
			return 1;
		}
	}
	let failed = unreachable;
	for (const r of stop([...pids], o.force)) {
		if (r.result === "denied") {
			failed++;
			console.error(
				`${r.pid}: not yours: ${o.opts.windows ? "run as administrator" : "run with sudo"}`,
			);
		} else if (r.result === "failed") {
			failed++;
			console.error(`${r.pid}: ${r.error}`);
		}
	}
	for (const name of containers) {
		const r = spawnSync("docker", ["stop", name], {
			stdio: "ignore",
			windowsHide: true,
		});
		if (r.status === 0) console.log(`stopped container ${name}`);
		else {
			failed++;
			console.error(`docker stop ${name} failed`);
		}
	}
	// a stopped server takes a moment to close: up to 3 s
	let running = [...pids].filter(alive);
	for (let t = 0; running.length && t < 30; t++) {
		await sleep(100);
		running = running.filter(alive);
	}
	const stopped = [...pids].filter((p) => !running.includes(p));
	if (stopped.length) console.log(c.green(`stopped ${stopped.join(", ")}`));
	if (running.length) {
		console.error(
			`still running: ${running.join(", ")}${o.force ? "" : ` (nethound kill ${port} --force)`}`,
		);
		return 1;
	}
	return failed ? 1 : 0;
}
