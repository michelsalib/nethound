// Terminal driver for `nethound watch`: raw keys and mouse clicks in, full redraws out, on the alternate screen so
// the user's scrollback is left as it was. Each refresh runs nethound itself in the background
// (--snapshot), so reading the machine never freezes the screen: a couple of seconds on Windows. The
// selected port is asked once whether it answers HTTP, in the background too; the others never are.

import { execFile, spawn } from "node:child_process";
import { homedir } from "node:os";
import { emitKeypressEvents } from "node:readline";
import { PassThrough } from "node:stream";
import type { Snapshot } from "../model.ts";
import { alive, stop } from "../stop.ts";
import { compiled } from "../update.ts";
import { openUrl, probe } from "../web.ts";
import { handleMouse, MOUSE_OFF, MOUSE_ON, readMouse } from "./mouse.ts";
import {
	applySnapshot,
	type Effect,
	handleKey,
	initialState,
	type Key,
	type State,
	selectedRow,
} from "./state.ts";
import { render, scrolled, tableRoom } from "./view.ts";

const ENTER = `\x1b[?1049h\x1b[?25l${MOUSE_ON}`; // alternate screen, hide cursor, report the mouse
const LEAVE = `${MOUSE_OFF}\x1b[?25h\x1b[?1049l`;

/** How to run this nethound again: the binary itself, or the runtime and the script. */
const self = (): [string, string[]] =>
	compiled()
		? [process.execPath, []]
		: [process.execPath, [process.argv[1] ?? ""]];

export interface WatchOptions {
	color: boolean;
	/** Passed on to each snapshot: --no-docker, --show-secrets. */
	args: string[];
	/** Between the end of one snapshot and the start of the next. */
	interval: number;
	/** Ask the selected port whether it answers HTTP (not with --no-probe). */
	probe: boolean;
}

export function runWatch(o: WatchOptions): Promise<void> {
	const stdin = process.stdin;
	const stdout = process.stdout;
	const home = homedir();
	let state: State = initialState(process.pid, o.probe);
	let timer: ReturnType<typeof setTimeout> | undefined;
	let reading = false;
	let done = false;
	/** Rows being asked whether they answer HTTP. */
	const asking = new Set<string>();

	return new Promise((resolve) => {
		const height = () => Math.max(8, stdout.rows || 24);
		const draw = () => {
			if (done) return;
			// the last column left empty: some terminals wrap after a full-width line
			const width = Math.max(20, (stdout.columns || 80) - 1);
			// the list scrolls only as far as the selection needs, and stays there
			state = { ...state, top: scrolled(state, tableRoom(height())) };
			const lines = render(state, width, height(), {
				color: o.color,
				now: Date.now(),
				home,
				windows: state.snap?.environment === "windows",
				wsl: state.snap?.environment === "wsl",
			});
			stdout.write(
				`\x1b[H${lines.map((l) => `${l}\x1b[K`).join("\r\n")}\x1b[J`,
			);
			// whatever moved the selection (a key, a click, a snapshot, the filter) drew it
			ask();
		};

		const read = () => {
			if (reading || done) return;
			reading = true;
			clearTimeout(timer);
			const [cmd, args] = self();
			execFile(
				cmd,
				[...args, "--snapshot", ...o.args],
				{ maxBuffer: 64 * 1024 * 1024, windowsHide: true },
				(error, out) => {
					reading = false;
					if (done) return;
					try {
						if (error) throw error;
						state = applySnapshot(
							state,
							JSON.parse(out) as Snapshot,
							Date.now(),
						);
						if (state.message?.text === "refreshing…")
							state = { ...state, message: undefined };
					} catch (e) {
						state = {
							...state,
							message: {
								text: `could not read the machine: ${(e as Error).message}`,
								error: true,
							},
						};
					}
					draw();
					timer = setTimeout(read, o.interval);
				},
			);
		};

		// the selected port, once it is selected and not asked yet: answers come in a few
		// milliseconds, the silent ones within the probe's timeout
		const ask = () => {
			const r = selectedRow(state);
			if (!o.probe || !r || r.closed || state.web[r.key] || asking.has(r.key))
				return;
			asking.add(r.key);
			probe(r.listener).then((web) => {
				asking.delete(r.key);
				if (done || !state.rows.some((x) => x.key === r.key && !x.closed))
					return;
				state = { ...state, web: { ...state.web, [r.key]: web } };
				// `o` pressed before the answer came, on this port still: open it now, or say why not
				if (
					state.message?.text.startsWith("asking ") &&
					selectedRow(state)?.key === r.key
				) {
					const [next, effect] = handleKey(state, { ch: "o" });
					state = next;
					draw();
					if (effect) run(effect);
					return;
				}
				draw();
			});
		};

		const run = (effect: Effect) => {
			switch (effect.kind) {
				case "quit":
					return finish();
				case "refresh":
					return read();
				case "stop": {
					const results = stop(effect.pids, effect.force);
					const denied = results.filter((r) => r.result === "denied").length;
					const failed = results.find((r) => r.result === "failed");
					state = {
						...state,
						message: failed
							? {
									text: `could not stop ${failed.pid}: ${failed.error}`,
									error: true,
								}
							: denied
								? {
										text: `${denied} not yours: run nethound with sudo (or as administrator) to stop them`,
										error: true,
									}
								: {
										text: effect.force
											? `killed ${effect.pids.join(", ")}`
											: `asked ${effect.pids.join(", ")} to stop; still running in a moment? k again forces it`,
									},
					};
					// see it go: a snapshot soon, another once it had time to exit
					setTimeout(() => {
						if (!effect.force && effect.pids.every((pid) => !alive(pid)))
							state = {
								...state,
								message: { text: `stopped ${effect.pids.join(", ")}` },
							};
						read();
					}, 700);
					return;
				}
				case "open": {
					openUrl(
						effect.url,
						effect.row.listener,
						state.snap?.environment ?? "linux",
					).then((error) => {
						state = {
							...state,
							message: error
								? { text: error, error: true }
								: { text: `opened ${effect.url}` },
						};
						draw();
					});
					return;
				}
				case "docker-stop": {
					state = {
						...state,
						message: { text: `docker stop ${effect.container}…` },
					};
					const child = spawn("docker", ["stop", effect.container], {
						stdio: "ignore",
						windowsHide: true,
					});
					child.on("error", (e) => {
						state = {
							...state,
							message: {
								text: `could not run docker: ${e.message}`,
								error: true,
							},
						};
						draw();
					});
					child.on("exit", (code) => {
						state = {
							...state,
							message:
								code === 0
									? { text: `stopped container ${effect.container}` }
									: {
											text: `docker stop ${effect.container} failed (exit ${code})`,
											error: true,
										},
						};
						read();
					});
					return;
				}
			}
		};

		const onKey = (
			str: string | undefined,
			key:
				| { name?: string; ctrl?: boolean; meta?: boolean; shift?: boolean }
				| undefined,
		) => {
			const ch =
				str &&
				!key?.ctrl &&
				!key?.meta &&
				[...str].length === 1 &&
				str >= " " &&
				str !== "\x7f"
					? str
					: undefined;
			const k: Key = {
				name: key?.name,
				ch,
				ctrl: key?.ctrl,
				shift: key?.shift,
			};
			const [next, effect] = handleKey(state, k);
			state = next;
			draw();
			if (effect) run(effect);
		};

		// the mouse reports taken out of what the terminal sends; the keys go on to readline
		const keys = new PassThrough();
		let pending = "";
		const onData = (data: Buffer) => {
			const read = readMouse(pending + data.toString("utf8"));
			pending = read.pending;
			if (read.rest) keys.write(read.rest);
			for (const m of read.events) {
				const [next, effect] = handleMouse(state, m, height());
				if (next === state && !effect) continue;
				state = next;
				draw();
				if (effect) run(effect);
			}
		};

		// the "updated 3s ago" line, and marks fading, move on between snapshots
		const tick = setInterval(draw, 1000);

		const finish = () => {
			done = true;
			clearTimeout(timer);
			clearInterval(tick);
			stdin.off("data", onData);
			keys.off("keypress", onKey);
			stdout.off("resize", draw);
			stdin.setRawMode(false);
			stdin.pause();
			stdout.write(LEAVE);
			resolve();
		};

		emitKeypressEvents(keys);
		keys.on("keypress", onKey);
		stdin.on("data", onData);
		stdout.on("resize", draw);
		stdout.write(ENTER);
		stdin.setRawMode(true);
		stdin.resume();
		draw();
		read();
	});
}
