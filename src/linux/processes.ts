// Which process owns each socket: /proc/PID/fd links to socket:[INODE]. Other users' fd
// directories are unreadable without root; nethound counts them so it can say so.

import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import type { Process } from "../model.ts";

export interface ProcessScan {
	processes: Process[];
	/** Socket inode → pid. A socket shared by several processes (a forked server) keeps the first. */
	owners: Map<number, number>;
	/** Processes whose fd directory could not be read. */
	hidden: number;
}

export function scanProcesses(proc: string): ProcessScan {
	const processes: Process[] = [];
	const owners = new Map<number, number>();
	let hidden = 0;
	let pids: string[] = [];
	try {
		pids = readdirSync(proc).filter((d) => /^\d+$/.test(d));
	} catch {}
	// lowest pid first, so a forked server's sockets go to the parent
	pids.sort((a, b) => Number(a) - Number(b));
	// boot time, in seconds since the epoch: processes' start times count from it
	let boot = 0;
	try {
		const btime = readFileSync(join(proc, "stat"), "utf8").match(
			/^btime (\d+)/m,
		);
		boot = Number(btime?.[1] ?? 0) * 1000;
	} catch {}
	for (const p of pids) {
		const pid = Number(p);
		const dir = join(proc, p);
		let fds: string[];
		// every process, socket or not: a server's parent (bun run dev) is one too. Its name, command
		// line and parent can be read whoever it belongs to; its open files only with root, or if ours
		processes.push(readProcess(dir, pid, boot));
		try {
			fds = readdirSync(join(dir, "fd"));
		} catch {
			hidden++;
			continue;
		}
		for (const fd of fds) {
			let target: string;
			try {
				target = readlinkSync(join(dir, "fd", fd));
			} catch {
				continue;
			}
			const m = target.match(/^socket:\[(\d+)\]$/);
			if (!m) continue;
			const inode = Number(m[1]);
			if (!owners.has(inode)) owners.set(inode, pid);
		}
	}
	return { processes, owners, hidden };
}

function readProcess(dir: string, pid: number, boot: number): Process {
	const text = (f: string) => {
		try {
			return readFileSync(join(dir, f), "utf8");
		} catch {
			return "";
		}
	};
	const comm = text("comm").trim();
	const argv = text("cmdline").split("\0").filter(Boolean);
	// comm is the main thread's name, which runtimes rename ("MainThread"): then the program's name
	const program = argv[0]?.split("/").pop();
	const name =
		(comm && argv.join(" ").includes(comm) ? comm : program || comm) ||
		String(pid);
	const cmd = argv.join(" ") || `[${name}]`;
	const uid = Number(text("status").match(/^Uid:\s+(\d+)/m)?.[1] ?? -1);
	// after the name in parentheses, which may hold spaces: state, ppid, … starttime (the 22nd field)
	const stat = text("stat");
	const f = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
	const ppid = Number(f[1]);
	const ticks = Number(f[19]);
	let cwd: string | undefined;
	try {
		cwd = readlinkSync(join(dir, "cwd"));
	} catch {}
	return {
		pid,
		name,
		cmd,
		uid,
		...(ppid > 0 && { ppid }),
		// clock ticks after boot: 100 a second (USER_HZ) on every Linux
		...(boot && ticks >= 0 && { started: boot + ticks * 10 }),
		...(cwd && { cwd }),
	};
}

/** User names by uid, from an /etc/passwd file. */
export function readUsers(passwd: string): Record<number, string> {
	const users: Record<number, string> = {};
	let text = "";
	try {
		text = readFileSync(passwd, "utf8");
	} catch {}
	for (const line of text.split("\n")) {
		const [name, , uid] = line.split(":");
		if (name && uid && /^\d+$/.test(uid)) users[Number(uid)] = name;
	}
	return users;
}
