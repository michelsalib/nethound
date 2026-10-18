import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { placeParts } from "../src/format.ts";
import type { Process } from "../src/model.ts";
import { annotate, decodeProject } from "../src/origin.ts";

// Claude Code's scratch folders (/tmp/claude-UID/…) are Linux's and macOS's
const windows = process.platform === "win32";

// a directory tree as decodeProject lists it
const tree: Record<string, string[]> = {
	"/": ["home"],
	"/home": ["me"],
	"/home/me": ["orca", "my.app"],
	"/home/me/orca": ["workspaces"],
	"/home/me/orca/workspaces": ["matchem-dp", "matchem-dp-infra"],
	"/home/me/orca/workspaces/matchem-dp": ["writer-rich-text"],
};
const list = (d: string) => tree[d] ?? [];

test("a Claude project name back to its directory, level by level", () => {
	expect(
		decodeProject("-home-me-orca-workspaces-matchem-dp-writer-rich-text", list),
	).toEqual({
		dir: "/home/me/orca/workspaces/matchem-dp/writer-rich-text",
	});
	// the longest match: matchem-dp-infra is a directory of its own
	expect(
		decodeProject("-home-me-orca-workspaces-matchem-dp-infra", list),
	).toEqual({
		dir: "/home/me/orca/workspaces/matchem-dp-infra",
	});
	// dots are encoded as dashes too
	expect(decodeProject("-home-me-my-app", list)).toEqual({
		dir: "/home/me/my.app",
	});
	// a worktree removed since: what is left of the name
	expect(
		decodeProject("-home-me-orca-workspaces-matchem-dp-gt-846-seo", list),
	).toEqual({
		dir: "/home/me/orca/workspaces/matchem-dp",
		missing: "gt-846-seo",
	});
});

const p = (
	pid: number,
	ppid: number,
	name: string,
	cmd: string,
	extra: Partial<Process> = {},
): Process => ({
	pid,
	ppid,
	name,
	cmd,
	uid: 1000,
	...extra,
});

test("the app that launched a process, through bash -c and runners", () => {
	const ps = [
		p(10, 1, "claude", "claude --dangerously-skip-permissions"),
		p(20, 10, "bash", "/bin/bash -c bun ui"),
		p(30, 20, "bun", "bun packages/dev/serve.ts", {
			git: { root: "/w/app", branch: "main", worktree: true },
		}),
		p(
			40,
			1,
			"MainThread",
			"/home/me/.vscode-server/bin/abc/node /home/me/.vscode-server/bin/abc/out/server-main.js",
		),
		p(50, 40, "node", "node /tmp/x.js"),
		p(60, 1, "node", "/home/me/.orca-wsl/hook-relay/wsl-agent-hook-relay.js"),
		p(70, 1, "zsh", "-zsh"),
		p(80, 70, "node", "node server.js"),
		// claude in an Orca terminal, its bash cd-ing into an Orca worktree: still claude's
		p(
			90,
			1,
			"bash",
			"/bin/bash --rcfile /mnt/c/Users/me/AppData/Roaming/orca/shell-wrappers/4e6b/shell-ready/bash/rcfile",
		),
		p(100, 90, "claude", "claude"),
		p(
			110,
			100,
			"bash",
			"/bin/bash -c eval 'cd /home/me/orca/workspaces/app/GT-862 && bun src/server.ts'",
		),
		p(120, 110, "bun", "bun src/server.ts"),
	];
	annotate(ps);
	const app = (pid: number) => ps.find((x) => x.pid === pid)?.app;
	expect([app(30), app(50), app(60), app(80), app(90), app(120)]).toEqual([
		"claude",
		"VS Code",
		"Orca",
		undefined,
		"Orca",
		"claude",
	]);
	// a checkout of its own: no project borrowed
	expect(ps.find((x) => x.pid === 30)?.project).toBeUndefined();
});

test.skipIf(windows)(
	"a browser a Claude session left behind, its worktree removed since",
	() => {
		const top = mkdtempSync(join(tmpdir(), "nethound-origin-"));
		const ws = join(top, "ws");
		mkdirSync(join(ws, "app", ".git"), { recursive: true });
		writeFileSync(join(ws, "app", ".git", "HEAD"), "ref: refs/heads/main\n");
		const encoded = ws.replace(/[^A-Za-z0-9]/g, "-");
		const session = "1daf761c-3115-4871-bd63-ae5e47e4d26c";
		const scratch = (project: string) =>
			`/tmp/claude-1000/${encoded}-${project}/${session}/scratchpad/cdp`;
		const ps = [
			// its session is over: its parent is init now
			p(
				100,
				1,
				"chrome",
				"chrome --headless=new --remote-debugging-port=9333",
				{
					cwd: scratch("gt-846-seo"),
				},
			),
			// a session still running, in a worktree that exists
			p(200, 1, "claude", "claude"),
			p(210, 200, "chrome", "chrome --headless=new", { cwd: scratch("app") }),
		];
		annotate(ps);
		const [gone, , live] = ps;
		expect(gone).toMatchObject({
			app: "claude",
			orphan: true,
			project: { root: join(ws, "gt-846-seo"), removed: true, via: "session" },
		});
		expect(live?.orphan).toBeUndefined();
		expect(live?.project).toMatchObject({
			root: join(ws, "app"),
			branch: "main",
			via: "session",
		});
		expect(placeParts(gone as Process)).toEqual({
			name: "gt-846-seo",
			tags: "(removed) · claude",
		});
		expect(placeParts(live as Process)).toEqual({
			name: "app (main)",
			tags: "· claude",
		});
	},
);

test.skipIf(windows)(
	"a symlinked directory on the way, as macOS's /var: still decoded",
	() => {
		const top = mkdtempSync(join(tmpdir(), "nethound-link-"));
		mkdirSync(join(top, "real", "my.app"), { recursive: true });
		symlinkSync(join(top, "real"), join(top, "linked"), "junction");
		const encoded = join(top, "linked", "my.app").replace(/[^A-Za-z0-9]/g, "-");
		expect(decodeProject(encoded).missing).toBeUndefined();
		expect(decodeProject(encoded).dir).toEndWith(join("linked", "my.app"));
	},
);

test("a project from the parent in a checkout; an app's own process named after the app", () => {
	const ps = [
		p(10, 1, "bun", "bun run dev", {
			git: { root: "/w/app-feature", branch: "feature-x", worktree: true },
		}),
		p(20, 10, "chrome", "chrome --headless", { cwd: "/tmp/chrome-profile" }),
		p(
			30,
			1,
			"MainThread",
			"/home/me/.vscode-server/bin/abc/node server-main.js",
			{ cwd: "/mnt/c/Program Files/Microsoft VS Code" },
		),
	];
	annotate(ps);
	expect(ps[1]?.project).toMatchObject({
		root: "/w/app-feature",
		branch: "feature-x",
		via: "parent",
	});
	expect(placeParts(ps[1] as Process)).toEqual({
		name: "app-feature (feature-x)",
		tags: "",
	});
	// a Windows path says less than "VS Code"
	expect(placeParts(ps[2] as Process)).toEqual({ name: "", tags: "VS Code" });
	// a worktree named after its branch: once
	expect(
		placeParts({
			...p(1, 0, "bun", "bun"),
			git: { root: "/w/writer", branch: "writer", worktree: true },
		}).name,
	).toBe("writer");
});
