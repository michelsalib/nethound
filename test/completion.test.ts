import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { complete, completionScript } from "../src/completion.ts";

const ports = () => [
	{ port: 3000, about: "node 4127  app-feature (feature-x)" },
	{ port: 5432, about: "container pg" },
	{ port: 5173, about: "node 4200  app (main)" },
];
let asked = 0;
const counting = () => {
	asked++;
	return ports();
};
const names = (words: string[]) =>
	complete(words, counting).map((c) => c.split("\t")[0]);

describe("complete", () => {
	test("commands first, help last", () => {
		const all = names([""]);
		expect(all.slice(0, 3)).toEqual(["list", "who", "conns"]);
		expect(all).toContain("completion");
		expect(all.at(-1)).toBe("help");
	});
	test("prefix filter", () => expect(names(["wa"])).toEqual(["watch"]));
	test("who and kill offer the ports listening now, with what holds them", () => {
		expect(complete(["kill", "3"], ports)).toEqual([
			"3000\tnode 4127  app-feature (feature-x)",
		]);
		expect(names(["who", "5"])).toEqual(["5432", "5173"]);
	});
	test("the machine is read only when ports are wanted", () => {
		asked = 0;
		names([""]);
		names(["kill", "--"]);
		names(["completion", ""]);
		expect(asked).toBe(0);
		names(["kill", ""]);
		expect(asked).toBe(1);
	});
	test("a command's own options; every option before a command", () => {
		expect(names(["kill", "--"])).toEqual([
			"--tree",
			"--force",
			"--yes",
			"--no-docker",
			"--help",
		]);
		expect(names(["--j"])).toEqual(["--json"]);
	});
	test("flags don't count as the command; nothing after a port", () => {
		expect(names(["--json", "who", "30"])).toEqual(["3000"]);
		expect(names(["kill", "3000", ""])).toEqual([]);
	});
	test("help takes a command, completion a shell; aliases are their command", () => {
		expect(names(["help", "w"])).toEqual(["who", "watch"]);
		expect(names(["completion", ""])).toEqual([
			"bash",
			"zsh",
			"fish",
			"powershell",
		]);
		expect(names(["if", "--j"])).toEqual(["--json"]);
	});
});

const has = (cmd: string) => spawnSync(cmd, ["--version"]).status === 0;

// on Windows, `bash` may be the WSL launcher
describe.skipIf(process.platform === "win32")("generated scripts", () => {
	test("bash parses", () =>
		expect(
			spawnSync("bash", ["-n"], { input: completionScript("bash") }).status,
		).toBe(0));
	test.skipIf(!has("zsh"))("zsh parses", () =>
		expect(
			spawnSync("zsh", ["-n"], { input: completionScript("zsh") }).status,
		).toBe(0),
	);
	test.skipIf(!has("fish"))("fish parses", () =>
		expect(
			spawnSync("fish", ["-n"], { input: completionScript("fish") }).status,
		).toBe(0),
	);
	test("bash completion end to end", () => {
		// load the script with a stub `nethound`, then complete `nethound ki`
		const script = `
      nethound() { bun "$NETHOUND_CLI" "$@"; }
      ${completionScript("bash")}
      COMP_WORDS=(nethound ki); COMP_CWORD=1; _nethound
      printf '%s\\n' "\${COMPREPLY[@]}"`;
		const r = spawnSync("bash", ["-c", script], {
			encoding: "utf8",
			// the path through the environment: spliced into the script, a space would break it
			env: {
				...process.env,
				NETHOUND_CLI: join(process.cwd(), "src", "cli.ts"),
			},
		});
		expect(r.stdout.trim()).toBe("kill");
	});
});

// a stub nethound.cmd on PATH, then PowerShell's own completion engine
test.skipIf(process.platform !== "win32")(
	"powershell completion end to end",
	() => {
		const dir = mkdtempSync(join(tmpdir(), "nethound-"));
		writeFileSync(
			join(dir, "nethound.cmd"),
			`@bun "${join(process.cwd(), "src", "cli.ts")}" %*\r\n`,
		);
		const script = `
    ${completionScript("powershell")}
    foreach ($line in 'nethound ki', 'nethound kill --f', 'nethound --json ') {
      (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText -join ','
    }`;
		const r = spawnSync(
			"powershell.exe",
			[
				"-NoProfile",
				"-NonInteractive",
				"-EncodedCommand",
				Buffer.from(script, "utf16le").toString("base64"),
			],
			{
				encoding: "utf8",
				env: { ...process.env, PATH: `${dir}${delimiter}${process.env.PATH}` },
			},
		);
		const [commands, flags, afterFlag] = r.stdout.trim().split(/\r?\n/);
		expect(commands).toBe("kill");
		expect(flags).toBe("--force");
		expect(afterFlag?.split(",")).toContain("list");
	},
	60_000,
);
