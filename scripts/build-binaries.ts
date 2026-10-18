// Standalone binaries for the GitHub release: bun build --compile, cross-compiled from one machine.
// Each embeds the Bun runtime the target needs; the x64 ones use Bun's baseline build, which runs on
// CPUs without AVX2. The same source and Bun version give the same bytes, wherever they are built.
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const TARGETS: Record<string, string> = {
	"nethound-linux-x64": "bun-linux-x64-baseline",
	"nethound-linux-arm64": "bun-linux-arm64",
	"nethound-darwin-x64": "bun-darwin-x64-baseline",
	"nethound-darwin-arm64": "bun-darwin-arm64",
	"nethound-windows-x64.exe": "bun-windows-x64-baseline",
};

const out = process.argv[2] ?? join("dist", "bin");
mkdirSync(out, { recursive: true });
for (const [file, target] of Object.entries(TARGETS)) {
	const r = spawnSync(
		"bun",
		[
			"build",
			"src/cli.ts",
			"--compile",
			"--minify",
			`--target=${target}`,
			"--outfile",
			join(out, file),
		],
		{ stdio: "inherit" },
	);
	if (r.status !== 0) process.exit(r.status ?? 1);
}
