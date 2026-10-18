import { expect, test } from "bun:test";
import { packageFiles } from "../scripts/packages.ts";

const NAMES = [
	"nethound-darwin-arm64",
	"nethound-darwin-x64",
	"nethound-linux-arm64",
	"nethound-linux-x64",
	"nethound-windows-x64.exe",
];
const sums = NAMES.map((n, i) => `${String(i).repeat(64)}  ${n}\n`).join("");

test("Homebrew, Scoop and winget files point at the release's binaries", () => {
	const files = packageFiles("1.2.3", sums);
	const formula = files["Formula/nethound.rb"] ?? "";
	for (const [i, n] of NAMES.slice(0, 4).entries()) {
		expect(formula).toContain(
			`url "https://github.com/michelsalib/nethound/releases/download/v1.2.3/${n}"`,
		);
		expect(formula).toContain(`sha256 "${String(i).repeat(64)}"`);
	}
	expect(formula).toContain('version "1.2.3"');
	expect(formula).toContain('chmod 0755, bin/"nethound"');
	expect(formula).toContain("class Nethound < Formula");
	expect(formula).toContain(
		'generate_completions_from_executable(bin/"nethound", "completion"',
	);

	const scoop = JSON.parse(files["nethound.json"] ?? "{}");
	expect(scoop.version).toBe("1.2.3");
	expect(scoop.architecture["64bit"]).toEqual({
		url: "https://github.com/michelsalib/nethound/releases/download/v1.2.3/nethound-windows-x64.exe#/nethound.exe",
		hash: "4".repeat(64),
	});

	const dir = "manifests/m/MichelSalib/nethound/1.2.3";
	expect(Object.keys(files).filter((f) => f.startsWith(dir))).toHaveLength(3);
	expect(files[`${dir}/MichelSalib.nethound.installer.yaml`]).toContain(
		`InstallerSha256: ${"4".repeat(64)}`,
	);
});

test("a binary missing from SHA256SUMS is an error", () =>
	expect(() => packageFiles("1.2.3", sums.split("\n")[0] ?? "")).toThrow(
		"no entry for",
	));
