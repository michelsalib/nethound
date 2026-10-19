// macOS's application firewall, from socketfilterfw, which answers without root. pf's rules take
// root to read, and are not read: the application firewall is the one System Settings shows.

import type { Firewall } from "../model.ts";
import type { Run } from "../run.ts";

export const SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/** "… is enabled.", "… ENABLED!", "State = 1": on; anything saying disabled or off: off. */
const on = (text: string) =>
	/state\s*=\s*[12]|\benabled\b|\bon\b/i.test(text) &&
	!/\bdisabled\b|\boff\b|state\s*=\s*0/i.test(text);

/** `--listapps`: each app's path, then whether it may take incoming connections. */
export function parseListApps(
	text: string,
): { path: string; allow: boolean }[] {
	const out: { path: string; allow: boolean }[] = [];
	for (const line of text.split("\n")) {
		const app = line.match(/^\s*\d+\s*:\s*(\S.*?)\s*$/);
		if (app?.[1]) out.push({ path: app[1], allow: true });
		else if (/block/i.test(line) && out.length) {
			const last = out[out.length - 1];
			if (last) last.allow = false;
		}
	}
	return out;
}

export function readMacFirewall(run: Run): Firewall | undefined {
	const ask = (flag: string) => run(SOCKETFILTERFW, [flag]);
	const state = ask("--getglobalstate");
	if (!state.trim()) return undefined;
	return {
		kind: "macos",
		enabled: on(state),
		// State = 2 is the old way of saying block all
		blockAll: on(ask("--getblockall")) || /state\s*=\s*2/i.test(state),
		allowSigned: on(ask("--getallowsigned").split("\n")[0] ?? ""),
		apps: parseListApps(ask("--listapps")),
	};
}
