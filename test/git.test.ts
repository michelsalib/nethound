import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkoutOf } from "../src/git.ts";

// a main checkout on main, a linked worktree on feature-x, a detached one, and a directory outside
const top = mkdtempSync(join(tmpdir(), "nethound-git-"));
const file = (path: string, text: string) => {
	mkdirSync(join(top, path, ".."), { recursive: true });
	writeFileSync(join(top, path), text);
};
file("app/.git/HEAD", "ref: refs/heads/main\n");
file("app/src/server/x", "");
file("app/.git/worktrees/app-feature/HEAD", "ref: refs/heads/feature-x\n");
file(
	"app-feature/.git",
	`gitdir: ${join(top, "app/.git/worktrees/app-feature")}\n`,
);
file(
	"app/.git/worktrees/app-fix/HEAD",
	"4b825dc642cb6eb9a060e54bf8d69288fbee4904\n",
);
file("app-fix/.git", "gitdir: ../app/.git/worktrees/app-fix\n");
mkdirSync(join(top, "elsewhere"));

test("the main checkout, from any directory in it", () => {
	expect(checkoutOf(join(top, "app/src/server"))).toEqual({
		root: join(top, "app"),
		branch: "main",
		worktree: false,
	});
});

test("a linked worktree, its branch from its own HEAD; a relative gitdir; a detached HEAD", () => {
	expect(checkoutOf(join(top, "app-feature"))).toEqual({
		root: join(top, "app-feature"),
		branch: "feature-x",
		worktree: true,
	});
	expect(checkoutOf(join(top, "app-fix"))).toEqual({
		root: join(top, "app-fix"),
		branch: undefined,
		worktree: true,
	});
});

test("outside any checkout, and from the cache", () => {
	const cache = new Map();
	expect(checkoutOf(join(top, "elsewhere"), cache)).toBeUndefined();
	expect(checkoutOf(join(top, "app/src"), cache)?.branch).toBe("main");
	// every directory walked through is remembered
	expect(cache.get(join(top, "app/src"))?.root).toBe(join(top, "app"));
});
