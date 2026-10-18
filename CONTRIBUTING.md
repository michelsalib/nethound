# Contributing to nethound

Bug reports, ideas and pull requests are welcome. For anything bigger than a fix, open an issue
first so we can agree on the approach.

## Setting up

You need [Bun](https://bun.sh) (the version in `.bun-version`) and Node 20 or newer, on Linux, macOS or
Windows. The tests read the fixtures of every system, wherever they run, and run the built CLI on the
machine itself.

```sh
bun install
bun run dev -- map          # run from source
bun test                    # unit tests on test/fixtures/root, plus the built CLI on node on this machine
bun run typecheck
bun run lint                # Biome: formatting and lint; `bunx biome check --write` fixes most of it
```

`test/fixtures/root` is a small machine as `/proc`, `/sys` and `/etc` show it, written by
`scripts/fixture.py`: change the script, not the files, and run `python3 scripts/fixture.py`. CI checks
the two agree. `test/fixtures/macos` is what each command nethound runs prints on a Mac, and
`test/fixtures/windows/snapshot.json` what its PowerShell script prints on Windows; when a reader
changes, record the new output on the real system, with your own addresses replaced.

## Pull requests

- Keep each pull request to one change, with a test that fails without it.
- CI must pass on Linux (x64 and arm64), macOS and Windows; `main` only accepts pull requests with green
  checks.
- Write commit messages that say what changed and why, in plain sentences.
- User-visible changes go in `CHANGELOG.md`, under "Unreleased".

## Releasing (maintainers)

1. In a pull request, move the "Unreleased" notes of `CHANGELOG.md` under the new version and bump
   `version` in `package.json`.
2. Once it's merged, tag the merge commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The release workflow tests on every OS and builds the files, then waits for approval in the
   `release` environment. Approve it to publish to npm and create the GitHub release.
4. Package managers: the publish job then opens a pull request in the Homebrew tap
   (`michelsalib/homebrew-nethound`) and in the Scoop bucket (`michelsalib/scoop-nethound`), each
   merged by its own install CI. It uses `PACKAGES_TOKEN`, a secret of the `release` environment: a
   fine-grained token limited to those two repositories, with Contents and Pull requests (read and
   write). Without it the job only warns, and the update is by hand:
   `bun scripts/packages.ts X.Y.Z SHA256SUMS dist/packages`, then
   `sh scripts/update-package-repos.sh X.Y.Z dist/packages`. `scripts/packages.ts` also writes the
   winget manifests (a pull request to `microsoft/winget-pkgs`, not automated).
