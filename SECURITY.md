# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub:
**[Report a vulnerability](https://github.com/michelsalib/nethound/security/advisories/new)**.
Don't open a public issue for them.

You'll get an answer within a week. Once a fix is released, the advisory is published with credit
to you, unless you'd rather not be named.

Only the latest release gets security fixes.

## What nethound does with your machine

These are worth knowing when you judge what counts as a vulnerability:

- **It reads, and stops only what you confirm.** No file is written, no interface, route or firewall
  rule is touched. `nethound kill PORT` and the `k`/`K` keys of `nethound watch` signal processes
  (SIGTERM, or SIGKILL when asked again) or run `docker stop`, only after naming each one and asking
  (`kill -y` skips the question). Stopping with what started a server climbs only through package
  runners (`npm`, `bun run`, a watcher, a `sh -c` they started), never into an interactive shell, an IDE,
  another user's process or nethound itself. What it reads:
  - on Linux, `/proc` (sockets, and each process's open files and command line), `/sys/class/net` and
    `/etc/resolv.conf`;
  - on macOS, what `netstat`, `lsof`, `ifconfig`, `networksetup`, `ps` and `/etc/resolv.conf` print;
  - on Windows, what one PowerShell script prints, from `Get-NetTCPConnection`, `Get-NetUDPEndpoint`,
    `Get-NetRoute`, `Win32_Process` and .NET's `NetworkInterface`. The script is part of nethound
    (`src/windows/collect.ts`) and is passed to `powershell.exe` with `-EncodedCommand`, not read from
    a file.
- **It runs `docker`**: `docker ps -q` and `docker inspect` of the running containers, to know which
  container sits behind each published port. `--no-docker` turns that off.
- **Root (or an administrator terminal) is optional.** Without it, on Linux and macOS other users'
  sockets show no process, and on Windows other users' command lines are hidden. Elevated, it sees them
  all, and still only reads.
- **Secret values are masked** in command lines (the values of `--token=`, `--password` and the like)
  in every output, `--json` included, unless you pass `--show-secrets`.
- **Network:** `nethound route HOST` with a host name asks your DNS resolver for its address. Once a
  week a background process asks the npm registry for the latest version (`NETHOUND_NO_UPDATE_CHECK=1`
  turns it off; never in CI, scripts or with `--json`), and `nethound upgrade` downloads the new
  release. Nothing else.

## Verifying a release

Every release is built by GitHub Actions from the tagged commit, and its files carry signed build
provenance, also attached to the release as `nethound.intoto.jsonl`:

```sh
# the GitHub release files: nethound.js, install.sh and the standalone binaries
gh attestation verify nethound.js -R michelsalib/nethound
sha256sum --check --ignore-missing SHA256SUMS
# the npm package
npm audit signatures
```

The build is reproducible: `git checkout vX.Y.Z && bun install --frozen-lockfile && bun run build`
gives the same `dist/nethound.js` as the release's `SHA256SUMS` (with the Bun version in
`.bun-version`).

`nethound upgrade` checks this for you before replacing itself: the file must match the release's
`SHA256SUMS` and be byte for byte the one in the npm package of the same version. A standalone
binary must match `SHA256SUMS` on GitHub and the copy of `SHA256SUMS` published in the npm package.

The sources are analysed by CodeQL on every pull request, and the project's practices are tracked by
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/michelsalib/nethound).
