# Changelog

All notable changes to nethound (called netbeagle up to 0.7.0). Versions follow [semantic versioning](https://semver.org).

## 0.8.0 (2026-10-18)

### Changed

- netbeagle is now **nethound**: the command, the npm package
  [`@michelsalib/nethound`](https://www.npmjs.com/package/@michelsalib/nethound), the repository
  `michelsalib/nethound`, the Homebrew tap `michelsalib/nethound` and the Scoop bucket `scoop-nethound`.
  Environment variables are `NETHOUND_*` (`NETHOUND_INSTALL_DIR`, `NETHOUND_NO_UPDATE_CHECK`...).
- A copy installed as netbeagle (npm, Homebrew, Scoop, `install.sh` or `install.ps1`) updates to this
  release under its old name, then says after each command how to switch: for `install.sh`, renaming
  the file is enough.

## 0.7.0 (2026-10-16)

### Changed

- `watch` is easier to read: the port number stands out, the checkout is coloured, how far a port
  reaches is green when only this machine can reach it and yellow when every interface can, and rows
  you can't act on (another user's process, a closed port) are faded. The selection is a bar across
  the screen, a rule titled with the selected port separates the details and says which rows show
  (`1–16 of 22`), and messages get their own line so the keys stay in sight.

### Added

- `netbeagle open PORT` opens what listens on PORT in the browser (in WSL, Windows' browser), once it
  answered HTTP or HTTPS; `netbeagle open` alone lists every port a browser can open, page or API, with
  what holds it. Databases, caches, DNS and ssh are never asked: Redis takes an HTTP request for an
  attack. Certificates are checked: HTTPS with one this machine doesn't trust (a dev
  server's own) is listed as such, for the browser to warn about.
- `watch` asks the selected port (only that one, once selected) whether it answers HTTP, and shows its
  URL first in the details; `o`, or a click on the URL, opens it.
- `--no-probe` (`watch`, `open PORT`): no port is asked anything; `o` and `open PORT` open
  `http://localhost:PORT` as is, databases and the like excepted.
- The mouse in `watch`: click a port to select it, scroll with the wheel, click a key on the last line
  (`k stop`, `y yes`, `esc clear filter`) to press it. Shift-drag still selects text in most terminals.

### Fixed

- A server Claude started in an Orca worktree showed `· Orca` instead of `· claude` when Claude's shell
  had `cd`ed into the worktree first: Orca is now recognised by its own files, not by a path under
  `~/orca/`.

## 0.6.0 (2026-10-14)

### Added

- Where a process comes from, beyond its directory: the app that launched it (`· claude`, `· VS Code`,
  `· Orca`, cursor, codex), and when its own directory is in no checkout, the project it works for, from
  the Claude session whose scratch folder it runs in, or from the nearest parent in a checkout. A
  worktree removed since shows as `(removed)`, and a process whose Claude session has ended is flagged
  as probably left behind (a headless browser, say). In `watch`, `who`, `kill`, completion and `--json`
  (`app`, `project`, `orphan`).
- WHERE shows a worktree's branch only when it differs from the worktree's name, and an app's own
  process (VS Code's server) as the app rather than its directory.

## 0.5.0 (2026-10-13)

### Added

- Shell completion for bash, zsh, fish and PowerShell (`netbeagle completion SHELL`): commands, each
  command's options, and for `who` and `kill` the ports listening now, each with its process and the
  checkout it runs in, or its container. `install.sh` and Homebrew install it for bash and fish;
  `install.ps1` prints the line for your PowerShell profile.

## 0.4.0 (2026-10-13)

### Added

- `netbeagle upgrade`: replaces an `install.sh` or `install.ps1` install (the script or the standalone
  binary) with the latest release, checked against the release's `SHA256SUMS` and against npm; other
  installs get their update command (`brew upgrade netbeagle`, `scoop update netbeagle`, npm…).
- Once a week, a background check of the npm registry: a newer version is mentioned after a command,
  with the update command for how netbeagle was installed. Never in scripts, CI or with `--json`;
  `NETBEAGLE_NO_UPDATE_CHECK=1` turns it off.

### Changed

- The npm package carries the release's `SHA256SUMS`, which `netbeagle upgrade` checks a binary from
  GitHub against.

## 0.3.0 (2026-10-13)

### Added

- `netbeagle doctor`: what is wrong with how this machine listens, each with what is behind it and
  its fix. Databases, caches, Jupyter, the Node.js inspector and the docker API reachable from other
  machines (the last two are errors: they run code), dev servers as notes; a published container's
  fix is its `-p 127.0.0.1:…`. And ports two programs share, with which one `localhost` reaches over
  IPv4 and over IPv6. `--json`; exits 1 on errors.
- `netbeagle watch`: every port live, with the git checkout and branch each server runs in (or its
  directory), its uptime and clients; ports that open or close are marked. Select one for its command
  line and what started it; `k` stops it (again: SIGKILL), `K` stops it with the `bun run dev`, `npm`
  or watcher that started it, a container is `docker stop`ped; `/` filters.
- `netbeagle kill PORT`: says which process listens on it, in which checkout, started by what, and asks
  before stopping it. `--tree`, `--force`, `-y`.
- `who` shows a server's git checkout and branch (or directory), what started it and since when.
- Processes carry their parent, start time, working directory (Linux and macOS) and git checkout in
  `--json`.
- Homebrew (macOS and Linux) and Scoop (Windows):
  `brew install michelsalib/netbeagle/netbeagle`, or
  `scoop bucket add netbeagle https://github.com/michelsalib/scoop-netbeagle` then
  `scoop install netbeagle/netbeagle`. Each release updates them.

### Fixed

- A port's clients are the connections open now: not those closing (TIME_WAIT, CLOSE_WAIT), which
  counted for up to a minute after a burst of requests. `conns --all` still shows them.
- A client of a container's published port is one client: docker-proxy's connection to the
  container on its behalf is shown with it ("each relayed by docker-proxy to 172.18.0.3:6379"), no
  longer as a connection to that port elsewhere, and `conns` names docker-proxy even without root.
- On Linux, every process is read, not only those holding a socket: a server's parent too.
- A local server on a port a container also publishes (postgres on 127.0.0.1:5432 beside a container
  on 0.0.0.0:5432) is its own listener, no longer counted as the container's.

## 0.2.0 (2026-10-12)

### Added

- macOS and Windows. On macOS, netbeagle reads `netstat`, `lsof`, `ifconfig` and `ps`: without root,
  other users' sockets show no process, as on Linux. On Windows, one PowerShell call gives every
  socket's process, the interfaces, routes and DNS servers; other users' command lines need an
  administrator terminal.
- Standalone binaries for macOS (x64, arm64) and Windows (x64), `install.sh` on macOS and
  `install.ps1` on Windows.
- A socket on `::` that takes IPv6 only (Windows' default, `tcp6` on macOS, `net.ipv6.bindv6only=1`
  on Linux) is reachable from `every interface, IPv6 only`, and only from interfaces with an IPv6
  address.

### Changed

- In `--json`, a socket's `uid` and `inode` can be missing (Windows has neither; macOS doesn't tell
  other users' without root), and a listener's `user` too. A socket no process holds any more has
  `orphan: true`.
- The `list` table shows the first two addresses of a service bound to more, and how many others.

### Fixed

- Without root, sockets closing (TIME_WAIT) are no longer counted among other users' sockets.

## 0.1.0 (2026-10-12)

### Added

- `netbeagle list`: every listening port, its owner (process or docker container), the addresses it is
  bound to, who can reach it and how many clients it has.
- `netbeagle who PORT`, `netbeagle conns`, `netbeagle interfaces`, `netbeagle route HOST` and
  `netbeagle map`.
- `--json` on every command; `--no-docker`; command lines masked unless `--show-secrets`.
- Linux and WSL, from `/proc`, `/sys` and `docker inspect`.
- `--version` and `--help` show the logo in a terminal: the beagle, looking over a network switch.
- Install with `npx netbeagle`, `npm install -g netbeagle` or `install.sh`, which falls back to a
  standalone binary (x64, arm64) without Node or Bun. Release files carry signed build provenance.
- `netbeagle --help` and the README point to envhound, netbeagle's sibling: which startup file sets
  each environment variable.
