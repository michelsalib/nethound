<p align="center">
  <img src="assets/logo.svg" width="128" height="128" alt="nethound logo: a friendly beagle peeking over a network switch, paws on its edge, two ports plugged in and one link light blinking">
</p>

<h1 align="center">nethound</h1>

<p align="center">See which process (or container) listens on each port, who can reach it, who is connected to it, and how everything on your machine connects.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@michelsalib/nethound"><img src="https://img.shields.io/npm/v/@michelsalib/nethound?color=a8521a" alt="npm version"></a>
  <a href="https://github.com/michelsalib/nethound/actions/workflows/ci.yml"><img src="https://github.com/michelsalib/nethound/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/node/v/@michelsalib/nethound" alt="Node version">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue" alt="Linux, macOS and Windows">
  <a href="LICENSE"><img src="https://img.shields.io/npm/l/@michelsalib/nethound" alt="MIT license"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/michelsalib/nethound"><img src="https://api.scorecard.dev/projects/github.com/michelsalib/nethound/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center"><a href="https://micheldev.com/nethound"><b>micheldev.com/nethound</b></a></p>

What is on port 5432, a local postgres or the one in docker? Can my laptop's neighbours reach it, or only
this machine? Which process keeps a connection open to that server, and through which interface and
gateway does it leave? nethound answers those in one command, by reading what the system already
knows (`/proc` and `/sys` on Linux, `netstat` and `lsof` on macOS, PowerShell on Windows) and asking
docker which container sits behind each published port.

<p align="center">
  <img src="docs/demo.gif" width="860" alt="Two worktrees of one app each run vite on port 5173. nethound doctor says localhost:5173 reaches main's server over IPv4 and the feat/checkout worktree's over IPv6; nethound who 5173 shows each one's command, checkout, branch and the npm run dev that started it; nethound watch lists every port with its worktree and branch, selects main's server and stops it with the npm that started it">
</p>

**Try it, nothing to install:**

```sh
npx @michelsalib/nethound             # every listening port
npx @michelsalib/nethound map         # how everything connects
npx @michelsalib/nethound who 5432    # what is on 5432
npx @michelsalib/nethound doctor      # what is exposed that shouldn't be
```

```
$ nethound doctor
! PostgreSQL on tcp 5432 is reachable from every interface
  container pg, bound to 0.0.0.0, ::
  any machine that can reach eth0 can try passwords, or log in where pg_hba.conf trusts
  firewall: ufw is on, but docker's rules let published ports in before the firewall's own (only a DOCKER-USER rule would stop it)
  fix: publish it on this machine only: -p 127.0.0.1:5432:5432 (in compose: "127.0.0.1:5432:5432")

! localhost:3000 reaches node 812 over IPv4 and bun 977 over IPv6
  node 812 on 127.0.0.1
  bun 977 on ::1
  localhost over IPv4 (127.0.0.1:3000) → node 812
  localhost over IPv6 ([::1]:3000) → bun 977
  other machines → nobody
  fix: a client may pick either (browsers and node try IPv6 first, many others IPv4): stop one, or move it to another port

2 warnings
```

```
$ nethound
PORT      ADDRESS       REACHABLE FROM     CLIENTS  OWNER
tcp 22    *             every interface    1        root's process (sudo to see it)
udp 53    127.0.0.53    this machine only           systemd-resolve's process (sudo to see it)
tcp 5000  127.0.0.1     this machine only  1        node 300
tcp 5432  0.0.0.0       every interface             container pg :5432
tcp 8080  192.168.1.10  eth0                        node 300
```

```
$ nethound map
box

listening on every interface
  tcp 22    root's process (sudo to see it)  ← 1 client
  tcp 5432  container pg :5432

lo  loopback  up  127.0.0.1/8 ::1/128
  routes      ::1/128
  listen      systemd-resolve's process (sudo to see it)  udp 53
  listen      node 300  tcp 5000  ← 1 client
  local       curl 400 → :5000 node 300

eth0  ethernet  up  192.168.1.10/24
  routes      default via 192.168.1.1, 192.168.1.0/24
  listen      node 300  tcp 8080
  neighbours  192.168.1.1 gateway, 192.168.1.50
  out         curl 400 → 140.82.121.4:443

br-abc  bridge  up  172.18.0.1/16  docker network app_default
  routes      172.18.0.0/16
  holds       pg 172.18.0.2  ← host :5432
  ports       veth1

down
  docker0

dns servers
  127.0.0.53  on this machine: systemd-resolved, which asks the others
```

### Dev servers in several worktrees

Two checkouts of the same app, each running `bun run dev`, look the same to `ps`: `node …/vite`. nethound
tells them apart by the git checkout and branch each runs in:

```
$ nethound who 5173
tcp 5173  node 41207
  process    node /home/me/src/app-feature/node_modules/.bin/vite  (pid 41207, me)
  checkout   ~/src/app-feature  branch feature-x  (worktree)
  started by bun 41190 ← zsh 40122
  …
$ nethound kill 5173 --tree
tcp 5173  node 41207  app-feature (feature-x)  started by bun 41190
         and bun 41190  app-feature (feature-x)  started by zsh 40122
stop them? [y/N] y
stopped 41190, 41207
```

`nethound watch` shows the same live, and stops the selected one with `k` (its process) or `K` (with the
`bun run dev`, `npm` or watcher that started it, so nothing starts it again; never your shell). Its second
tab (`tab` or `2`) is the map, live: what `nethound map` shows, neighbours included.

Which of these is a web page? `nethound open` asks each port, and `nethound open PORT` opens one:

```console
$ nethound open
http://localhost:3000   page (302)                  node 41207  app-feature (feature-x)
http://localhost:3002   API (404 application/json)  container mock-server
http://localhost:16686  page                        container jaeger
```

## Install

nethound is a single JavaScript file that runs on Node ≥ 20 or Bun, on Linux (WSL included), macOS and
Windows. Without either, the installers fetch a standalone binary instead, which needs nothing.

```sh
npx @michelsalib/nethound map               # or: bunx @michelsalib/nethound map, nothing to install
npm install -g @michelsalib/nethound        # or: bun add -g @michelsalib/nethound
curl -fsSL https://github.com/michelsalib/nethound/releases/latest/download/install.sh | sh
```

To pin a version, or to read the script before running it:

```sh
curl -fsSL https://github.com/michelsalib/nethound/releases/download/v0.11.0/install.sh -o install.sh
less install.sh && sh install.sh
gh attestation verify install.sh -R michelsalib/nethound   # optional: proves GitHub Actions built it
```

On Windows, in PowerShell:

```powershell
irm https://github.com/michelsalib/nethound/releases/latest/download/install.ps1 | iex
```

With a package manager, which installs the standalone binary:

```sh
brew install michelsalib/nethound/nethound                    # Homebrew, macOS and Linux
scoop bucket add nethound https://github.com/michelsalib/scoop-nethound
scoop install nethound/nethound                               # Scoop, Windows
```

`install.sh` puts `nethound` in `~/.local/bin` (`NETHOUND_INSTALL_DIR` to change it, `NETHOUND_VERSION=0.11.0`
to pin a version), checks it against the release's `SHA256SUMS`, and runs it on Node, or on Bun when there
is no Node ≥ 20. With neither, or with `NETHOUND_BINARY=1`, it installs the standalone binary for your
system (Linux and macOS, x64 and arm64). `install.ps1` does the same on Windows, in
`%LOCALAPPDATA%\Programs\nethound`: `nethound.mjs` and a `nethound.cmd` launcher, or `nethound.exe`.
Neither edits your `PATH`: they print what to run.

**Completion.** `install.sh` and Homebrew also install bash and fish completion; `install.ps1` prints the
line for PowerShell. See [Shell completion](#shell-completion).

**Formerly netbeagle.** Up to 0.7.0, nethound was called netbeagle (`npm install -g netbeagle`). A copy
installed under that name updates to nethound like any other, then says after each command how to
switch to the new name. Environment variables are now `NETHOUND_*`.

**Updates.** Once a week nethound asks the npm registry, in the background, whether a newer version
exists, and when there is one says so after a command, with the update command for how you installed it:
`nethound upgrade` for `install.sh` and `install.ps1`, `brew upgrade nethound`, `scoop update nethound`,
`npm install -g @michelsalib/nethound@latest`, and so on. It stays quiet in scripts, CI, with `--json`, and with
`NETHOUND_NO_UPDATE_CHECK=1`. `nethound upgrade` never runs anything it downloads: the new file must match
the release's `SHA256SUMS` on GitHub and be the one published on npm (for a binary, the `SHA256SUMS` npm
has), so a tampered release would have to be tampered with on both. Then it replaces itself in one rename.

The binaries are release files too (`nethound-linux-x64`, `nethound-linux-arm64`, `nethound-darwin-x64`,
`nethound-darwin-arm64`, `nethound-windows-x64.exe`), listed in `SHA256SUMS` and attested like the rest;
see [SECURITY.md](SECURITY.md#verifying-a-release).

On Linux and macOS, without root, nethound can't see other users' processes, so their sockets show no
process; `sudo nethound` shows them all. Windows names every socket's process, but shows other users'
command lines only in an administrator terminal. nethound only reads: see
[what it does with your machine](SECURITY.md#what-nethound-does-with-your-machine).

## Commands

| Command | What it shows |
|---|---|
| `nethound` / `nethound list` | every listening port (TCP and UDP): the addresses it is bound to, who can reach it (this machine only, every interface, or the interfaces holding its address), how many clients are connected, and its owner: a process, or the docker container behind a published port |
| `nethound who PORT` | what listens on `PORT`: its command line, or its container with the address and network inside; where it is reachable from, and whether the firewall lets other machines in (with the rule that decides); on Linux, what listens on `PORT` inside containers and other network namespaces (and what takes a published port in its container); every client connected now, with its process when it runs here; and connections from this machine to `PORT` elsewhere. Exits 1 when there are none |
| `nethound conns` | every connection, grouped by process: inbound (←) to its ports and outbound (→), with the process, container or route at the other end, and the VPN it goes through. `--all` adds sockets opening or closing |
| `nethound interfaces` | every interface: kind (ethernet, wifi, bridge, veth, tun, wireguard…, VPNs marked with their adapter on Windows), state, addresses, routes, bridge ports, docker containers on it, traffic |
| `nethound route HOST` | where packets to `HOST` go: this machine, a container, an attached network, or a gateway; with the interface, the route and the source address, and whether they go through a VPN that is up. In WSL, where Windows sends them next: through Windows' VPN or not; a name only Windows resolves (a VPN's), Windows resolves |
| `nethound watch` | live: every port with its process, the **git checkout and branch** it runs in (or its directory), how long it has been up and its clients, refreshed every couple of seconds; ports that open or close are marked. Select one to see its command line and what started it; `o` opens it in the browser when it answers HTTP, `k` stops it, `K` stops it with what started it (`bun run dev`, `npm`, a watcher), `/` filters by branch, port or name. A second tab (`tab` or `2`) shows the map, live. Click a port to select it, its URL to open it, scroll with the wheel, click the keys on the last line |
| `nethound open [PORT]` | opens what listens on `PORT` in the browser (in WSL, Windows' browser) once it answers HTTP or HTTPS; alone, lists every port a browser can open, page or API, with what holds it. Databases and caches are never asked; `--no-probe` asks nothing and opens `http://localhost:PORT` as is. Exits 1 when nothing answers |
| `nethound kill PORT` | stops what listens on `PORT`, after saying which process it is, in which checkout, started by what, and asking. `--tree` also stops what started it, `--force` kills at once, `-y` doesn't ask; a container is `docker stop`ped |
| `nethound doctor` | what is wrong with how this machine listens and routes, each with what is behind it and its fix: databases, caches, debuggers and the docker API reachable from other machines (dev servers too, as notes); ports two programs share, with which one `localhost` reaches over IPv4 and over IPv6; servers on `::` that refuse IPv4, or on `::1` only; in WSL, a Windows program on a port WSL serves, which Windows' `localhost` then reaches instead. Ports docker publishes to a container where nothing listens, or only the container's own `127.0.0.1`. The firewall's answer comes with each: what it blocks is only a note. Then the routes: no default route, two with the same metric, a VPN taking all traffic or only some networks (in WSL, Windows' VPN, which WSL's traffic goes through; whether WSL asks its DNS servers; an MTU bigger than its), DNS servers with no route (or a private one only the default route reaches, often a disconnected VPN's). Exits 1 on errors |
| `nethound map` | the whole picture, interface by interface: what is open everywhere, what is bound to each interface, the containers behind each bridge (with the ports each listens on inside, on Linux), what listens in other network namespaces, the connections leaving through each one, the other machines on each network this one has exchanged packets with (its neighbour table: read, nothing sent to find them), which local process talks to which, and the DNS servers; in WSL, the VPN Windows runs and the machines on Windows' networks, which WSL can't see from behind its NAT |
| `nethound completion bash\|zsh\|fish\|powershell` | a shell completion script (commands, options, the ports listening now) |
| `nethound upgrade` | update an `install.sh` or `install.ps1` install; for others, prints the update command |

`nethound COMMAND --help` (or `nethound help COMMAND`) shows one command's usage, options and examples.
`if`, `ifaces`, `connections`, `graph` and `ls` are accepted too.

Options: `--json`, `--tcp`, `--udp`, `-a, --all`, `--no-docker` (don't ask docker), `--show-secrets` (command
lines are shown with the values of `--token=`, `--password` and the like masked by default).

## Shell completion

`install.sh` and Homebrew set up bash and fish completion for you. Otherwise:

```sh
eval "$(nethound completion bash)"                                 # in ~/.bashrc
eval "$(nethound completion zsh)"                                  # in ~/.zshrc, after compinit
nethound completion fish > ~/.config/fish/completions/nethound.fish
```

In PowerShell, add this line to your profile (`notepad $PROFILE`):

```powershell
nethound completion powershell | Out-String | Invoke-Expression
```

Completion is dynamic: on each <kbd>Tab</kbd> the script asks `nethound` for candidates, so `nethound kill <Tab>`
and `nethound who <Tab>` offer the ports listening right now, each with what holds it:

```
$ nethound kill <Tab>
3000  -- node 4127  app-feature (feature-x)
5173  -- node 4200  app (main)
5432  -- container pg
```

## How it works

Each system is read its own way, into the same picture, so every command works the same everywhere.

- **Linux**: sockets from `/proc/net/tcp`, `tcp6`, `udp` and `udp6`; IPv4 clients of a socket bound to `::`
  (`::ffff:1.2.3.4`) are shown as IPv4. Each socket's process is found through the `socket:[inode]` links
  in `/proc/PID/fd`. Without root, other users' processes can't be read: their sockets show the user
  only, and `sudo nethound` shows them all. Interfaces from `/sys/class/net` (kind, state, bridge and
  its ports, traffic) and their addresses from `getifaddrs`; routes from the kernel's main table,
  `/proc/net/route` and `/proc/net/ipv6_route`; neighbours from `/proc/net/arp`.
- **macOS**: every user's sockets from `netstat -an` (`tcp46` for a socket taking both families), and
  the process behind each from `lsof`: without root, only your own, so other users' show no process and
  `sudo nethound` shows them all. Interfaces from `ifconfig -a` (bridge members included), their traffic
  from `netstat -ibn`, which one is Wi-Fi from `networksetup`; routes from `netstat -rn`, without the
  ARP entries and interface-scoped copies; neighbours from `arp -an`; processes from `ps`.
- **Windows**: one PowerShell call. Sockets and their processes from `Get-NetTCPConnection` and
  `Get-NetUDPEndpoint` (`netstat` translates its states into the system's language; these don't),
  interfaces, addresses, traffic and DNS servers from .NET's `NetworkInterface`, routes from `Get-NetRoute`
  (their metric plus the interface's, as Windows compares them), neighbours from `Get-NetNeighbor`
  (for `map` only: it takes a quarter of a second), command lines from `Win32_Process`.
  It takes a couple of seconds, PowerShell's start included.
- **Neighbours** (`map`): the machines on each network that this one has exchanged packets with
  lately, as the system's neighbour (ARP) table keeps them, IPv4 only: the gateway, a printer just
  used, a phone that answered a broadcast. nethound sends nothing to find them, so a machine that stayed
  silent isn't listed; broadcast and multicast entries, and addresses still being resolved, are left out.
  In WSL behind NAT, WSL's own table holds only Windows: `map` adds Windows' table
  (`netsh.exe interface ipv4 show neighbors`), the machines on its Wi-Fi or Ethernet.
- `route` picks the longest matching prefix, then the lowest metric, as the system does (policy
  routing, `ip rule` on Linux, is not replayed).
- **Containers**: `docker inspect` of the running containers gives their networks (and the host bridge
  each uses, `docker0` or `br-<network id>`) and their published ports. A published port belongs to
  its container, whether `docker-proxy` holds a socket for it or the firewall forwards it with none.
- **Containers on macOS and Windows**: Docker Desktop runs them in a VM, so their networks are not on this
  machine; a published port shows its container all the same.
- **Who reaches what**: a socket on `127.0.0.1`, `::1` or another address of the loopback is reachable
  from this machine only; on `0.0.0.0` or `::`, from every interface; on one address, from the interface
  holding it. A socket on `::` takes IPv4 too by default on Linux (`net.ipv6.bindv6only` is 0) and on
  macOS (`tcp46`), and IPv6 only on Windows unless its program asks for both: those say
  `every interface, IPv6 only`.
- **The firewall** (`who` and `doctor`): whether a connection from another machine gets in, and the
  rule or default that decides. Read as the system keeps it:
  - Linux as root: `iptables-save` and `ip6tables-save` (ufw's and docker's rules, whichever backend
    holds them) and `nft -j list ruleset` (firewalld's, `/etc/nftables.conf`), walked as the kernel
    does for a new connection: the input chains for a process, the forward chains for a port docker
    publishes. A rule that depends on the client (its address, a rate limit) makes it `lets some
    machines in`. Without root, ufw's settings (`/etc/ufw/ufw.conf`: on, and its default) and
    firewalld's zones (`/etc/firewalld`, `/usr/lib/firewalld`); ufw's own rules take root to read.
    Docker publishes ports before ufw's and firewalld's rules, so those don't stop them.
  - Windows: the firewall's profiles, each network's profile (`Get-NetConnectionProfile`) and its
    inbound rules (by program, port and source), from the same PowerShell call. Store apps' rules
    are left out. Another firewall registered with Windows Security is named, not read.
  - macOS: the application firewall, from `socketfilterfw` (on, block all, signed software, each
    app). pf's rules take root and are not read.
- **WSL**: Windows forwards its own `localhost` to ports bound to `127.0.0.1` or every interface in the
  WSL VM, so those say `+ Windows`.
- Connections between two processes of this machine are matched end to end, so `curl 400 → :5000 node
  300` names both sides.
- **Network namespaces** (Linux): a container's own sockets, which the host's don't show, from
  `/proc/PID/net` of its first process (`docker inspect` gives it): anyone can read it, so
  `who` names the ports a container listens on inside, and `doctor` sees a published port with
  nothing behind it. Other namespaces (`ip netns`, rootless podman, sandboxes) are found by their
  processes' `/proc/PID/ns/net`: your own, or all as root. Which process holds a socket inside a
  container takes root, as on the host. Docker Desktop keeps containers in its VM: not read there.
- **DNS servers**: `/etc/resolv.conf`; behind systemd-resolved's `127.0.0.53`, the servers it asks too,
  from `/run/systemd/resolve/resolv.conf`.
- **`doctor` in WSL** also asks Windows which ports it listens on, with Windows' own `netstat.exe`,
  `tasklist.exe` and `netsh.exe interface portproxy` (half a second; skipped when WSL can't run
  Windows programs). `wslrelay`, Docker Desktop and port proxies forward to WSL: they don't count.

## Status

Linux (WSL included), macOS and Windows.

## The pack

nethound has a sibling, built the same way: one small file for Node or Bun, or a standalone binary,
nothing to configure.

| Tool | What it finds | Try it |
|---|---|---|
| **nethound** | which process or container listens on each port, who can reach it, and how everything on your machine connects | `npx @michelsalib/nethound` |
| **[envhound](https://github.com/michelsalib/envhound)** | which startup file (or registry key) sets each environment variable, and your `PATH` | `npx @michelsalib/envhound` |

## Development

```sh
bun install
bun run dev -- map          # run from source
bun test                    # unit tests on the fixtures of each system, plus the built CLI on node on this machine
bun run typecheck
bun run lint                # Biome: formatting and lint
bun run build               # dist/nethound.js, plain JS for node >= 20
```

`test/fixtures/root` is a small Linux machine as `/proc`, `/sys` and `/etc` show it, written by
`scripts/fixture.py` (its docstring describes it); `test/fixtures/macos` holds what its commands print
on a Mac, and `test/fixtures/windows` what nethound's PowerShell script prints on Windows. Source uses only `node:` APIs, so the build runs on
both Node and Bun.

See [CONTRIBUTING.md](CONTRIBUTING.md) for pull requests and releases.
