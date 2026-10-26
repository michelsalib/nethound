// nethound --help: an overview of the commands, and nethound COMMAND --help (or nethound help
// COMMAND) for one command alone: its usage, what it does, the options it takes, examples.

/** Every option, as the help lists it. */
export const OPTIONS: Record<string, [string, string]> = {
	json: ["--json", "machine-readable output"],
	tcp: ["--tcp", "TCP only"],
	udp: ["--udp", "UDP only"],
	all: [
		"-a, --all",
		"also connections that are opening or closing (TIME_WAIT…)",
	],
	"no-docker": [
		"--no-docker",
		"don't ask docker which containers publish ports",
	],
	"show-secrets": [
		"--show-secrets",
		"don't mask the values of --token=, --password and the like\nin command lines",
	],
	"no-probe": [
		"--no-probe",
		"don't ask ports whether they answer HTTP: o and open PORT\nopen http://localhost:PORT (or its address) unchecked",
	],
	tree: [
		"--tree",
		"with what started it: bun run dev, npm, a watcher; never your shell",
	],
	force: ["--force", "kill at once (SIGKILL) instead of asking it to stop"],
	yes: ["-y, --yes", "without asking"],
	help: ["-h, --help", "show help: nethound COMMAND --help for one command"],
	version: ["-v, --version", "show the version"],
};

export interface CommandHelp {
	/** Usage lines, without "nethound ". */
	usage: string[];
	/** One line for the overview. */
	summary: string;
	/** What it does, in a few lines. */
	about: string;
	/** Keys of OPTIONS it takes, besides --help. */
	options: string[];
	examples: string[];
}

export const COMMAND_HELP: Record<string, CommandHelp> = {
	list: {
		usage: ["[list]"],
		summary:
			"every listening port: its process or container, and who can reach it",
		about: `Lists every port something listens on, with the process (or the docker container)
behind it, the addresses it is bound to, and who can reach it: this machine only,
every interface, or the interfaces holding its address. Ports docker publishes
without a socket of their own are listed too. This is what nethound does with no
command.`,
		options: ["json", "tcp", "udp", "no-docker"],
		examples: ["nethound", "nethound list --tcp --json"],
	},
	who: {
		usage: ["who PORT"],
		summary: "what listens on PORT, who can reach it, who is connected to it",
		about: `Shows what listens on PORT: the process and its command line, or the container
and the address inside it the port forwards to; the addresses it is bound to and
the interfaces that reach it, and whether the firewall lets other machines in
(its rule); and every client connected right now, with its process when it runs
here. On Linux, also what listens on PORT inside containers and other network
namespaces, and what takes a published port in its container. Also lists
connections from this machine to PORT elsewhere. Exits 1 when there are none.`,
		options: ["json", "show-secrets", "no-docker"],
		examples: ["nethound who 5432", "nethound who 443"],
	},
	conns: {
		usage: ["conns"],
		summary: "every connection, by process, with what is at the other end",
		about: `Lists the open connections of each process: inbound ones (←) to its listening
ports and outbound ones (→). The other end is named when it is on this machine
(its process, or the container behind the port) or in a container; otherwise
nethound shows the interface and gateway the traffic leaves through.`,
		options: ["json", "all", "tcp", "udp", "no-docker"],
		examples: ["nethound conns", "nethound conns --all"],
	},
	interfaces: {
		usage: ["interfaces"],
		summary: "every network interface: addresses, routes, bridges, containers",
		about: `Lists the network interfaces: kind (ethernet, wifi, bridge, veth, tun…), state,
addresses, the routes going through each, the ports of a bridge and the docker
containers on it, and the traffic so far.`,
		options: ["json", "no-docker"],
		examples: ["nethound interfaces", "nethound if --json"],
	},
	route: {
		usage: ["route HOST"],
		summary: "which interface and gateway traffic to HOST takes",
		about: `Resolves HOST (a name or an address) and shows where packets to it go, as the
kernel's main routing table decides: this machine, a container, a network one of
the interfaces is on, or a gateway; with the route and the source address, and
whether it goes through a VPN that is up. In WSL, where Windows sends it next
from Windows' own routing table: through Windows' VPN or not.`,
		options: ["json", "no-docker"],
		examples: ["nethound route github.com", "nethound route 172.18.0.2"],
	},
	watch: {
		usage: ["watch"],
		summary:
			"live: every port, which worktree's server holds it, stop it from there",
		about: `Shows every listening port live, refreshed every couple of seconds, with the
process behind it, the git checkout and branch it runs in (or its directory),
how long it has been up and its clients; ports that just opened or closed are
marked. Select one to see its command line, what started it (bun run dev, npm)
and what stopping it would take, and its URL when it answers HTTP. Keys: arrows
to select, o to open it in the browser, k to stop its process, K to stop it with
what started it, / to filter (a branch, a port, a name), tab (or 1, 2) to switch
tabs: the ports, and the map (what nethound map shows, live: interfaces,
neighbours, connections), r to refresh, q to quit.
A second k forces it (SIGKILL); a container is docker stopped. The mouse works
too: click a port to select it, its URL to open it, the wheel to move, and the
keys on the last line to press them (shift-drag still selects text).`,
		options: ["no-docker", "show-secrets", "no-probe"],
		examples: ["nethound watch", "sudo nethound watch"],
	},
	open: {
		usage: ["open [PORT]"],
		summary: "open PORT in the browser; alone, every port a browser can open",
		about: `Asks what listens on PORT for / over HTTP, then HTTPS, and opens it in the
browser (in WSL, Windows' browser). Without PORT, lists every port that answers
HTTP with its URL, whether it is a page or an API, and what holds it. Databases,
caches and the like are never asked: Redis takes an HTTP request for an attack.
Exits 1 when nothing answers.`,
		options: ["json", "no-probe", "no-docker"],
		examples: ["nethound open 3000", "nethound open"],
	},
	kill: {
		usage: ["kill PORT"],
		summary: "stop what listens on PORT, after saying which process that is",
		about: `Stops what listens on PORT: says which process it is, the git checkout and
branch it runs in and what started it, then asks. --tree also stops what started
it (bun run dev, npm, a watcher such as nodemon, never your shell), so nothing
starts it again. A container is docker stopped. Exits 1 when something still
runs after 3 seconds: --force kills it at once.`,
		options: ["tree", "force", "yes", "no-docker"],
		examples: ["nethound kill 3000", "nethound kill 5173 --tree -y"],
	},
	doctor: {
		usage: ["doctor"],
		summary:
			"what is exposed that shouldn't be, ports taken twice, routes and DNS",
		about: `Lists what is wrong with how this machine listens and routes, each with what is
behind it and how to fix it: databases, caches, debuggers and the like reachable
from other machines (dev servers too, as notes); ports held by two programs, with
which one localhost reaches over IPv4 and over IPv6; servers that take IPv6 only;
in WSL, Windows programs on a port WSL serves, which take Windows' localhost;
ports docker publishes to a container where nothing listens, or only its own
127.0.0.1.
Then the routes: no default route, two of them tied, a VPN taking all traffic or
only some networks; in WSL, Windows' VPN too, whether WSL asks its DNS servers
and an MTU bigger than its. DNS servers with no route. What the firewall blocks is a note, with the rule
that blocks it. Exits 1 when there are errors.`,
		options: ["json", "no-docker"],
		examples: ["nethound doctor", "sudo nethound doctor --json"],
	},
	map: {
		usage: ["map"],
		summary: "how everything connects, interface by interface",
		about: `The whole picture: the ports open on every interface; then each interface with
its routes, the ports bound to it, the containers behind it (and the ports each
listens on inside, on Linux), the other machines on its network this one has
exchanged packets with (its neighbour table: nothing is sent to find them), and
the connections leaving through it; on the loopback, which local process talks
to which. In WSL, the machines on Windows' networks too. Then what listens in other network
namespaces, and the DNS servers with the way to them.`,
		options: ["json", "no-docker"],
		examples: ["nethound map"],
	},
	completion: {
		usage: ["completion SHELL"],
		summary: "print a shell completion script",
		about: `Prints a completion script for SHELL (bash, zsh, fish or powershell): commands,
their options, and for who, kill and open the ports listening right now, each with what
holds it. Load it from your shell's startup file (install.sh and Homebrew install
it for bash and fish).`,
		options: [],
		examples: [
			'eval "$(nethound completion bash)"        # in ~/.bashrc',
			'eval "$(nethound completion zsh)"         # in ~/.zshrc, after compinit',
			"nethound completion fish | source        # in ~/.config/fish/config.fish",
			"nethound completion powershell | Out-String | Invoke-Expression  # $PROFILE",
		],
	},
	upgrade: {
		usage: ["upgrade"],
		summary: "update nethound to the latest release",
		about: `Replaces this nethound with the latest release when it was installed with
install.sh or install.ps1 (the script or the standalone binary); the download
must match the release's SHA256SUMS and the npm package. Other installs get the
command to run (npm, bun, Homebrew, Scoop…). Once a week nethound also asks npm,
in the background, whether a newer version exists, and says so after a command;
NETHOUND_NO_UPDATE_CHECK=1 turns that off.`,
		options: [],
		examples: ["nethound upgrade"],
	},
};

/** Accepted names for commands. */
export const ALIASES: Record<string, string> = {
	ls: "list",
	if: "interfaces",
	ifaces: "interfaces",
	connections: "conns",
	graph: "map",
};

const optionLines = (keys: string[]) => {
	const rows = [...keys, "help"]
		.map((k) => OPTIONS[k])
		.filter((o): o is [string, string] => !!o);
	const w = Math.max(...rows.map(([f]) => f.length));
	return rows.map(
		([f, d]) =>
			`  ${f.padEnd(w)}  ${d.replaceAll("\n", `\n  ${" ".repeat(w)}  `)}`,
	);
};

export function overview(): string {
	const entries = Object.values(COMMAND_HELP);
	const w = Math.max(...entries.map((h) => (h.usage[0] ?? "").length));
	return [
		"Usage: nethound [COMMAND] [OPTIONS]",
		"",
		"Commands:",
		...entries.map((h) => `  ${(h.usage[0] ?? "").padEnd(w)}  ${h.summary}`),
		"",
		"Options:",
		...optionLines(["json", "no-docker", "show-secrets", "version"]),
		"",
		"nethound COMMAND --help shows one command's usage, options and examples.",
		process.platform === "win32"
			? "Without an administrator terminal, other users' command lines are hidden."
			: "Without root, sockets of other users' processes show no process: sudo shows them all.",
		"",
		"From the same pack: envhound, which startup file sets each environment variable.",
		"  npx @michelsalib/envhound",
		"",
	].join("\n");
}

export function commandHelp(name: string): string | undefined {
	const h = COMMAND_HELP[ALIASES[name] ?? name];
	if (!h) return undefined;
	return [
		`Usage: ${h.usage.map((u) => `nethound ${u}`).join("\n       ")}`,
		"",
		h.about,
		"",
		"Options:",
		...optionLines(h.options),
		"",
		"Examples:",
		...h.examples.map((e) => `  ${e}`),
		"",
	].join("\n");
}
