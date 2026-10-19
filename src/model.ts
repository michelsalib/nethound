// What nethound reads from the machine, in one snapshot: everything else is computed from it,
// so tests (and --json consumers) can work from a saved one.

export type Family = 4 | 6;
export type Proto = "tcp" | "udp";

export interface Address {
	family: Family;
	address: string;
	/** Prefix length, e.g. 24 for 192.168.1.10/24. */
	prefix: number;
}

export type IfaceKind =
	| "loopback"
	| "ethernet"
	| "wifi"
	| "bridge"
	| "veth"
	| "vlan"
	| "bond"
	| "tun"
	| "wireguard"
	| "virtual";

export interface Iface {
	name: string;
	index: number;
	kind: IfaceKind;
	state: "up" | "down" | "unknown";
	mtu: number;
	mac?: string;
	addresses: Address[];
	/** The bridge (or bond) this interface is a port of. */
	master?: string;
	/** For a bridge or bond: its ports. */
	members: string[];
	rxBytes: number;
	txBytes: number;
}

export interface Route {
	family: Family;
	/** Network address, e.g. 0.0.0.0 for the default route. */
	dest: string;
	prefix: number;
	gateway?: string;
	iface: string;
	metric: number;
}

export interface Endpoint {
	address: string;
	port: number;
}

export type SocketState =
	| "LISTEN"
	| "ESTABLISHED"
	| "SYN_SENT"
	| "SYN_RECV"
	| "FIN_WAIT1"
	| "FIN_WAIT2"
	| "TIME_WAIT"
	| "CLOSE"
	| "CLOSE_WAIT"
	| "LAST_ACK"
	| "CLOSING"
	/** A UDP socket bound with no peer: it receives from anyone, nethound treats it as listening. */
	| "UNCONN";

export interface Socket {
	proto: Proto;
	/** The address family once IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) are unwrapped. */
	family: Family;
	local: Endpoint;
	remote: Endpoint;
	state: SocketState;
	/** The owner's uid; unknown on Windows, and on macOS for other users' sockets without root. */
	uid?: number;
	/** Linux only: the socket's inode, which ties it to the process holding it. */
	inode?: number;
	/** Unknown when the process belongs to another user and nethound runs without root. */
	pid?: number;
	/** No process holds it any more (TIME_WAIT): the kernel finishes closing it. */
	orphan?: boolean;
	/** Bound to :: and taking IPv6 only. Linux's default is both (net.ipv6.bindv6only is 0), so is
	 * macOS's, where netstat says tcp46 or tcp6; Windows' is IPv6 only. */
	v6only?: boolean;
}

export interface Process {
	pid: number;
	name: string;
	/** The full command line, arguments joined by spaces. */
	cmd: string;
	uid?: number;
	/** Its parent: `bun run dev` for the vite it started. */
	ppid?: number;
	/** When it started, in milliseconds since the epoch. */
	started?: number;
	/** Its working directory; unknown on Windows, and for other users' processes without root. */
	cwd?: string;
	/** The git checkout its working directory is in. */
	git?: GitCheckout;
	/** The app that launched it, or what started it: claude, VS Code, Orca… */
	app?: string;
	/** When its own directory is in no checkout: the project it works for, from the Claude session it
	 * runs in (its scratch folder) or from the nearest parent in a checkout. */
	project?: Project;
	/** Launched by a Claude session that has ended: probably left behind. */
	orphan?: boolean;
}

export interface Project extends GitCheckout {
	via: "session" | "parent";
	/** The worktree no longer exists. */
	removed?: boolean;
}

export interface GitCheckout {
	/** The checkout's top directory. */
	root: string;
	/** The branch checked out; undefined when HEAD is detached. */
	branch?: string;
	/** A linked worktree (git worktree add), not the main checkout. */
	worktree: boolean;
}

export interface ContainerNetwork {
	name: string;
	/** The host interface the network uses, e.g. docker0 or br-b9465e98212d. */
	bridge?: string;
	ip?: string;
}

export interface PublishedPort {
	proto: Proto;
	hostIp: string;
	hostPort: number;
	containerPort: number;
}

export interface Container {
	id: string;
	name: string;
	image: string;
	/** The compose project, when it was started by docker compose. */
	project?: string;
	networks: ContainerNetwork[];
	ports: PublishedPort[];
}

/** In WSL: a port Windows itself listens on. */
export interface WindowsPort {
	address: string;
	port: number;
	pid: number;
	/** Its image name, without .exe. */
	name?: string;
	/** `netsh interface portproxy` forwards it: to WSL, most of the time. */
	proxy?: boolean;
}

export interface Snapshot {
	hostname: string;
	/** "wsl" in Windows Subsystem for Linux, where Windows forwards localhost ports into the VM. */
	environment: "linux" | "wsl" | "macos" | "windows";
	interfaces: Iface[];
	routes: Route[];
	sockets: Socket[];
	processes: Process[];
	containers: Container[];
	/** User names by uid. */
	users: Record<number, string>;
	/** Name servers: /etc/resolv.conf (then systemd-resolved's own, behind its 127.0.0.53), or
	 * each interface's on Windows. */
	dns: string[];
	/** In WSL, for nethound doctor: the TCP ports Windows listens on, which its localhost reaches
	 * before WSL's. */
	windowsPorts?: WindowsPort[];
	/** Our uid: sockets of other users have no process unless we are root. */
	uid?: number;
	/** Processes whose sockets nethound could not read (other users', without root). */
	hidden: number;
}

const SECRET_WORD =
	"(?:token|secret|passw(?:or)?d|api[-_]?key|private[-_]?key|credential|auth(?![a-z]))";
// --token=…, --password …, ?api_key=…: the value goes, the name stays
const SECRET_ARG = new RegExp(
	`((?:^|\\s)--?[\\w-]*${SECRET_WORD}[\\w-]*(?:=|\\s+)|[\\w-]*${SECRET_WORD}[\\w-]*=)(?!-)[^\\s&]+`,
	"gi",
);

/** A command line as nethound shows it: values of token- or password-like arguments masked. */
export const maskCmd = (cmd: string) => cmd.replace(SECRET_ARG, "$1********");
