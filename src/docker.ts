// Running containers, from `docker inspect`: their networks (and the host bridge each one uses)
// and the ports they publish. Skipped quietly when docker is missing or not running.

import { spawnSync } from "node:child_process";
import type { Container, Proto, PublishedPort } from "./model.ts";

interface Inspect {
	Id?: string;
	Name?: string;
	Config?: { Image?: string; Labels?: Record<string, string> | null };
	State?: { Pid?: number };
	NetworkSettings?: {
		Networks?: Record<
			string,
			{ NetworkID?: string; IPAddress?: string; GlobalIPv6Address?: string }
		> | null;
		Ports?: Record<
			string,
			{ HostIp?: string; HostPort?: string }[] | null
		> | null;
	};
}

/** Containers from the JSON array `docker inspect` prints. */
export function parseInspect(json: string): Container[] {
	let data: Inspect[];
	try {
		data = JSON.parse(json);
	} catch {
		return [];
	}
	return data.map((c) => {
		const ports: PublishedPort[] = [];
		for (const [key, binds] of Object.entries(c.NetworkSettings?.Ports ?? {})) {
			const [port = "0", proto = "tcp"] = key.split("/");
			for (const b of binds ?? [])
				ports.push({
					proto: proto as Proto,
					hostIp: b.HostIp || "0.0.0.0",
					hostPort: Number(b.HostPort),
					containerPort: Number(port),
				});
		}
		return {
			id: (c.Id ?? "").slice(0, 12),
			name: (c.Name ?? "").replace(/^\//, ""),
			image: c.Config?.Image ?? "",
			project: c.Config?.Labels?.["com.docker.compose.project"],
			networks: Object.entries(c.NetworkSettings?.Networks ?? {}).map(
				([name, n]) => ({
					name,
					// docker's default network is docker0; the others get br- and the network id
					bridge:
						name === "bridge"
							? "docker0"
							: n.NetworkID && !["host", "none"].includes(name)
								? `br-${n.NetworkID.slice(0, 12)}`
								: undefined,
					ip: n.IPAddress || n.GlobalIPv6Address || undefined,
				}),
			),
			ports,
			...(c.State?.Pid && { pid: c.State.Pid }),
		};
	});
}

export function readContainers(): Container[] {
	const run = (args: string[]) =>
		spawnSync("docker", args, { encoding: "utf8", timeout: 5000 });
	const ps = run(["ps", "-q"]);
	if (ps.status !== 0 || !ps.stdout.trim()) return [];
	const inspect = run(["inspect", ...ps.stdout.trim().split(/\s+/)]);
	return inspect.status === 0 ? parseInspect(inspect.stdout) : [];
}
