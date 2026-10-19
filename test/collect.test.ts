import { expect, test } from "bun:test";
import { parseInspect } from "../src/docker.ts";
import { maskCmd } from "../src/model.ts";
import { fixture } from "./helpers.ts";

const snap = fixture();

test("interfaces: kinds, states, bridges", () => {
	const by = Object.fromEntries(snap.interfaces.map((i) => [i.name, i]));
	expect(snap.interfaces.map((i) => i.name)).toEqual([
		"lo",
		"eth0",
		"br-abc",
		"veth1",
		"docker0",
	]);
	expect(by.lo?.kind).toBe("loopback");
	expect(by.lo?.state).toBe("up");
	expect(by.eth0?.kind).toBe("ethernet");
	expect(by["br-abc"]?.kind).toBe("bridge");
	expect(by["br-abc"]?.members).toEqual(["veth1"]);
	expect(by.veth1?.kind).toBe("veth");
	expect(by.veth1?.master).toBe("br-abc");
	expect(by.docker0?.state).toBe("down");
});

test("routes: rejected, multicast and link-local host routes left out", () => {
	expect(snap.routes.filter((r) => r.family === 4)).toEqual([
		{
			family: 4,
			dest: "0.0.0.0",
			prefix: 0,
			gateway: "192.168.1.1",
			iface: "eth0",
			metric: 100,
		},
		{
			family: 4,
			dest: "192.168.1.0",
			prefix: 24,
			gateway: undefined,
			iface: "eth0",
			metric: 100,
		},
		{
			family: 4,
			dest: "172.18.0.0",
			prefix: 16,
			gateway: undefined,
			iface: "br-abc",
			metric: 0,
		},
	]);
	expect(
		snap.routes
			.filter((r) => r.family === 6)
			.map((r) => `${r.dest}/${r.prefix}`),
	).toEqual(["::1/128", "fe80::/64"]);
});

test("sockets get their process from /proc/PID/fd", () => {
	const s = (inode: number) => snap.sockets.find((x) => x.inode === inode);
	expect(s(200)?.pid).toBe(300);
	expect(s(202)?.pid).toBe(400);
	expect(s(100)?.pid).toBeUndefined();
	// an IPv4 client of a socket bound to ::
	expect(s(102)).toMatchObject({
		family: 4,
		local: { address: "192.168.1.10", port: 22 },
		remote: { address: "192.168.1.50", port: 51515 },
	});
	expect(s(500)?.state).toBe("UNCONN");
});

test("a runtime's renamed main thread gives way to the program's name", () => {
	expect(snap.processes.find((p) => p.pid === 300)?.name).toBe("node");
	expect(snap.processes.find((p) => p.pid === 400)?.name).toBe("curl");
	expect(snap.users[101]).toBe("systemd-resolve");
	expect(snap.dns).toEqual(["127.0.0.53", "192.168.1.1"]);
	expect(snap.environment).toBe("linux");
});

test("token and password arguments are masked", () => {
	expect(maskCmd("node server.js --token=s3cret")).toBe(
		"node server.js --token=********",
	);
	expect(maskCmd("x --password hunter2 -v")).toBe("x --password ******** -v");
	expect(maskCmd("curl https://h/?api_key=k&b=1")).toBe(
		"curl https://h/?api_key=********&b=1",
	);
	expect(maskCmd("ls --authors /home/oauth2")).toBe(
		"ls --authors /home/oauth2",
	);
});

test("docker inspect: networks, their bridge, published ports", () => {
	const [c] = parseInspect(
		JSON.stringify([
			{
				Id: "d2bb5b893eee0000",
				Name: "/local-pg-1",
				Config: {
					Image: "postgres:18",
					Labels: { "com.docker.compose.project": "local" },
				},
				NetworkSettings: {
					Networks: {
						local_default: {
							NetworkID: "b9465e98212d1234",
							IPAddress: "172.18.0.9",
						},
						bridge: { NetworkID: "208b14c09edc", IPAddress: "172.17.0.2" },
					},
					Ports: {
						"5432/tcp": [
							{ HostIp: "0.0.0.0", HostPort: "5434" },
							{ HostIp: "::", HostPort: "5434" },
						],
						"9000/tcp": null,
					},
				},
			},
		]),
	);
	expect(c).toEqual({
		id: "d2bb5b893eee",
		name: "local-pg-1",
		image: "postgres:18",
		project: "local",
		networks: [
			{ name: "local_default", bridge: "br-b9465e98212d", ip: "172.18.0.9" },
			{ name: "bridge", bridge: "docker0", ip: "172.17.0.2" },
		],
		ports: [
			{ proto: "tcp", hostIp: "0.0.0.0", hostPort: 5434, containerPort: 5432 },
			{ proto: "tcp", hostIp: "::", hostPort: 5434, containerPort: 5432 },
		],
	});
	expect(parseInspect("not json")).toEqual([]);
});
