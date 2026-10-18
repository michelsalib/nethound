// IP addresses as the kernel writes them in /proc, and the arithmetic routes need.

import { isIPv4, isIPv6 } from "node:net";
import type { Address, Endpoint, Family } from "./model.ts";

/** The bytes of an address, 4 or 16 of them; undefined when it is not an IP address. */
export function ipBytes(ip: string): number[] | undefined {
	if (isIPv4(ip)) return ip.split(".").map(Number);
	if (!isIPv6(ip)) return undefined;
	let s = ip.replace(/%.*$/, "");
	// a trailing dotted IPv4 part (::ffff:1.2.3.4) becomes two groups
	const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
	if (v4?.[1]) {
		const [a, b, c, d] = v4[1].split(".").map(Number) as [
			number,
			number,
			number,
			number,
		];
		s = `${s.slice(0, -v4[1].length)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
	}
	const [head = "", tail] = s.split("::");
	const left = head ? head.split(":") : [];
	const right = tail ? tail.split(":") : [];
	const groups =
		tail === undefined
			? left
			: [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
	return groups.flatMap((g) => {
		const n = Number.parseInt(g, 16);
		return [n >> 8, n & 0xff];
	});
}

export const familyOf = (ip: string): Family | undefined =>
	isIPv4(ip) ? 4 : isIPv6(ip) ? 6 : undefined;

/** Canonical IPv6 text (RFC 5952): lower case, the longest run of zero groups as ::. */
export function formatIPv6(bytes: number[]): string {
	const groups: number[] = [];
	for (let i = 0; i < 16; i += 2)
		groups.push(((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0));
	let best = -1;
	let bestLen = 1;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLen) {
			best = i;
			bestLen = j - i;
		}
		i = j;
	}
	const hex = groups.map((g) => g.toString(16));
	if (best < 0) return hex.join(":");
	return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

/** 32 bits in host (little-endian) order, as /proc/net/tcp and /proc/net/route write IPv4. */
function wordBytes(hex: string): number[] {
	const n = Number.parseInt(hex, 16);
	return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

/** An IPv4 address as /proc/net/tcp and /proc/net/route write it: 0100007F is 127.0.0.1. */
export const procIPv4 = (hex: string) => wordBytes(hex).join(".");

/**
 * An address from /proc/net/tcp6 or udp6: four 32-bit words, each in host order. IPv4-mapped
 * addresses (::ffff:1.2.3.4, IPv4 clients of a socket bound to ::) come back as IPv4.
 */
export function procIPv6(hex: string): { family: Family; address: string } {
	const bytes: number[] = [];
	for (let i = 0; i < 32; i += 8) bytes.push(...wordBytes(hex.slice(i, i + 8)));
	if (
		bytes.slice(0, 10).every((b) => b === 0) &&
		bytes[10] === 0xff &&
		bytes[11] === 0xff
	)
		return { family: 4, address: bytes.slice(12).join(".") };
	return { family: 6, address: formatIPv6(bytes) };
}

/** An IPv6 address in network order, as /proc/net/ipv6_route and if_inet6 write it. */
export function hexIPv6(hex: string): string {
	const bytes: number[] = [];
	for (let i = 0; i < 32; i += 2)
		bytes.push(Number.parseInt(hex.slice(i, i + 2), 16));
	return formatIPv6(bytes);
}

/** True when `ip` is in `net`/`prefix`. Addresses of different families never match. */
export function inNetwork(ip: string, net: string, prefix: number): boolean {
	const a = ipBytes(ip);
	const b = ipBytes(net);
	if (!a || !b || a.length !== b.length) return false;
	for (let bit = 0; bit < prefix; bit++) {
		const i = bit >> 3;
		const mask = 0x80 >> (bit & 7);
		if (((a[i] ?? 0) & mask) !== ((b[i] ?? 0) & mask)) return false;
	}
	return true;
}

/** The network an address is on: 172.20.83.30/20 is on 172.20.80.0. */
export function networkOf(a: Address): string {
	const bytes = ipBytes(a.address) ?? [];
	const out = bytes.map((byte, i) => {
		const keep = Math.max(0, Math.min(8, a.prefix - i * 8));
		return byte & ((0xff << (8 - keep)) & 0xff);
	});
	return a.family === 4 ? out.join(".") : formatIPv6(out);
}

/** An address as a command prints it, as nethound keeps it: no %zone, IPv4-mapped IPv6 unwrapped. */
export function plainIP(ip: string): { family: Family; address: string } {
	const a = ip.replace(/%.*$/, "").toLowerCase();
	const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
	if (mapped?.[1]) return { family: 4, address: mapped[1] };
	return { family: a.includes(":") ? 6 : 4, address: a };
}

export const isWildcard = (ip: string) => ip === "0.0.0.0" || ip === "::";
export const isLoopback = (ip: string) => ip === "::1" || ip.startsWith("127.");
export const isLinkLocal = (ip: string) =>
	ip.startsWith("169.254.") || /^fe[89ab][0-9a-f]:/i.test(ip);

/** 1.2.3.4:80, or [::1]:80 for IPv6. */
export const endpoint = (e: Endpoint) =>
	e.address.includes(":")
		? `[${e.address}]:${e.port}`
		: `${e.address}:${e.port}`;

/** Number of set bits of a netmask written as /proc/net/route does. */
export const maskPrefix = (hex: string) =>
	wordBytes(hex).reduce(
		(n, b) => n + b.toString(2).replaceAll("0", "").length,
		0,
	);
