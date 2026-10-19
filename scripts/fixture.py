#!/usr/bin/env python3
"""Writes test/fixtures/root: a small machine as /proc, /sys and /etc show it.

    lo      127.0.0.1/8
    eth0    192.168.1.10/24, default route via 192.168.1.1
    br-abc  172.18.0.1/16, a docker bridge with one port, veth1 (container pg, 172.18.0.2)

    sshd (root, hidden)  listens on 0.0.0.0:22 and :::22; one client, 192.168.1.50, over IPv6-mapped IPv4
    docker-proxy (root)  listens on 0.0.0.0:5432 for pg
    node 300             listens on 127.0.0.1:5000 and 192.168.1.10:8080; curl 400 is its client;
                         started by bun run dev (250), itself started from zsh (240), in ~/src/app-feature
    curl 400             also talks to 140.82.121.4:443
    systemd-resolved     udp 127.0.0.53:53, asking 192.168.1.1
"""
import os, shutil, socket, struct, sys

root = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures", "root")
shutil.rmtree(root, ignore_errors=True)

def w(path, text):
    p = os.path.join(root, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)

def v4(ip):  # host order, as /proc writes it
    return "%08X" % struct.unpack("<I", socket.inet_aton(ip))[0]

def v6(ip):
    b = socket.inet_pton(socket.AF_INET6, ip)
    return "".join("%08X" % struct.unpack("<I", b[i:i + 4])[0] for i in range(0, 16, 4))

def ep(ip, port, six):
    return "%s:%04X" % (v6(ip) if six else v4(ip), port)

HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

def table(rows, six):
    out = HEAD
    for n, (l, lp, r, rp, st, uid, inode) in enumerate(rows):
        out += "%4d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n" % (
            n, ep(l, lp, six), ep(r, rp, six), st, uid, inode)
    return out

w("proc/net/tcp", table([
    ("0.0.0.0", 22, "0.0.0.0", 0, "0A", 0, 100),
    ("0.0.0.0", 5432, "0.0.0.0", 0, "0A", 0, 300),
    ("127.0.0.1", 5000, "0.0.0.0", 0, "0A", 1000, 200),
    ("192.168.1.10", 8080, "0.0.0.0", 0, "0A", 1000, 204),
    ("127.0.0.1", 5000, "127.0.0.1", 40000, "01", 1000, 201),
    ("127.0.0.1", 40000, "127.0.0.1", 5000, "01", 1000, 202),
    ("192.168.1.10", 50000, "140.82.121.4", 443, "01", 1000, 203),
    ("192.168.1.10", 50001, "140.82.121.4", 443, "06", 1000, 0),
], False))
w("proc/net/tcp6", table([
    ("::", 22, "::", 0, "0A", 0, 101),
    ("::ffff:192.168.1.10", 22, "::ffff:192.168.1.50", 51515, "01", 0, 102),
], True))
w("proc/net/udp", table([("127.0.0.53", 53, "0.0.0.0", 0, "07", 101, 500)], False))
w("proc/net/udp6", HEAD)

w("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" + "".join(
    "%s\t%s\t%s\t%04X\t0\t0\t%d\t%s\t0\t0\t0\n" % (i, v4(d), v4(g), f, m, v4(mask))
    for i, d, g, f, m, mask in [
        ("eth0", "0.0.0.0", "192.168.1.1", 3, 100, "0.0.0.0"),
        ("eth0", "192.168.1.0", "0.0.0.0", 1, 100, "255.255.255.0"),
        ("br-abc", "172.18.0.0", "0.0.0.0", 1, 0, "255.255.0.0"),
        ("docker0", "172.17.0.0", "0.0.0.0", 0x201, 0, "255.255.0.0"),  # reject: ignored
    ]))
w("proc/net/ipv6_route",
  "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000001       lo\n"
  "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
  "ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n")
w("proc/sys/kernel/osrelease", "6.8.0-generic\n")

def proc(pid, comm, argv, uid, sockets, ppid=1, start=0, cwd=None):
    w("proc/%d/comm" % pid, comm + "\n")
    # state, ppid, then 16 fields nethound skips, then starttime in clock ticks after boot
    w("proc/%d/stat" % pid, "%d (%s) S %d %s %d %s\n" % (pid, comm, ppid, " ".join(["0"] * 17), start, " ".join(["0"] * 30)))
    if cwd:
        os.symlink(cwd, os.path.join(root, "proc/%d/cwd" % pid))
    w("proc/%d/cmdline" % pid, "\0".join(argv) + "\0")
    w("proc/%d/status" % pid, "Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n" % (comm, uid, uid, uid, uid))
    os.makedirs(os.path.join(root, "proc/%d/fd" % pid), exist_ok=True)
    os.symlink("/dev/null", os.path.join(root, "proc/%d/fd/0" % pid))
    for n, inode in enumerate(sockets, start=3):
        os.symlink("socket:[%d]" % inode, os.path.join(root, "proc/%d/fd/%d" % (pid, n)))

# booted at 1760000000 (2025-10-09); start times are in 1/100 s after it
w("proc/stat", "cpu  0 0 0 0\nbtime 1760000000\n")
proc(240, "zsh", ["-zsh"], 1000, [], start=100, cwd="/home/me")
proc(250, "bun", ["bun", "run", "dev"], 1000, [], ppid=240, start=6000, cwd="/home/me/src/app-feature")
# a node that renamed its main thread, as runtimes do; started a minute after boot by bun run dev
proc(300, "MainThread", ["/usr/bin/node", "server.js", "--token=s3cret"], 1000, [200, 201, 204], ppid=250, start=6050, cwd="/home/me/src/app-feature")
proc(400, "curl", ["curl", "http://127.0.0.1:5000/", "https://github.com/"], 1000, [202, 203], ppid=240, start=9000, cwd="/home/me")

def iface(name, index, typ, operstate, mac, mtu, devtype=None, device=False, master=None, brif=()):
    d = "sys/class/net/%s/" % name
    for f, v in [("ifindex", index), ("type", typ), ("operstate", operstate), ("address", mac), ("mtu", mtu),
                 ("statistics/rx_bytes", 1500000), ("statistics/tx_bytes", 2000)]:
        w(d + f, "%s\n" % v)
    w(d + "uevent", "INTERFACE=%s\nIFINDEX=%d\n" % (name, index) + ("DEVTYPE=%s\n" % devtype if devtype else ""))
    # a file in each directory the code looks for: git doesn't keep empty ones
    if device:
        w(d + "device/uevent", "DRIVER=virtio_net\n")
    if master:
        os.symlink("../" + master, os.path.join(root, d, "master"))
    if devtype == "bridge":
        w(d + "bridge/bridge_id", "8000.%s\n" % mac.replace(":", "")[:12])
        # a bridge with no ports has an empty brif, which git doesn't keep: a missing one reads the same
        os.makedirs(os.path.join(root, d, "brif"), exist_ok=True)
        for p in brif:
            os.symlink("../../" + p + "/brport", os.path.join(root, d, "brif", p))

iface("lo", 1, 772, "unknown", "00:00:00:00:00:00", 65536)
iface("eth0", 2, 1, "up", "52:54:00:12:34:56", 1500, device=True)
iface("br-abc", 3, 1, "up", "02:42:ac:12:00:01", 1500, devtype="bridge", brif=["veth1"])
iface("veth1", 4, 1, "up", "ae:10:00:00:00:01", 1500, master="br-abc")
iface("docker0", 5, 1, "down", "02:42:ac:11:00:01", 1500, devtype="bridge")

w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nsystemd-resolve:x:101:101::/run/systemd:/usr/sbin/nologin\nme:x:1000:1000::/home/me:/bin/bash\n")
w("etc/resolv.conf", "# generated\nnameserver 127.0.0.53\nsearch lan\n")
w("run/systemd/resolve/resolv.conf", "# the servers systemd-resolved asks\nnameserver 192.168.1.1\n")
