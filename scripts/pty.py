# Runs a command in a pseudo-terminal, as a person at a terminal would, and prints what it wrote as
# JSON [seconds, text] pairs, timed as it happened. Used by the tests of nethound watch.
#   python3 -I scripts/pty.py COLS ROWS STEPS_JSON command [args...]
# STEPS_JSON is a list of ["wait", text] (until the output shows text), ["sleep", seconds] and
# ["send", keys]; once they are played, it waits for the command to exit.
import codecs, fcntl, json, os, pty, select, struct, sys, termios, time
cols, rows, steps = int(sys.argv[1]), int(sys.argv[2]), json.loads(sys.argv[3])
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[4], sys.argv[4:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
start, events, seen, mark = time.monotonic(), [], "", 0
decode = codecs.getincrementaldecoder("utf-8")("replace").decode
def pump(timeout):
    global seen
    if not select.select([fd], [], [], timeout)[0]:
        return True
    try:
        chunk = os.read(fd, 65536)
    except OSError:
        return False
    if not chunk:
        return False
    text = decode(chunk)
    if text:
        events.append([round(time.monotonic() - start, 3), text])
        seen += text
    return True
alive = True
for kind, arg in steps:
    if kind == "sleep":
        end = time.monotonic() + arg
        while alive and time.monotonic() < end:
            alive = pump(max(0, end - time.monotonic()))
    elif kind == "wait":
        deadline = time.monotonic() + 30
        while alive and arg not in seen[mark:]:
            if time.monotonic() > deadline:
                json.dump(events, sys.stdout)
                sys.exit("timed out waiting for " + arg)
            alive = pump(0.05)
        mark = len(seen)
    elif kind == "send":
        os.write(fd, arg.encode())
while alive:
    alive = pump(0.1)
os.waitpid(pid, 0)
json.dump(events, sys.stdout)
