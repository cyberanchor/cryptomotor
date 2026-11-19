#!/usr/bin/env python3
"""pty_sigint.py <cryptomotor> <plain-file>

Runs `cryptomotor --encrypt --file <plain-file> --low-memory` on a fresh
pseudo-terminal, waits for the hidden password prompt, presses Ctrl+C (writes
0x03 to the master, so the line discipline sends SIGINT to the foreground
process group) and then reads the terminal flags of that pty.

Prints one line: ECHO before/during/after and how the child ended.
"""
import os
import pty
import resource
import select
import signal
import sys
import termios
import time

binary, plain = sys.argv[1], sys.argv[2]

pid, master = pty.fork()
if pid == 0:  # child: new session, the pty is its controlling terminal
    resource.setrlimit(resource.RLIMIT_AS, (3_000_000 * 1024, 3_000_000 * 1024))
    # A background job of a non-interactive shell inherits SIGINT=SIG_IGN, and Go
    # keeps an inherited SIG_IGN. An interactive terminal delivers SIGINT normally.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.execv(binary, [binary, "--encrypt", "--file", plain, "--low-memory", "--no-progress"])


def echo_on():
    return bool(termios.tcgetattr(master)[3] & termios.ECHO)


before = echo_on()
buf = b""
deadline = time.time() + 10
while b"Enter password" not in buf and time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.2)
    if r:
        try:
            buf += os.read(master, 1024)
        except OSError:
            break
time.sleep(0.3)  # let ReadPassword switch echo off
during = echo_on()
os.write(master, b"\x03")  # Ctrl+C
status = None
for _ in range(50):  # up to 5 s
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        status = st
        break
    time.sleep(0.1)
if status is None:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print(f"prompt_seen={b'Enter password' in buf} child=did-not-exit-after-ctrl-c (killed)")
    sys.exit(0)
after = echo_on()
how = f"signal {os.WTERMSIG(status)}" if os.WIFSIGNALED(status) else f"exit {os.WEXITSTATUS(status)}"
print(f"prompt_seen={b'Enter password' in buf} echo_before={before} echo_during={during} "
      f"echo_after={after} child={how}")
