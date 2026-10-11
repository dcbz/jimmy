#!/usr/bin/env python3
"""rshell — a deliberately restricted shell used as the demo lab payload.

It models the class of environment the Phrack article studies: an
allowlisting shell whose *invoked applications* fail to preserve the
restriction. The weaknesses are application-level (like pico/urlview in
psh), not memory corruption.

Red herrings built in (the boundary genuinely holds here):
  * more's `!` shell escape is stubbed out ("disabled in this build")
  * the system editor profile /etc/texteditrc is read-only
  * `set` shows env vars but masks JIMMY_* values

Real weaknesses (the intended chains):
  * textedit :r/:w touch files the rshell itself cannot (read/write
    primitives under the user's filesystem permissions)
  * textedit honours ~/.texteditrc — if it contains allow_shell=1, :sh
    runs commands with no shell restriction (write -> config consumption
    -> invocation chain)

Usage: rshell.py --home DIR --etc DIR   (run on a PTY)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

PROMPT = "rshell$ "
EDITOR_PROMPT = ": "
BANNER = "RShell 0.4 (restricted) — type 'help' for permitted commands"

# Characters the restricted parser refuses outright.
METACHARS = set(";|&><`()$*!{}\\\n\r\x00")

ALLOWED = ("help", "ls", "pwd", "echo", "id", "cat", "more", "textedit",
           "set", "version", "exit")


def out(s: str = "") -> None:
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


class RShell:
    def __init__(self, home: str, etc: str):
        self.home = os.path.realpath(home)
        self.etc = os.path.realpath(etc)
        self.buffer = ""

    # -- helpers -----------------------------------------------------------

    def in_jail(self, path: str) -> bool:
        rp = os.path.realpath(path)
        return rp == self.home or rp.startswith(self.home + os.sep)

    def expand(self, path: str) -> str:
        if path.startswith("~"):
            path = self.home + path[1:]
        return os.path.abspath(path)

    def editor_profile(self) -> dict:
        """Parse textedit config: system profile, then user profile wins."""
        cfg = {}
        for p in (os.path.join(self.etc, "texteditrc"),
                  os.path.join(self.home, ".texteditrc")):
            try:
                with open(p) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, _, v = line.partition("=")
                            cfg[k.strip()] = v.strip()
            except OSError:
                pass
        return cfg

    # -- commands ------------------------------------------------------------

    def cmd_help(self, args):
        out("Permitted commands: " + " ".join(ALLOWED))
        out("Shell metacharacters (; | & > < $ ` etc.) are disabled.")

    def cmd_ls(self, args):
        target = self.expand(args[0]) if args else self.home
        if not self.in_jail(target):
            out(f"ls: {args[0] if args else ''}: permission denied")
            return
        try:
            for name in sorted(os.listdir(target)):
                out(name)
        except OSError as e:
            out(f"ls: {e.strerror}: {target}")

    def cmd_pwd(self, args):
        out(os.getcwd())

    def cmd_echo(self, args):
        out(" ".join(args))

    def cmd_id(self, args):
        p = subprocess.run(["id"], capture_output=True, text=True)
        out(p.stdout.strip() or p.stderr.strip())

    def cmd_version(self, args):
        out("RShell 0.4")

    def cmd_set(self, args):
        for k, v in sorted(os.environ.items()):
            if k.startswith("JIMMY_"):
                v = "<redacted>"
            out(f"{k}={v}")

    def cmd_cat(self, args):
        if not args:
            out("cat: missing operand")
            return
        for a in args:
            path = self.expand(a)
            if not self.in_jail(path):
                out(f"cat: {a}: permission denied")
                continue
            try:
                with open(path, errors="replace") as f:
                    out(f.read())
            except OSError as e:
                out(f"cat: {a}: {e.strerror}")

    def cmd_more(self, args):
        if not args:
            out("more: missing operand")
            return
        path = self.expand(args[0])
        if not self.in_jail(path):
            out(f"more: {args[0]}: permission denied")
            return
        try:
            with open(path, errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as e:
            out(f"more: {args[0]}: {e.strerror}")
            return
        i = 0
        while i < len(lines):
            for ln in lines[i:i + 20]:
                out(ln)
            i += 20
            out("--More-- (space=next, q=quit, !=shell)")
            sys.stdout.flush()
            try:
                key = sys.stdin.readline().strip() or " "
            except EOFError:
                return
            if key == "q":
                return
            if key == "!":
                out("more: external commands are disabled in this build")
                return

    def cmd_textedit(self, args):
        filename = self.expand(args[0]) if args else ""
        if filename:
            try:
                with open(filename, errors="replace") as f:
                    self.buffer = f.read()
            except OSError:
                self.buffer = ""
        out("textedit 1.6 — :r/:w file, :sh cmd, i=insert, p=print, :q=quit")
        while True:
            sys.stdout.write(EDITOR_PROMPT)
            sys.stdout.flush()
            try:
                line = sys.stdin.readline()
            except EOFError:
                return
            if not line:
                return
            cmd = line.rstrip("\r\n")
            if not cmd:
                continue
            if cmd == "i":
                out("(append lines, single '.' on a line to finish)")
                while True:
                    try:
                        ln = sys.stdin.readline()
                    except EOFError:
                        break
                    if ln.rstrip("\r\n") == ".":
                        break
                    self.buffer += ln
                continue
            if cmd == "p":
                out(self.buffer if self.buffer else "(empty buffer)")
                continue
            if cmd.startswith(":"):
                verb, _, rest = cmd[1:].partition(" ")
                rest = rest.strip()
                if verb == "q":
                    return
                if verb in ("r", "w"):
                    # NOTE: the editor does NOT enforce the shell's jail.
                    # This is the weakness, faithful to pico-in-psh.
                    path = self.expand(rest) if rest else filename
                    if not path:
                        out(f":{verb}: no filename")
                        continue
                    if verb == "r":
                        try:
                            with open(path, errors="replace") as f:
                                self.buffer = f.read()
                            filename = path
                        except OSError as e:
                            out(f"textedit: {rest}: {e.strerror}")
                    else:
                        try:
                            with open(path, "w") as f:
                                f.write(self.buffer)
                            out(f'"{path}" written')
                            filename = path
                        except OSError as e:
                            out(f"textedit: {rest}: {e.strerror}")
                    continue
                if verb == "sh":
                    if not rest:
                        out(":sh: usage: :sh <command>")
                        continue
                    cfg = self.editor_profile()
                    if cfg.get("allow_shell", "").lower() not in ("1", "yes", "true"):
                        out("textedit: shell access not permitted in this profile")
                        continue
                    out("--- running via textedit profile exception ---")
                    rc = subprocess.call(rest, shell=True)
                    out(f"--- command exited ({rc}) — back to textedit ---")
                    continue
                out(f"textedit: unknown command :{verb}")
                continue
            out("textedit: unrecognized input (use :r :w :sh i p :q)")

    def cmd_exit(self, args):
        raise SystemExit(0)

    # -- main loop -------------------------------------------------------------

    def run(self) -> int:
        out(BANNER)
        while True:
            try:
                sys.stdout.write(PROMPT)
                sys.stdout.flush()
                line = sys.stdin.readline()
            except (EOFError, KeyboardInterrupt):
                return 0
            if not line:
                return 0
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            bad = METACHARS & set(line)
            if bad:
                out(f"rshell: parse error: character {sorted(bad)[0]!r} "
                    "is not permitted")
                continue
            parts = line.split()
            cmd, args = parts[0], parts[1:]
            if cmd == "exit":
                return 0
            handler = getattr(self, f"cmd_{cmd}", None)
            if handler is None or cmd not in ALLOWED:
                out(f"rshell: {cmd}: command not permitted")
                continue
            try:
                handler(args)
            except SystemExit:
                return 0
            except BrokenPipeError:
                return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", default=os.path.expanduser("~"))
    ap.add_argument("--etc", default=os.environ.get("JIMMY_ETC", "/etc"))
    a = ap.parse_args()
    return RShell(a.home, a.etc).run()


if __name__ == "__main__":
    sys.exit(main())
