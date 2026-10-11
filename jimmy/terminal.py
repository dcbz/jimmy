"""Interactive PTY terminal controller.

Wraps a target process in a real pty (pexpect) and maintains two views of it:

* raw byte stream — lossless, kept for evidence;
* normalized screen — pyte terminal emulation so fullscreen apps
  (editors, pagers) are readable as text rather than escape-sequence soup.

Prompt detection combines output quiescence (the primary signal) with a
lightweight line heuristic — the design explicitly avoids regex-only
detection, because a restricted shell can print a convincing prompt without
being at one.
"""

from __future__ import annotations

import dataclasses
import os
import re
import time
from typing import Optional

import pexpect
import pyte

# Named keys translated for the model. Literal text passes through unchanged.
KEYCODES = {
    "<Enter>": "\r",
    "<CR>": "\r",
    "<C-c>": "\x03",
    "<C-d>": "\x04",
    "<C-z>": "\x1a",
    "<C-l>": "\x0c",
    "<Tab>": "\t",
    "<Esc>": "\x1b",
    "<BS>": "\x7f",
    "<Up>": "\x1b[A",
    "<Down>": "\x1b[B",
    "<Right>": "\x1b[C",
    "<Left>": "\x1b[D",
    "<Home>": "\x1b[H",
    "<End>": "\x1b[F",
    "<PgUp>": "\x1b[5~",
    "<PgDn>": "\x1b[6~",
}

_KEY_RE = re.compile(r"<[A-Za-z][A-Za-z0-9-]*>")


def encode_keys(seq: str) -> bytes:
    """Encode a keystroke string: `<Name>` tokens plus literals -> bytes."""
    out: list[str] = []
    i = 0
    while i < len(seq):
        m = _KEY_RE.match(seq, i)
        if m:
            name = m.group(0)
            if name in KEYCODES:
                out.append(KEYCODES[name])
            else:
                # Unknown <token>: send literally (safer than guessing).
                out.append(name)
            i = m.end()
        elif seq[i] == "\\" and i + 1 < len(seq):
            nxt = seq[i + 1]
            special = {"n": "\n", "r": "\r", "t": "\t", "e": "\x1b", "\\": "\\"}
            out.append(special.get(nxt, seq[i:i + 2]))
            i += 2
        else:
            out.append(seq[i])
            i += 1
    return "".join(out).encode("utf-8", "surrogateescape")


@dataclasses.dataclass
class Observation:
    raw_tail: str          # last chunk of raw output produced by this action
    screen: str            # normalized pyte screen
    at_prompt: bool        # quiescent + prompt-ish final line
    prompt_line: str
    alive: bool
    eof: bool

    def summary(self, screen_limit: int = 4000) -> str:
        return "\n".join([
            f"[prompt] {self.prompt_line!r}  at_prompt={self.at_prompt}  "
            f"alive={self.alive} eof={self.eof}",
            f"[screen]\n{self.screen[:screen_limit]}",
        ])


class PtyTerminal:
    """One live session against a target process."""

    def __init__(self, spawn_fn, cols: int = 80, rows: int = 24,
                 idle_time: float = 0.45, max_read_time: float = 12.0,
                 transcript_path: Optional[str] = None):
        # spawn_fn: zero-arg callable -> (argv, cwd, env). Called on every
        # start() so a target reset (fresh tokens/env) is picked up.
        self.spawn_fn = spawn_fn
        self.cols, self.rows = cols, rows
        self.idle_time = idle_time
        self.max_read_time = max_read_time
        self.transcript_path = transcript_path
        self.child: Optional[pexpect.spawn] = None
        self._screen = pyte.Screen(cols, rows)
        self._stream = pyte.ByteStream(self._screen)
        self._pending = ""  # raw bytes not yet consumed by an observation

    # -- lifecycle ------------------------------------------------------

    def start(self) -> Observation:
        if self.child is not None and self.child.isalive():
            raise RuntimeError("terminal already running; call stop() first")
        self._screen.reset()
        argv, cwd, env = self.spawn_fn()
        env = dict(env) if env is not None else dict(os.environ)
        env.setdefault("TERM", "xterm")
        self.child = pexpect.spawn(
            argv[0], argv[1:], dimensions=(self.rows, self.cols),
            encoding=None, env=env, cwd=cwd,
            codec_errors="replace",
        )
        self.child.delaybeforesend = 0.03
        return self._read()

    def alive(self) -> bool:
        return self.child is not None and self.child.isalive()

    def stop(self) -> None:
        if self.child is not None:
            try:
                if self.child.isalive():
                    self.child.terminate(force=True)
            except Exception:
                pass
            self.child = None

    # -- I/O ------------------------------------------------------------

    def send(self, keys: str, wait: bool = True) -> Observation:
        if not self.alive():
            raise RuntimeError("target session is not running")
        self.child.send(encode_keys(keys))
        return self._read() if wait else self._read(timeout=0.3)

    def read(self, timeout: Optional[float] = None) -> Observation:
        return self._read(timeout=timeout)

    def takeover(self) -> bool:
        """Hand the live session to the operator: real keyboard <-> child.

        Used by the CLI when the host verifier has declared a breakout —
        the point of the exercise is to see the shell actually open, and
        a declared victory nobody can touch is just a log line. Ctrl-]
        detaches. Output keeps tee-ing into the evidence transcript via
        interact()'s output_filter, so the run's record still covers what
        happened after the machine stopped acting. Returns False if there
        is no live session to attach to."""
        if not self.alive():
            return False
        log = None
        if self.transcript_path:
            try:
                log = open(self.transcript_path, "ab")
                log.write(b"\n[[ operator take-over: session attached ]]\n")
                log.flush()
            except OSError:
                log = None

        def tee(data):
            if log is not None:
                try:
                    log.write(data if isinstance(data, bytes)
                              else data.encode("utf-8", "replace"))
                    log.flush()
                except OSError:
                    pass
            return data

        try:
            self.child.interact(escape_character=chr(29),  # Ctrl-]
                                output_filter=tee)
        except (EOFError, KeyboardInterrupt):
            pass  # detach cleanly; the session itself stays as-is
        finally:
            if log is not None:
                try:
                    log.write(b"\n[[ take-over ended ]]\n")
                    log.close()
                except OSError:
                    pass
        return True

    # -- internals ------------------------------------------------------

    def _read(self, timeout: Optional[float] = None) -> Observation:
        """Pump bytes until the stream goes quiet, then snapshot the screen."""
        assert self.child is not None
        limit = timeout or self.max_read_time
        deadline = time.monotonic() + limit
        chunk: list[bytes] = []
        last = time.monotonic()
        eof = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                data = self.child.read_nonblocking(size=65536,
                                                   timeout=min(0.25, remaining))
            except pexpect.TIMEOUT:
                data = b""
            except pexpect.EOF:
                eof = True
                data = b""
            if data:
                chunk.append(data)
                self._stream.feed(data)
                self._record_transcript(data)
                last = time.monotonic()
            elif not self.child.isalive():
                # child gone and no buffered data left
                try:
                    more = self.child.read_nonblocking(size=65536, timeout=0.1)
                    if more:
                        chunk.append(more)
                        self._stream.feed(more)
                        self._record_transcript(more)
                        continue
                except (pexpect.TIMEOUT, pexpect.EOF):
                    pass
                eof = True
                break
            elif time.monotonic() - last > self.idle_time:
                break
            time.sleep(0.02)
        raw = b"".join(chunk).decode("utf-8", "replace")
        screen = "\n".join(self._screen.display)
        tail = raw[-6000:]
        prompt_line = self._guess_prompt_line(screen)
        at_prompt = self._looks_like_prompt(prompt_line)
        return Observation(raw_tail=tail, screen=screen, at_prompt=at_prompt,
                           prompt_line=prompt_line, alive=self.child.isalive(),
                           eof=eof or not self.child.isalive())

    def _record_transcript(self, data: bytes) -> None:
        if self.transcript_path:
            with open(self.transcript_path, "ab") as f:
                f.write(data)
                f.flush()

    @staticmethod
    def _guess_prompt_line(screen: str) -> str:
        lines = [ln.rstrip() for ln in screen.splitlines() if ln.strip()]
        return lines[-1] if lines else ""

    @staticmethod
    def _looks_like_prompt(line: str) -> bool:
        # Heuristic only — output quiescence is the real signal upstream.
        return bool(re.search(r"([$#%>]\s*|[\w.~@-]+\$ ?|[\w.~@-]+# ?)$", line))
