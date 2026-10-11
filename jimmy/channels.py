"""Observation channels: evidence has provenance.

A capability claim is established through one or more *channels*, each with
a trust level describing who controls it and how forgeable it is:

    session   the PTY stream under test. Proves READ (random canary text
              appearing in output), nothing else — a compromised app can
              print anything.
    guest     a side connection at the SUBJECT'S OWN privilege (e.g. a
              second ssh session into the account). Sees process creation
              and user-owned files, cannot see root-owned state.
    control   the harness's own control plane (docker exec as root, the
              sandbox filesystem). Strong file/process observation.
    trace     kernel-level event stream (strace execve attached from the
              host). The only basis a pure write primitive cannot forge.

The broker routes each check kind to the STRONGEST available channel that
produces it, and applies the lesson of the tmux case: a file-marker exec
proof is demoted with a caveat when the capability graph already
demonstrates a write primitive, because a writer that expands environment
variables could plant the marker without executing anything.

`verify_boundary` / `list_channels` expose all of this to the model so it
can reason about the strength of its own evidence.
"""

from __future__ import annotations

import abc
import platform
import re
import shutil
import subprocess
import time
from typing import Callable, Optional

TRUST_ORDER = {"session": 1, "guest": 2, "control": 3, "trace": 4}


class Evidence:
    def __init__(self, ok: bool, detail: str, basis: list,
                 caveats: Optional[list] = None):
        self.ok = ok
        self.detail = detail
        self.basis = basis        # [{"channel": id, "trust": level}, ...]
        self.caveats = caveats or []

    def as_dict(self) -> dict:
        return {"ok": self.ok, "detail": self.detail[:1500],
                "basis": self.basis, "caveats": self.caveats}


class Channel(abc.ABC):
    id: str = "channel"
    trust: str = "session"

    def produces(self) -> tuple:
        return ()

    def available(self) -> bool:
        return True

    def status(self) -> dict:
        return {"channel": self.id, "trust": self.trust,
                "available": self.available(),
                "produces": list(self.produces())}


class SessionChannel(Channel):
    """The raw PTY transcript of the subject session."""
    id = "pty-session"
    trust = "session"

    def __init__(self, transcript_provider: Callable[[], str]):
        self._provider = transcript_provider

    def produces(self):
        return ("canary_read", "outside_canary_read")

    def transcript(self) -> str:
        try:
            return self._provider()
        except Exception:  # noqa: BLE001
            return ""


class FsChannel(Channel):
    """Filesystem + process observation via a target's host_exec.

    trust='control' when host_exec runs above the subject (root in the
    container, the harness's own sandbox); trust='guest' when it runs at
    the subject's own uid (second ssh connection)."""
    trust = "control"

    def __init__(self, target, id: str = "fs", trust: Optional[str] = None,
                 exec_fn: Optional[Callable] = None):
        self.target = target
        self.id = id
        if trust:
            self.trust = trust
        self._exec_fn = exec_fn

    def produces(self):
        return ("file_exists", "file_absent", "file_contains",
                "write_contains", "exec_proof", "uid_snapshot",
                "process_exec", "snapshot")

    def exec(self, argv: list) -> tuple[int, str, str]:
        try:
            if self._exec_fn is not None:
                return self._exec_fn(argv)
            return self.target.host_exec(argv)
        except Exception as e:  # noqa: BLE001
            return 1, "", str(e)

    def marker_content(self) -> str:
        rc, out, _ = self.exec(["cat", self.target.sentinels["exec_proof_path"]])
        return out if rc == 0 else ""

    def procs(self) -> str:
        rc, out, err = self.exec(
            ["sh", "-c", "ps -eo pid=,uid=,comm= 2>/dev/null || ps aux"])
        return out or err


class TraceChannel(Channel):
    """strace -f -e trace=execve attached to the subject's init pid,
    armed for the duration of one experiment (Linux hosts only)."""
    id = "trace-execve"
    trust = "trace"

    def __init__(self, pid_provider: Callable[[], Optional[int]],
                 strace_bin: str = "strace"):
        self.pid_provider = pid_provider
        self.strace_bin = strace_bin
        self.out_path: Optional[str] = None   # set by the harness
        self.proc: Optional[subprocess.Popen] = None

    def produces(self):
        return ("execve_events", "process_exec", "exec_proof")

    def available(self) -> bool:
        if platform.system() != "Linux" or not shutil.which(self.strace_bin):
            return False
        try:
            return self.pid_provider() is not None
        except Exception:  # noqa: BLE001
            return False

    def arm(self) -> bool:
        if self.proc is not None or not self.out_path or not self.available():
            return False
        try:
            pid = self.pid_provider()
            with open(self.out_path, "w"):
                pass
            self.proc = subprocess.Popen(
                [self.strace_bin, "-qq", "-f", "-e", "trace=execve",
                 "-o", self.out_path, "-p", str(pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.15)   # let attach settle
            return True
        except Exception:  # noqa: BLE001
            self.proc = None
            return False

    def harvest(self) -> list:
        """Return raw execve event lines collected since arm()."""
        if self.proc is None:
            return []
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                self.proc.kill()
            except Exception:  # noqa: BLE001
                pass
        self.proc = None
        try:
            with open(self.out_path, errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return []
        return [ln for ln in lines
                if "execve(" in ln and "= -1" not in ln]


_EXECVE_RE = re.compile(r'execve\("([^"]*)"')


def execve_paths(lines: list) -> list:
    return [m.group(1) for ln in lines
            for m in [_EXECVE_RE.search(ln)] if m]


class ChannelBroker:
    """Routes check evaluation through channels by trust strength."""

    def __init__(self, channels: list, target, graph):
        self.channels = channels
        self.target = target
        self.graph = graph

    # -- introspection -----------------------------------------------------

    def status(self) -> list:
        return [c.status() for c in self.channels]

    def _strongest(self, kind: str, cap: Optional[str] = None):
        cands = [c for c in self.channels
                 if kind in c.produces() and c.available()]
        if cap:
            cands = [c for c in cands if TRUST_ORDER[c.trust] <= TRUST_ORDER[cap]]
        cands.sort(key=lambda c: TRUST_ORDER[c.trust], reverse=True)
        return cands

    # -- experiment windows --------------------------------------------------

    def window_start(self) -> None:
        for c in self.channels:
            if isinstance(c, TraceChannel):
                c.arm()

    def window_stop(self) -> list:
        events = []
        for c in self.channels:
            if isinstance(c, TraceChannel):
                events.extend(c.harvest())
        return events

    # -- snapshots -----------------------------------------------------------

    def snapshot(self) -> dict:
        fs = self._strongest("snapshot")
        if not fs:
            return {"ts": time.time(), "marker": "", "procs": "",
                    "basis": []}
        ch = fs[0]
        return {"ts": time.time(), "marker": ch.marker_content(),
                "procs": ch.procs(),
                "basis": [{"channel": ch.id, "trust": ch.trust}]}

    # -- check evaluation ------------------------------------------------------

    def evaluate(self, kind: str, path: Optional[str] = None,
                 marker: Optional[str] = None, pattern: Optional[str] = None,
                 events: Optional[list] = None,
                 snapshot: Optional[dict] = None) -> Evidence:
        events = events or []
        if kind in ("canary_read", "outside_canary_read"):
            key = ("read_token" if kind == "canary_read" else "outside_token")
            token = self.target.sentinels.get(key, "")
            sess = [c for c in self._strongest(kind)
                    if isinstance(c, SessionChannel)]
            ok = bool(token) and bool(sess) and token in sess[0].transcript()
            return Evidence(
                ok,
                f"canary {key} {'observed in' if ok else 'NOT in'} session transcript",
                [{"channel": sess[0].id, "trust": "session"}] if sess else [],
                caveats=[] if (ok or sess) else ["no session channel available"])

        if kind == "exec_proof":
            return self._eval_exec_proof(events, snapshot)

        if kind == "process_exec":
            basis = []
            hit = [ln for ln in events if pattern and pattern in ln]
            if hit:
                basis.append({"channel": "trace-execve", "trust": "trace"})
            fs = self._strongest("snapshot")
            procs_hit = False
            if fs and pattern:
                procs = (snapshot or self.snapshot())["procs"]
                procs_hit = any(pattern in ln for ln in procs.splitlines())
                if procs_hit:
                    basis.append({"channel": fs[0].id, "trust": fs[0].trust})
            ok = bool(hit) or procs_hit
            detail = (f"{len(hit)} execve event(s) matching {pattern!r}; "
                      f"ps match: {procs_hit}")
            return Evidence(ok, detail, basis)

        if kind == "uid_snapshot":
            fs = self._strongest("exec") or self._strongest("snapshot")
            if not fs:
                return Evidence(False, "no filesystem channel", [])
            rc, out, err = fs[0].exec(["id"])
            return Evidence(True, out or err,
                            [{"channel": fs[0].id, "trust": fs[0].trust}])

        # file_* kinds
        fs = self._strongest(kind)
        if not fs:
            return Evidence(False, f"no available channel produces {kind}", [])
        ch = fs[0]
        basis = [{"channel": ch.id, "trust": ch.trust}]
        if kind == "file_exists":
            rc, out, err = ch.exec(["ls", "-l", path])
            return Evidence(rc == 0, out or err, basis)
        if kind == "file_absent":
            rc, out, err = ch.exec(["ls", path])
            return Evidence(rc != 0, err or out or "absent", basis)
        rc, out, err = ch.exec(["cat", path])   # file_contains / write_contains
        ok = rc == 0 and bool(marker) and marker in out
        return Evidence(ok, f"content of {path}: " + (out or err)[:1200], basis)

    def _eval_exec_proof(self, events, snapshot) -> Evidence:
        token = getattr(self.target, "_exec_token", "")
        proof_path = self.target.sentinels.get("exec_proof_path", "exec_proof")
        basis, caveats = [], []

        # strongest basis: an actual execve whose argv mentions the proof file
        event_hit = [ln for ln in events if proof_path in ln or "JIMMY_TOKEN" in ln]
        if event_hit:
            basis.append({"channel": "trace-execve", "trust": "trace"})

        # marker basis: file contents (control or guest channel)
        marker_ok = False
        fs = [c for c in self._strongest("exec_proof") if isinstance(c, FsChannel)]
        if fs:
            content = ((snapshot or {}).get("marker", "")
                       or fs[0].marker_content())
            marker_ok = bool(token) and token in content
            if marker_ok:
                basis.append({"channel": fs[0].id, "trust": fs[0].trust})
        ok = bool(event_hit) or marker_ok

        if marker_ok and not event_hit:
            write_caps = [f for f in self.graph.closure()
                          if f.startswith("write.")]
            if write_caps:
                caveats.append(
                    "exec proof rests on the file marker alone; a write "
                    f"capability is already verified ({', '.join(write_caps)}), "
                    "and a writer that expands $JIMMY_TOKEN could plant it "
                    "without executing — confirm with the trace channel "
                    "(strace available on this target? see list_channels)")
            if fs and fs[0].trust == "guest":
                caveats.append("marker read at the subject's own privilege; "
                               "an env-expanding app readable to this uid "
                               "could fabricate it")
        detail = (f"{len(event_hit)} execve event(s) reference the proof "
                  "write; marker file "
                  + ("contains" if marker_ok else "does NOT contain")
                  + " the run token")
        return Evidence(ok, detail, basis, caveats)
