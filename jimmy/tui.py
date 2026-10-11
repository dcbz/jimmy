"""Live session watcher: watch a run while it happens.

The harness already persists everything incrementally — `transcript.raw`
grows as bytes flow over the PTY, `experiments.jsonl` appends one record
per experiment, `graph.json` is saved after every graph update, and
`status.json` is a heartbeat the agent loop writes. So the TUI needs no
IPC: it tails the run directory.

Layout:

    ┌ header: run id · LIVE/finished · budget ┐
    │ experiments table │ session screen       │
    │ (hypotheses,      │ (pyte replay of the  │
    │  marks, verdicts) │  live PTY stream)    │
    │ capability graph  │ selected experiment  │
    │                   │ checks/basis/caveats │
    └ footer: bindings · usage · phase ┘

Textual is an optional dependency (`pip install jimmy[watch]`); the
pure state-reading helpers below work without it, which also gives
`--once` text snapshots and makes the module testable headless.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import pyte

COLS, ROWS = 80, 24

# ---------------------------------------------------------------- state readers

def tail_jsonl(path: str, offset: int = 0, buf: str = "") -> tuple[list, int, str]:
    """Append-only JSONL tail. Returns (records, new_offset, leftover).
    A torn final line is kept in *buf* until the newline lands."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return [], offset, buf
    lines = (buf + data.decode("utf-8", errors="replace")).split("\n")
    buf = lines.pop()                      # incomplete tail (may be "")
    out = []
    for ln in lines:
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                out.append({"_parse_error": ln[:200]})
    return out, offset + len(data), buf


class TranscriptReplayer:
    """Feeds transcript.raw incrementally into a pyte screen."""

    def __init__(self, cols: int = COLS, rows: int = ROWS):
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self._offset = 0

    def feed(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size < self._offset:            # truncated (reset/replay): restart
            self.screen.reset()
            self._offset = 0
        try:
            with open(path, "rb") as f:
                f.seek(self._offset)
                chunk = f.read()
        except OSError:
            return
        if chunk:
            try:
                self.stream.feed(chunk)
            except Exception:  # noqa: BLE001 — malformed bytes never kill the viewer
                pass
            self._offset += len(chunk)

    def text(self) -> str:
        return "\n".join(
            "".join(self.buffer[y][x].data for x in range(self.screen.columns))
            .rstrip() for y in range(self.screen.lines))

    @property
    def buffer(self):
        return self.screen.buffer


def load_status(run_dir: str) -> dict:
    try:
        with open(os.path.join(run_dir, "status.json")) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def graph_view(run_dir: str) -> dict:
    """Rebuild the planner's view from the persisted graph — same closure
    semantics the harness uses, not a guess from raw records."""
    from .capability import CapabilityGraph
    try:
        g = CapabilityGraph(path=os.path.join(run_dir, "graph.json"))
    except Exception:  # noqa: BLE001 — missing/partial file
        return {"verified": [], "hypothesized": [], "disproven": 0}
    v = sorted(g.closure())
    return {"verified": v,
            "hypothesized": sorted(g.all_facts() - set(v)),
            "disproven": len(g.disproven)}


def load_report(run_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(run_dir, "report.json")) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def describe_run(run_dir: str) -> dict:
    meta = {}
    try:
        with open(os.path.join(run_dir, "meta.json")) as f:
            meta = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass
    return meta


# ---------------------------------------------------------------- plain snapshot

def snapshot_text(run_dir: str, rec_tail: list, replay: TranscriptReplayer,
                  status: dict, graph: dict,
                  report: Optional[dict]) -> str:
    """One text frame — used by --once and by tests."""
    lines = [f"run dir : {run_dir}"]
    if report:
        lines.append(f"status  : {report.get('status')}"
                     f"{' (FALSE POSITIVE!) ' if report.get('false_positive') else ''}")
    else:
        lines.append(f"phase   : {status.get('phase', 'unknown')}"
                     f"  turns {status.get('turns', '?')}/"
                     f"{status.get('max_turns', '?')}"
                     f"  experiments {status.get('experiments', '?')}/"
                     f"{status.get('max_experiments', '?')}")
    lines.append("")
    lines.append("EXPERIMENTS")
    for r in rec_tail[-15:]:
        mark = "✓" if r.get("verified_capability") else ("✗" if "verified_capability" in r else "?")
        hyp = (r.get("hypothesis") or "?")[:66]
        lines.append(f"  {mark} [{r.get('id', '?')}] {hyp}")
    lines.append("")
    lines.append("GRAPH   verified: " + (", ".join(graph.get("verified") or [])
                                         or "none"))
    if graph.get("hypothesized"):
        lines.append("        hypothesized: "
                     + ", ".join(graph["hypothesized"][:6]))
    cav = []
    for r in rec_tail[-6:]:
        for c in (r.get("observation") or {}).get("checks", []):
            cav.extend(c.get("caveats", []))
    cav += ((report or {}).get("verifier_verdict") or {}).get("caveats", [])
    for c in cav[-3:]:
        lines.append(f"  ⚠ {c[:110]}")
    lines.append("")
    lines.append("SESSION SCREEN")
    lines.extend("| " + ln for ln in replay.text().splitlines())
    return "\n".join(lines)


# ---------------------------------------------------------------- textual app

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import DataTable, Header, Footer, Static
    from textual.binding import Binding
    from rich.text import Text as RichText
    TEXTUAL = True
except ImportError:  # pragma: no cover
    TEXTUAL = False

if TEXTUAL:

    class WatchApp(App):
        """Live TUI: `jimmy watch <run_dir>`."""

        CSS = """
        Screen { layers: base table right; }
        #left { width: 42%; dock: left; }
        #exptable { height: 1fr; border: round $primary; }
        #graph { height: 9; border: round $accent; }
        #screenview { height: 26; border: round $success; }
        #detail { height: 1fr; border: round $warning; }
        #banner { height: auto; }
        """

        BINDINGS = [
            Binding("q", "halt", "quit (asks a live run to stop first)"),
            Binding("p", "pause", "pause/resume polling"),
            Binding("r", "replay_screen", "replay transcript from start"),
            Binding("tab", "focus_next", "focus panes (arrows scroll the "
                                          "experiment table when it has focus)"),
        ]

        def __init__(self, run_dir: str, stop_fn=None, state: Optional[dict] = None,
                     attachable: bool = False):
            # stop_fn/state are set when the run lives in this same process
            # (`jimmy run --watch`): q must mean "stop it", not "orphan it".
            # attachable says the escaped session is REACHABLE from here —
            # on a declared breakout the view then closes itself and hands
            # the shell over. An external watcher must never do that; the
            # session lives in the run's own terminal, and it says so.
            super().__init__()
            self.run_dir = run_dir
            self.replay = TranscriptReplayer()
            self._off = {"exp": 0, "expbuf": ""}
            self._records: list = []
            self._paused = False
            self._last_finished = False
            self.stop_fn = stop_fn
            self.state = state if state is not None else {}
            self._q_hits = 0
            self.attachable = attachable
            self._splash_done = False

        def action_halt(self) -> None:
            if self.stop_fn is None or load_report(self.run_dir) \
                    or self.state.get("error"):
                self.exit()
                return
            self._q_hits += 1
            if self._q_hits == 1:
                self.stop_fn()          # cooperative; report lands next turn
                self.notify("stop requested — the run ends its current turn "
                            "and writes its report. q again to leave now.",
                            severity="warning", timeout=6)
            else:
                self.notify("leaving — the run thread is finishing up; the "
                            "report prints when it lands.", timeout=6)
                self.exit()

        # -- layout ---------------------------------------------------------

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal():
                with Vertical(id="left"):
                    yield DataTable(id="exptable")
                    yield Static("", id="graph")
                with Vertical(id="right"):
                    yield Static("", id="screenview")
                    yield Static("", id="detail")
            yield Footer()

        def on_mount(self) -> None:
            meta = describe_run(self.run_dir)
            kind = ((meta.get("target") or {}).get("kind")) or "?"
            self.title = f"jimmy — {os.path.basename(self.run_dir)} · {kind}"
            self.sub_title = "LIVE" if not load_report(self.run_dir) \
                else "finished"
            t = self.query_one("#exptable", DataTable)
            t.add_columns(" ", "id", "hypothesis")
            t.cursor_type = "row"
            self._tick()
            self.set_interval(0.4, self._tick)

        # -- polling ----------------------------------------------------------

        def _tick(self) -> None:
            if self._paused:
                return
            report = load_report(self.run_dir)
            status = load_status(self.run_dir)
            try:
                self.replay.feed(os.path.join(self.run_dir, "transcript.raw"))
            except Exception:  # noqa: BLE001
                pass
            recs, self._off["exp"], self._off["expbuf"] = tail_jsonl(
                os.path.join(self.run_dir, "experiments.jsonl"),
                self._off["exp"], self._off["expbuf"])
            if recs:
                self._records.extend(recs)
                t = self.query_one("#exptable", DataTable)
                for r in recs:
                    mark = ("✓" if r.get("verified_capability")
                            else "✗" if "verified_capability" in r else "?")
                    t.add_row(mark, r.get("id", "?"),
                              (r.get("hypothesis") or "?")[:60], key=str(len(self._records) - 1))
            graph = graph_view(self.run_dir)
            self._repaint(graph, status, report)
            if report and not self._last_finished:
                self._last_finished = True
                if not ((report.get("verifier_verdict") or {})
                        .get("shell_restriction_bypass")):
                    self.sub_title = f"finished — {report.get('status')}"
                    # breakout keeps the ★ BREAKOUT headline _repaint set

        def _repaint(self, graph: dict, status: dict, report) -> None:
            sv = self.query_one("#screenview", Static)
            sv.update(self._pyte_text())
            g = self.query_one("#graph", Static)
            v = sorted(graph.get("verified") or [])
            h = sorted(graph.get("hypothesized") or [])
            g.update("[b]capability graph[/b]\n"
                     f" ✓ {'  '.join(v) or '—'}\n"
                     f" ? {'  '.join(h[:6]) or '—'}   "
                     f"(disproven: {graph.get('disproven', 0)})")
            b = status.get("phase", "")
            self.title = f"jimmy — {os.path.basename(self.run_dir)}"
            if report:
                if ((report.get("verifier_verdict") or {})
                        .get("shell_restriction_bypass")):
                    self._announce_breakout(report)
                else:
                    fp = report.get("false_positive")
                    self.sub_title = ("FINISHED: " + str(report.get("status"))
                                      + ("  ⚠FALSE POSITIVE" if fp else ""))
            elif self.state.get("error"):
                self.sub_title = (f"AGENT CRASHED: "
                                  f"{type(self.state['error']).__name__}"
                                  " — see error.log, q to leave")
            else:
                self.sub_title = (f"LIVE · turns "
                                  f"{status.get('turns', '?')}/{status.get('max_turns', '?')}"
                                  f" · exp {status.get('experiments', '?')}"
                                  f"/{status.get('max_experiments', '?')}"
                                  f" · {b}")

        def _pyte_text(self):
            out = RichText()
            for y in range(self.replay.screen.lines):
                if y:
                    out.append("\n")
                run_txt, run_style = "", None
                for x in range(self.replay.screen.columns):
                    ch = self.replay.buffer[y][x]
                    style = ""
                    if ch.fg and ch.fg != "default":
                        style += f"#{ch.fg}"
                    if ch.bold:
                        style = "bold " + style
                    if style != run_style:
                        if run_txt:
                            out.append(run_txt, style=run_style or None)
                        run_txt, run_style = "", style
                    run_txt += ch.data if ch.data != " " else " "
                if run_txt:
                    out.append(run_txt, style=run_style or None)
            return out

        def _announce_breakout(self, report: dict) -> None:
            """The one moment this whole view exists for. It must be loud,
            unmissable, and — when the session is reachable from here —
            self-clearing: the operator's next screen IS the escape."""
            basis = ", ".join(sorted({b.get("channel", "?")
                                      for b in report.get(
                                          "verifier_verdict", {}
                                      ).get("basis", [])})) or "n/a"
            self.sub_title = ("★ BREAKOUT — host-verified · "
                              + ("this view closes; your shell is next"
                                 if self.attachable else
                                 "session held in the run's own terminal"))
            if self._splash_done:
                return
            self._splash_done = True
            d = self.query_one("#detail", Static)
            d.update(RichText.from_markup(
                "[b]══════════ B R E A K O U T ══════════[/b]\n"
                "The host verifier demonstrated unrestricted\n"
                "command execution in the live session.\n\n"
                + (f"  basis: [cyan]{basis}[/]\n\n"
                   "  This view closes itself and hands you the\n"
                   "  session — no keypress needed. Ctrl-] detaches\n"
                   "  the shell later; the transcript keeps recording."
                   if self.attachable else
                   "  The run's own terminal is holding the live\n"
                   "  session — it is handing over the shell there.\n"
                   "  Report: [dim]" + os.path.join(self.run_dir,
                                                    "report.json")
                   + "[/]")))
            self.notify("breakout verified by the host — declaring success",
                        severity="information", timeout=8)
            if self.attachable:
                self.set_timer(3.5, self._close_for_handoff)

        def _close_for_handoff(self) -> None:
            # guard the race: a stopped-not-declared report can't land after
            # a breakout splash (single writer), but a crash can — only the
            # bypass verdict opens a shell.
            try:
                rep = load_report(self.run_dir)
            except Exception:  # noqa: BLE001
                rep = None
            if not rep or not (rep.get("verifier_verdict") or {}) \
                    .get("shell_restriction_bypass"):
                return
            self.exit()

        # -- interaction -------------------------------------------------------

        def on_data_table_row_selected(self, event) -> None:
            try:
                rec = self._records[int(event.row_key.value)]
            except (ValueError, KeyError, IndexError):
                return
            d = self.query_one("#detail", Static)
            lines = [f"[b]{rec.get('hypothesis')}[/b]",
                     f"capability: {rec.get('expected_capability')}"
                     f" · source: {rec.get('source')}", ""]
            for c in (rec.get("observation") or {}).get("checks", []):
                mark = "[green]PASS[/]" if c.get("passed") else "[red]FAIL[/]"
                lines.append(f" {mark} {c.get('kind')}")
                for bs in c.get("basis", []):
                    lines.append(f"      via [cyan]{bs.get('channel')}[/]"
                                 f" ([magenta]trust={bs.get('trust')}[/])")
                for cv in c.get("caveats", []):
                    lines.append(f"      ⚠ [yellow]{cv}[/yellow]")
            v = (rec.get("observation") or {}).get("verdict") or {}
            lines.append("")
            lines.append("verdict: " + "  ".join(
                ("✓ " if v.get(k) else "· ") + k.replace("_", " ")
                for k in ("shell_restriction_bypass", "fs_containment_escape",
                          "privilege_escalation")))
            d.update(RichText.from_markup("\n".join(lines)))

        def action_pause(self) -> None:
            self._paused = not self._paused
            self.screen.sub_title = "PAUSED" if self._paused else ""

        def action_replay_screen(self) -> None:
            self.replay = TranscriptReplayer()
            self.replay.feed(os.path.join(self.run_dir, "transcript.raw"))


def newest_run_dir(base: str = "runs") -> Optional[str]:
    if not os.path.isdir(base):
        return None
    cands = [os.path.join(base, d) for d in os.listdir(base)
             if os.path.isfile(os.path.join(base, d, "meta.json"))]
    if not cands:
        return None
    return max(cands, key=os.path.getmtime)
