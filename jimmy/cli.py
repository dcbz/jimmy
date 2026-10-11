"""jimmy command line."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .agent import MODEL, Harness

# Respect a gateway/proxy deployment (ANTHROPIC_MODEL) when set.
DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL") or MODEL
from .evidence import EvidenceStore
from .targets import build_target


def cmd_run(args) -> int:
    import anthropic
    # Fail fast: the SDK only validates credentials when it builds the first
    # request, deep inside the agent loop — which, under --watch, means a
    # confusing crash in a worker thread instead of a startup message.
    client = anthropic.Anthropic()
    if not any((client.api_key, client.auth_token, client.credentials)):
        print("[jimmy] no Anthropic credentials in the environment: export "
              "ANTHROPIC_API_KEY (plus ANTHROPIC_BASE_URL if you use a "
              "gateway). Nothing was started.", file=sys.stderr)
        return 2
    base = os.environ.get("ANTHROPIC_BASE_URL")
    if base and "anthropic.com" not in base and not os.environ.get(
            "ANTHROPIC_MODEL"):
        print(f"[jimmy] note: ANTHROPIC_BASE_URL points at a custom "
              f"gateway ({base}) and ANTHROPIC_MODEL is unset — using the "
              f"default model name ({args.model}); if the gateway serves "
              f"others, this run will 404 on the first call. Export "
              f"ANTHROPIC_MODEL or pass --model.", file=sys.stderr)
    kw = {}
    if args.target == "demo":
        kw = {"root": args.root} if args.root else {}
    elif args.target == "docker":
        kw = {"image": args.image}
    elif args.target.startswith("ssh:"):
        kw = {"confirm_lab": args.i_confirm_this_is_a_lab,
              "user": args.user}
    target = build_target(args.target, **kw)
    run_dir = args.run_dir or EvidenceStore.new_run_dir(label=args.target)
    os.makedirs(run_dir, exist_ok=True)
    print(f"[jimmy] run dir: {run_dir}")
    print(f"[jimmy] target : {args.target} ({target.describe().get('kind')})")
    print(f"[jimmy] model  : {args.model} effort={args.effort}")
    if not args.yes:
        print("[jimmy] target must be a DISPOSABLE lab. Ctrl-C to abort, "
              "Enter to confirm.", file=sys.stderr)
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            return 1
    harness = Harness(target, run_dir, model=args.model, effort=args.effort,
                      max_experiments=args.max_experiments,
                      max_api_turns=args.max_turns, client=client,
                      keep_going=args.keep_going)
    if args.watch:
        return _run_and_watch(harness, run_dir, no_takeover=args.no_takeover)
    try:
        report = harness.run()
    except KeyboardInterrupt:
        print("\n[jimmy] interrupted; graph saved at "
              f"{os.path.join(run_dir, 'graph.json')}")
        return 130
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as e:
        # config/endpoint class of failure (404 model, connection, auth at
        # request time) — one honest line, like the --watch thread surface;
        # the hints above already said what to export.
        print(f"[jimmy] API request failed: {type(e).__name__}: {e}",
              file=sys.stderr)
        print(f"[jimmy] partial state saved under {run_dir}",
              file=sys.stderr)
        return 1
    _print_report(report)
    _offer_takeover(harness, report, no_takeover=args.no_takeover)
    return 0


def _stdin_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _offer_takeover(harness, report: dict, no_takeover: bool = False) -> None:
    """A verified bypass with a live session is a shell — hand it over.

    Automatic, not on request: the run ending in a bang nobody asked for
    is the point ("presenting the user with a working shell"). Only the
    host verifier's word authorizes this — status breakout is set solely
    by the harness — so no model text can talk its way into an
    operator-facing interactive session. --no-takeover opts out; a
    missing terminal (piped run) declines out loud instead of hanging."""
    v = report.get("verifier_verdict") or {}
    if not v.get("shell_restriction_bypass"):
        return
    if not harness.terminal.alive():
        print("[jimmy] bypass verified, but that session has exited "
              "(reset or crash after the verdict) — nothing to attach. The "
              "evidence stands in the run dir.", file=sys.stderr)
        return
    kind = (harness.target.describe() or {}).get("kind", "?")
    print("\n[jimmy] ── breakout declared by the harness ──")
    print("[jimmy] the escaped session is still live, held open by this "
          "process. You are looking at the thing the paper is about: a "
          "restricted shell that stopped restricting.")
    if kind == "local-demo":
        print("[jimmy] lab honesty: the demo jail is behavioral — what "
              "you attach to is an ordinary shell at your uid, modeling "
              "the attack surface, not a security boundary.",
              file=sys.stderr)
    if no_takeover:
        print("[jimmy] (--no-takeover: not attaching)", file=sys.stderr)
        return
    if not _stdin_tty():
        print("[jimmy] no terminal to hand the shell to (stdin/stdout are "
              "not a tty) — session ends with this process. Re-run under "
              "a real terminal to take it.", file=sys.stderr)
        return
    print("[jimmy] handing you the shell — your input now goes straight "
          "into the escaped session. Ctrl-] detaches.")
    try:
        harness.terminal.takeover()
    except Exception as e:  # noqa: BLE001 — never let attach break a report
        print(f"[jimmy] could not attach: {type(e).__name__}: {e}",
              file=sys.stderr)
        return
    print("[jimmy] detached. The session ends when this run exits; "
          "everything you did is in the transcript.")


def _run_and_watch(harness, run_dir: str,
                   no_takeover: bool = False) -> int:
    """Run the agent in a thread and drive the TUI from the main thread.

    No IPC is needed: the harness persists incrementally (transcript.raw,
    experiments.jsonl, graph.json, status.json) and the watcher tails the
    run dir, so same-process or other-terminal is the same code path. The
    only extra care is shutdown — quitting the view must stop the run
    cooperatively and wait for the report, not orphan the lab session."""
    import threading
    import traceback

    from . import tui
    if not tui.TEXTUAL:
        print("[jimmy] --watch needs textual: pip install 'jimmy[watch]'",
              file=sys.stderr)
        return 1

    state = {"report": None, "error": None, "done": threading.Event()}

    def _agent() -> None:
        try:
            state["report"] = harness.run()
        except BaseException as e:  # noqa: BLE001 — surfaced via TUI + stderr
            state["error"] = e
            try:
                with open(os.path.join(run_dir, "error.log"), "w") as f:
                    f.write(traceback.format_exc())
            except OSError:
                pass
        finally:
            state["done"].set()

    t = threading.Thread(target=_agent, name="jimmy-agent", daemon=True)
    t.start()
    try:
        tui.WatchApp(run_dir, stop_fn=harness.request_stop,
                     state=state, attachable=True).run()
    except KeyboardInterrupt:
        pass
    if t.is_alive():
        # The view can also close itself: the breakout splash hands over
        # after a few seconds with the thread still writing its epilogue.
        # A landed report means the loop is already done — requesting a
        # stop then would kill the very session about to be handed over.
        if state["report"] is None and not os.path.exists(
                os.path.join(run_dir, "report.json")):
            harness.request_stop()
        t.join(timeout=30)
    if t.is_alive():
        print("[jimmy] agent still mid-turn after stop request; "
              "killing the lab session and exiting.", file=sys.stderr)
        try:
            harness.terminal.stop()
        except Exception:  # noqa: BLE001
            pass
    if state["error"] is not None:
        e = state["error"]
        print(f"[jimmy] agent died: {type(e).__name__}: {e}",
              file=sys.stderr)
        print(f"[jimmy] full traceback: {run_dir}/error.log",
              file=sys.stderr)
        return 1
    if state["report"] is not None:
        _print_report(state["report"])
        # same handoff as the plain path — after the TUI has released the
        # terminal, the escaped session is still alive in the agent thread's
        # harness; joining the thread above guarantees nothing else touches it
        _offer_takeover(harness, state["report"], no_takeover=no_takeover)
        return 0
    print("[jimmy] run stopped before writing a report; graph at "
          f"{os.path.join(run_dir, 'graph.json')}")
    return 130


def cmd_demo(args) -> int:
    """Drop into the demo restricted shell yourself (lab sanity check)."""
    import pexpect
    t = build_target("demo", root=args.root)
    argv, cwd, env = t.spawn()
    print(f"[jimmy] sandbox: {t.root}  (Ctrl-] to detach)")
    c = pexpect.spawn(argv[0], argv[1:], env=env, cwd=cwd,
                      dimensions=(24, 80), encoding=None)
    c.interact()
    return 0


def cmd_report(args) -> int:
    with open(os.path.join(args.run_dir, "report.json")) as f:
        _print_report(json.load(f))
    return 0


def cmd_watch(args) -> int:
    from . import tui
    run_dir = args.run_dir or tui.newest_run_dir()
    if not run_dir or not os.path.isdir(run_dir):
        print("[jimmy] no run dir found under runs/ — pass one explicitly",
              file=sys.stderr)
        return 1
    if args.once:  # headless frame: no TTY, no textual needed
        rep = tui.TranscriptReplayer()
        rep.feed(os.path.join(run_dir, "transcript.raw"))
        recs, _, _ = tui.tail_jsonl(
            os.path.join(run_dir, "experiments.jsonl"))
        print(tui.snapshot_text(run_dir, recs, rep, tui.load_status(run_dir),
                                tui.graph_view(run_dir), tui.load_report(run_dir)))
        return 0
    if not tui.TEXTUAL:
        print("[jimmy] the live TUI needs textual: pip install 'jimmy[watch]'",
              file=sys.stderr)
        return 1
    tui.WatchApp(run_dir).run()
    return 0


_VERDICT_OUTCOME_KEYS = ("shell_restriction_bypass", "fs_containment_escape",
                         "privilege_escalation", "read_primitive_demonstrated")


def _print_report(report: dict) -> None:
    v = report.get("verifier_verdict", {})
    m = report.get("metrics", {})
    print("\n===== jimmy report =====")
    print(f"status        : {report.get('status')}")
    print(f"false positive: {report.get('false_positive')}")
    print("verifier verdicts (host-side, independent of model):")
    for k in _VERDICT_OUTCOME_KEYS:
        if k in v:
            print(f"  {'[YES]' if v[k] else '[ - ]'} {k}")
    for b in v.get("basis", []):
        print(f"    basis: {b['channel']} (trust={b['trust']})")
    for c in v.get("caveats", []):
        print(f"    CAVEAT: {c}")
    print(f"experiments   : {m.get('experiments')} | api turns: "
          f"{m.get('api_turns')} | {m.get('seconds')}s | "
          f"verified caps: {m.get('novel_verified_capabilities')} | "
          f"disproven: {m.get('disproven_hypotheses')}")
    narr = report.get("narrative", "")
    if narr:
        print("narrative:")
        print(narr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="jimmy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the research agent against a target")
    r.add_argument("--target", default="demo",
                   help="demo | docker | ssh:HOST")
    r.add_argument("--root", default=None,
                   help="sandbox root for the demo target")
    r.add_argument("--image", default="jimmy-lab:latest")
    r.add_argument("--user", default="root")
    r.add_argument("--model", default=DEFAULT_MODEL)
    r.add_argument("--effort", default="high",
                   choices=["low", "medium", "high", "xhigh", "max"])
    r.add_argument("--max-experiments", type=int, default=40)
    r.add_argument("--max-turns", type=int, default=120)
    r.add_argument("--run-dir", default=None)
    r.add_argument("--keep-going", action="store_true",
                   help="do not stop when the host verifier declares the "
                        "breakout; keep researching for coverage (the "
                        "declaration is still made once)")
    r.add_argument("--no-takeover", action="store_true",
                   help="on a verified bypass, do not hand over the live "
                        "escaped session (default: attach automatically)")
    r.add_argument("--watch", action="store_true",
                   help="run the agent in-process and show the live TUI in "
                        "this terminal (same as watching a run in a second "
                        "window); q stops the run first, then quits")
    r.add_argument("--yes", action="store_true",
                   help="skip the interactive disposable-lab confirmation")
    r.add_argument("--i-confirm-this-is-a-lab", action="store_true",
                   help="required for ssh targets")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="interactive shell into the demo lab")
    d.add_argument("--root", default=None)
    d.set_defaults(func=cmd_demo)

    p = sub.add_parser("report", help="print a previous run's report")
    p.add_argument("run_dir")
    p.set_defaults(func=cmd_report)

    w = sub.add_parser("watch", help="live TUI over a run dir")
    w.add_argument("run_dir", nargs="?", default=None,
                   help="run directory; defaults to the newest under runs/")
    w.add_argument("--once", action="store_true",
                   help="print one text snapshot and exit (no TTY needed)")
    w.set_defaults(func=cmd_watch)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
