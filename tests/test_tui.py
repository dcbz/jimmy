"""Headless tests for the live watcher's state-reading layer."""

import asyncio
import json
import os

import pytest

from jimmy.tui import (TranscriptReplayer, graph_view, snapshot_text,
                         tail_jsonl)


def test_tail_jsonl_partial_lines(tmp_path):
    p = str(tmp_path / "experiments.jsonl")
    with open(p, "w") as f:
        f.write('{"id": 1}\n{"id": 2')          # second line torn mid-write
    recs, off, buf = tail_jsonl(p)
    assert [r["id"] for r in recs] == [1]
    with open(p, "a") as f:
        f.write('}\n{"id": 3}\n')               # rest lands + new record
    recs2, off2, buf2 = tail_jsonl(p, off, buf)
    assert [r["id"] for r in recs2] == [2, 3]
    assert buf2 == ""


def test_replay_tracks_growth_and_resets_on_truncate(tmp_path):
    p = str(tmp_path / "transcript.raw")
    rep = TranscriptReplayer()
    with open(p, "wb") as f:
        f.write(b"hello\r\n")
    rep.feed(p)
    assert "hello" in rep.text()
    with open(p, "ab") as f:
        f.write(b"world\r\n")
    rep.feed(p)
    assert "world" in rep.text()
    with open(p, "wb") as f:                      # shrink = re-created file
        f.write(b"fresh\r\n")
    rep.feed(p)
    assert "fresh" in rep.text() and "world" not in rep.text()


def test_graph_view_closure_from_disk(tmp_path):
    from jimmy.capability import CapabilityGraph
    g = CapabilityGraph(path=str(tmp_path / "graph.json"))
    g.add_or_update("textedit", "write", verified=True, evidence_id="ev-1")
    g.save()
    v = graph_view(str(tmp_path))
    assert "write.textedit" in v["verified"]
    assert v["disproven"] == 0


def test_snapshot_text_renders_everything(tmp_path):
    (tmp_path / "meta.json").write_text(json.dumps({"target": {"kind": "demo"}}))
    (tmp_path / "transcript.raw").write_bytes(b"rshell$ id\r\nuid=1000\r\n")
    (tmp_path / "experiments.jsonl").write_text(json.dumps({
        "id": "exp-0001", "hypothesis": "textedit can write",
        "verified_capability": "write.textedit",
        "observation": {"checks": [{"kind": "write_contains", "passed": True,
                                    "basis": [{"channel": "demo-fs",
                                               "trust": "control"}],
                                    "caveats": ["exec proof rests on the "
                                                "file marker alone"]}],
                        "verdict": {}}}) + "\n")
    (tmp_path / "status.json").write_text(json.dumps(
        {"phase": "thinking…", "turns": 3, "max_turns": 40,
         "experiments": 1, "max_experiments": 12}))
    rep = TranscriptReplayer()
    rep.feed(str(tmp_path / "transcript.raw"))
    recs, _, _ = tail_jsonl(str(tmp_path / "experiments.jsonl"))
    out = snapshot_text(str(tmp_path), recs, rep,
                        {"phase": "thinking…", "turns": 3, "max_turns": 40,
                         "experiments": 1, "max_experiments": 12},
                        graph_view(str(tmp_path)), None)
    assert "✓ [exp-0001] textedit can write" in out
    assert "phase   : thinking…" in out
    assert "uid=1000" in out
    assert "⚠ exec proof rests" in out


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_watch_app_boots(tmp_path):
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")
    (tmp_path / "transcript.raw").write_bytes(b"rshell$ help\r\n")

    async def go():
        app = WatchApp(str(tmp_path))
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.8)
            sv = app.query_one("#screenview")
            assert "rshell$" in sv.render().plain
    asyncio.run(go())


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_halt_asks_live_in_process_run_to_stop_first(tmp_path):
    """`run --watch`: first q requests a cooperative stop, second q leaves."""
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")
    calls = []

    async def go():
        app = WatchApp(str(tmp_path), stop_fn=lambda: calls.append(1),
                       state={})
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("q")           # stop requested
            assert calls == [1]
            assert app._q_hits == 1
            await pilot.press("q")           # leave now
            await pilot.pause(0.2)
        assert not app.is_running
    asyncio.run(go())


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_finished_run_exits_on_single_q(tmp_path):
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")
    (tmp_path / "report.json").write_text(json.dumps(
        {"status": "success", "false_positive": False}))
    calls = []

    async def go():
        app = WatchApp(str(tmp_path), stop_fn=lambda: calls.append(1))
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("q")
            await pilot.pause(0.2)
        assert calls == []                    # nothing to stop
        assert not app.is_running
    asyncio.run(go())


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_agent_crash_shows_in_header(tmp_path):
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")

    async def go():
        app = WatchApp(str(tmp_path), stop_fn=lambda: None,
                       state={"error": RuntimeError("boom")})
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.6)
            assert "AGENT CRASHED" in app.sub_title
    asyncio.run(go())


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_breakout_splash_headlines_and_auto_closes(tmp_path):
    """The view must shout the breakout and get out of its own way —
    this is the handoff the operator should never have to trigger."""
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")
    (tmp_path / "report.json").write_text(json.dumps(
        {"status": "breakout", "declared_by": "harness",
         "false_positive": False,
         "verifier_verdict": {"shell_restriction_bypass": True,
                              "basis": [{"channel": "local-demo-fs",
                                         "trust": "control"}]}}))

    async def go():
        app = WatchApp(str(tmp_path), state={}, attachable=True)
        scheduled = []
        app.set_timer = lambda delay, callback, **kw: scheduled.append(
            (delay, callback))
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.6)
            assert "BREAKOUT" in app.sub_title
            closers = [cb for d, cb in scheduled
                       if cb == app._close_for_handoff]
            assert closers
            assert all(d <= 5 for d, cb in scheduled
                       if cb == app._close_for_handoff)
            detail = app.query_one("#detail")
            assert "B R E A K O U T" in detail.render().plain
            closers[0]()                       # the timer firing
            await pilot.pause(0.3)
        assert not app.is_running              # closed itself; no q needed
    asyncio.run(go())


@pytest.mark.skipif(os.environ.get("JIMMY_SKIP_TUI_APP"), reason="opt-out")
def test_external_watch_announces_without_grabbing(tmp_path):
    """A second-terminal watcher sees the same headline but must never
    close or steal a session it cannot reach."""
    pytest.importorskip("textual")
    from jimmy.tui import WatchApp
    (tmp_path / "meta.json").write_text("{}")
    (tmp_path / "report.json").write_text(json.dumps(
        {"status": "breakout", "declared_by": "harness",
         "false_positive": False,
         "verifier_verdict": {"shell_restriction_bypass": True,
                              "basis": []}}))

    async def go():
        app = WatchApp(str(tmp_path))          # external view: not attachable
        scheduled = []
        app.set_timer = lambda delay, callback, **kw: scheduled.append(
            (delay, callback))
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.6)
            assert "BREAKOUT" in app.sub_title
            assert "own terminal" in app.sub_title
            assert app._splash_done
            assert all(cb != app._close_for_handoff for _, cb in scheduled)
            assert app.is_running              # stays open until q
            await pilot.press("q")
            await pilot.pause(0.2)
    asyncio.run(go())
