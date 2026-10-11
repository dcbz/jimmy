"""Auto-stop-and-handoff: the harness declares success on a verified bypass.

The run that motivated this (20261011-095713-demo-7cabc8) verified the
execute.textedit breakout by trace evidence at turn ~30 and then *kept
going* — churning the escape into capability prose for two more turns
before a budget note made it stop. The lesson is the same one as the
conversion nudge: a verified boundary is not another data point. These
tests pin the machine-side half of "success": detection, declaration,
the mutation guard, and the operator handoff prompt.
"""

import os
import types

import pytest

from jimmy import cli
from jimmy.agent import Harness
from jimmy.targets import LocalDemoTarget
from jimmy.terminal import PtyTerminal

BYPASS = {"shell_restriction_bypass": True,
          "fs_containment_escape": False,
          "privilege_escalation": False,
          "read_primitive_demonstrated": True,
          "basis": [{"channel": "trace-execve", "trust": "trace"}],
          "caveats": []}
CLEAN = dict(BYPASS, shell_restriction_bypass=False)


@pytest.fixture()
def harness(tmp_path):
    t = LocalDemoTarget(root=str(tmp_path / "jimmy-breakout-lab"))
    run = tmp_path / "run"
    run.mkdir()
    h = Harness(t, str(run), client=object())          # API never touched
    return h


def _note(**verdict_over):
    res = {"hypothesis": "h", "verified_any": True,
           "boundary_verdict": dict(BYPASS, **verdict_over)}
    return res


# ------------------------------------------------------------- registration

def test_experiment_verdict_registers_breakout_once(harness):
    harness._register_breakout(_note())
    assert harness._breakout is not None
    assert harness._breakout["evidence"] == ["trace-execve"]
    assert harness._breakout["experiment"] == "h"
    first = harness._breakout
    harness._register_breakout(_note())                # later runs: no-op
    assert harness._breakout is first


def test_registration_carries_harness_note(harness):
    res = _note()
    harness._register_breakout(res)
    assert "VERIFIED host-side" in res["harness_note"]


def test_clean_or_missing_verdicts_register_nothing(harness):
    harness._register_breakout({"boundary_verdict": CLEAN})
    harness._register_breakout({"boundary_verdict": {}})
    harness._register_breakout({})
    assert harness._breakout is None


def test_non_bypass_outcomes_do_not_stop_the_run(harness):
    # escape/privilege findings are real but not THE breakout; the loop's
    # predicate is shell_restriction_bypass specifically
    harness._register_breakout(_note(
        shell_restriction_bypass=False, fs_containment_escape=True,
        privilege_escalation=True, basis=[]))
    assert harness._breakout is None


# ------------------------------------------------------------------ stopping

def test_breakout_ends_the_run_with_a_harness_declaration(harness, tmp_path):
    harness._breakout = {"turn": 2, "experiment": "h",
                         "evidence": ["trace-execve"], "verdict": BYPASS}
    report = harness.run()                    # terminal starts; API never does
    assert report["status"] == "breakout"
    assert report["declared_by"] == "harness"
    assert report["false_positive"] is False
    assert report["verifier_verdict"]["shell_restriction_bypass"] is True
    assert "trace-execve" in report["narrative"]
    saved = os.path.join(str(tmp_path / "run"), "report.json")
    assert "breakout" in open(saved).read()


def test_keep_going_continues_past_the_breakout(harness, tmp_path):
    # harness (the fixture's) already ran in other tests? No — fresh
    # instance per test; reuse its target but not its run dir.
    h2 = Harness(harness.target, str(tmp_path / "run-kg"),
                 client=object(), keep_going=True)
    h2._breakout = {"turn": 1, "experiment": "h", "evidence": [],
                    "verdict": BYPASS}

    def boom():
        raise RuntimeError("API-WAS-REACHED")

    h2._call_api = boom
    with pytest.raises(RuntimeError, match="API-WAS-REACHED"):
        h2.run()                              # did not stop on the breakout
    assert h2.finished is None


def test_mutations_are_frozen_once_declared(harness):
    harness._breakout = {"turn": 0, "experiment": "h", "evidence": [],
                         "verdict": BYPASS}
    r = harness._tool("send_keys", {"keys": "ls<Enter>"})
    assert "rejected" in r and "breakout" in r["rejected"]
    r = harness._tool("propose_experiment", {"steps": [], "checks": []})
    assert "rejected" in r
    assert harness.policy.experiments_used == 0       # guard ran first


def test_keep_going_leaves_mutations_open(harness, tmp_path):
    h2 = Harness(LocalDemoTarget(root=str(tmp_path / "jimmy-open-lab")),
                 str(tmp_path / "run2"), client=object(), keep_going=True)
    h2._breakout = {"turn": 0, "experiment": "h", "evidence": [],
                    "verdict": BYPASS}
    r = h2._tool("send_keys", {"keys": "id"})         # alive() fails first
    assert "rejected" not in r                       # guard did not fire


# ---------------------------------------------------------------- handoff

class FakeHarness:
    def __init__(self, alive=True, kind="docker"):
        self.terminal = types.SimpleNamespace(alive=lambda: alive)
        self.target = types.SimpleNamespace(
            describe=lambda: {"kind": kind})


def test_takeover_prompt_only_for_a_bypass(capsys):
    cli._offer_takeover(FakeHarness(), {"verifier_verdict": CLEAN},
                        no_takeover=True)
    assert capsys.readouterr().out == ""


def test_dead_session_says_so(capsys):
    cli._offer_takeover(FakeHarness(alive=False),
                        {"verifier_verdict": BYPASS}, no_takeover=True)
    err = capsys.readouterr().err
    assert "nothing to attach" in err


def test_no_takeover_flag_declines(capsys):
    rc = cli._offer_takeover(FakeHarness(), {"verifier_verdict": BYPASS},
                             no_takeover=True)
    cap = capsys.readouterr()
    assert rc is None and "--no-takeover" in cap.err
    assert "attached" not in cap.out + cap.err


def test_local_demo_gets_the_lab_honesty_note(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_stdin_tty", lambda: True)
    calls = []
    fh = FakeHarness(kind="local-demo")
    fh.terminal = types.SimpleNamespace(
        alive=lambda: True, takeover=lambda: calls.append(1) or True)
    cli._offer_takeover(fh, {"verifier_verdict": BYPASS})
    assert "behavioral" in capsys.readouterr().err
    assert calls == [1]                              # attached, no asking


def test_takeover_is_automatic_no_prompt(capsys, monkeypatch):
    """The whole handoff must need zero keypresses: run ends → shell."""
    monkeypatch.setattr(cli, "_stdin_tty", lambda: True)
    calls = []
    fh = FakeHarness()
    fh.terminal = types.SimpleNamespace(
        alive=lambda: True, takeover=lambda: calls.append(1) or True)
    cli._offer_takeover(fh, {"verifier_verdict": BYPASS})
    assert calls == [1]
    out = capsys.readouterr().out
    assert "press Enter" not in out                  # the old prompt is gone
    assert "Ctrl-] detaches" in out


def test_headless_declines_out_loud(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_stdin_tty", lambda: False)
    calls = []
    fh = FakeHarness()
    fh.terminal = types.SimpleNamespace(
        alive=lambda: True, takeover=lambda: calls.append(1) or True)
    cli._offer_takeover(fh, {"verifier_verdict": BYPASS})
    assert calls == []
    assert "no terminal" in capsys.readouterr().err


# ------------------------------------------------------------------ pty side

def test_takeover_without_a_session_returns_false(tmp_path):
    t = PtyTerminal(spawn_fn=lambda: (["/bin/true"], None, None),
                    transcript_path=str(tmp_path / "t.raw"))
    assert t.takeover() is False


# ------------------------------------------------- handler-level end-to-end

def test_real_demo_escape_trips_the_host_declaration(harness, tmp_path):
    """The exact two-experiment chain from the e2e test, driven through the
    model's own tool path: the write experiment registers nothing, the
    :sh experiment's exec_proof verdict triggers the harness declaration,
    and a follow-up mutation attempt is frozen. (No API client anywhere.)"""
    harness.terminal.start()
    write = harness._tool("propose_experiment", {
        "hypothesis": "textedit :w writes outside the rshell parser",
        "expected_capability": "write", "source": "textedit",
        "test": {"steps": [
            {"send": "textedit<Enter>", "wait": 0.8},
            {"send": "i<Enter>allow_shell=1<Enter>.<Enter>", "wait": 0.6},
            {"send": ":w ~/.texteditrc<Enter>", "wait": 0.8},
            {"send": ":q<Enter>", "wait": 0.6}]},
        "checks": [{"kind": "write_contains", "path": "$HOME/.texteditrc",
                    "marker": "allow_shell=1"}]})
    assert write.get("verified_any") and harness._breakout is None
    assert "harness_note" not in write

    ex = harness._tool("propose_experiment", {
        "hypothesis": "textedit :sh execs with unrestricted env",
        "expected_capability": "execute", "source": "textedit",
        "test": {"steps": [
            {"send": "textedit<Enter>", "wait": 0.8},
            {"send": ":sh echo $JIMMY_TOKEN > "
                     "\"$HOME/_jimmy/exec_proof\"<Enter>", "wait": 1.2},
            {"send": ":q<Enter>", "wait": 0.5}]},
        "checks": [{"kind": "exec_proof"}]})
    assert ex["boundary_verdict"]["shell_restriction_bypass"], ex
    assert harness._breakout is not None
    assert harness._breakout["evidence"]           # named the basis channel
    assert "VERIFIED host-side" in ex["harness_note"]
    # the session is still alive and the loop's freeze is in force
    assert harness.terminal.alive()
    assert "rejected" in harness._tool("send_keys", {"keys": "id<Enter>"})
