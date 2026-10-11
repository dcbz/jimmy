"""Deterministic tests: no API calls. The e2e test drives a full
capability chain through a real PTY and asserts the *verifier* (not the
model) concludes the boundary was crossed."""

import json
import os
import sys

import pytest

from jimmy.capability import CapabilityGraph, Rule
from jimmy.evidence import EvidenceStore
from jimmy.experiment import Check, Experiment, ExperimentRunner, Step
from jimmy.policy import PolicyViolation, ScopePolicy
from jimmy.targets import LocalDemoTarget, NotDisposable
from jimmy.terminal import PtyTerminal, encode_keys


# ---------------------------------------------------------------- key encoding

def test_encode_keys():
    assert encode_keys("id<Enter>") == b"id\r"
    assert encode_keys("<C-c>") == b"\x03"
    assert encode_keys("a\\nb") == b"a\nb"
    assert encode_keys("<Nonsense>") == b"<Nonsense>"


# ---------------------------------------------------------------- graph logic

def test_closure_ignores_tentative(tmp_path):
    g = CapabilityGraph()
    g.add_or_update("textedit", "write", verified=True, evidence_id="ev-1")
    g.rules.append(Rule(
        requires=["write.textedit"], produces=["execute.unrestricted"],
        note="config chain hypothesis", tentative=True))
    assert "write.textedit" in g.closure()
    assert "execute.unrestricted" not in g.closure()   # hypothesis != fact
    assert "execute.unrestricted" in g.all_facts()     # visible as hypothesized
    g.rules[-1].tentative = False
    assert "execute.unrestricted" in g.closure()
    g.save(str(tmp_path / "g.json"))
    g2 = CapabilityGraph(path=str(tmp_path / "g.json"))
    assert "execute.unrestricted" in g2.closure()


# ---------------------------------------------------------------- policy

def test_policy_rejects_host_paths_and_bad_kinds(tmp_path):
    t = LocalDemoTarget(root=str(tmp_path / "jimmy-sandbox-x"))
    p = ScopePolicy()
    exp = Experiment(hypothesis="h", expected_capability="read", source="x",
                     steps=[Step(send="id")],
                     checks=[Check(kind="file_contains", path="/etc/shadow",
                                   marker="x")])
    with pytest.raises(PolicyViolation):
        p.gate_experiment(exp, t)
    exp.checks = [Check(kind="sneaky")]
    with pytest.raises(PolicyViolation):
        p.gate_experiment(exp, t)
    exp.checks = [Check(kind="file_exists", path="$HOME/_jimmy/read_canary")]
    p.gate_experiment(exp, t)  # allowed


def test_policy_rejects_nondisposable_roots():
    with pytest.raises(NotDisposable):
        LocalDemoTarget(root="/")


# ---------------------------------------------------------------- e2e chain

@pytest.mark.skipif(not os.path.exists("/dev/ptmx") and sys.platform != "darwin",
                    reason="no pty")
def test_demo_chain_verified_end_to_end(tmp_path):
    t = LocalDemoTarget(root=str(tmp_path / "jimmy-sandbox-e2e"))
    run = EvidenceStore(str(tmp_path / "run"), meta={"target": t.describe()})
    term = PtyTerminal(spawn_fn=t.spawn, transcript_path=run.transcript_path)
    graph = CapabilityGraph()
    pol = ScopePolicy(max_experiments=10)
    from jimmy.channels import ChannelBroker
    from jimmy.verifier import BoundaryVerifier
    tp = lambda: open(run.transcript_path, errors="replace").read()
    broker = ChannelBroker(t.channels(tp), t, graph)
    ver = BoundaryVerifier(t, broker)
    runner = ExperimentRunner(term, t, pol, run, graph, ver, broker=broker)

    obs = term.start()
    assert "RShell" in obs.screen

    # 0) the boundary holds from inside: cat of outside canary is refused
    held = runner.run(Experiment(
        hypothesis="rshell cat reaches outside_jail_canary",
        expected_capability="read", source="rshell-cat",
        steps=[Step(send="cat ../outside_jail_canary<Enter>", wait=0.6)],
        checks=[Check(kind="outside_canary_read")]))
    assert not held["verified_any"]
    assert not ver.check_containment()

    # 1) write primitive: textedit :w creates a user editor profile
    wr = runner.run(Experiment(
        hypothesis="textedit can write user files outside rshell parser",
        expected_capability="write", source="textedit",
        steps=[Step(send="textedit<Enter>", wait=0.8),
               Step(send="i<Enter>allow_shell=1<Enter>.<Enter>", wait=0.6),
               Step(send=":w ~/.texteditrc<Enter>", wait=0.8),
               Step(send=":q<Enter>", wait=0.6)],
        checks=[Check(kind="write_contains", path="$HOME/.texteditrc",
                      marker="allow_shell=1")]))
    assert wr["verified_all"], wr

    # 2) invocation: textedit honours the user profile -> unrestricted exec
    ex = runner.run(Experiment(
        hypothesis="textedit :sh runs unrestricted commands via user profile",
        expected_capability="execute", source="textedit",
        steps=[Step(send="textedit<Enter>", wait=0.8),
               Step(send=":sh echo $JIMMY_TOKEN > \"$HOME/_jimmy/exec_proof\"<Enter>",
                    wait=1.2),
               Step(send=":q<Enter>", wait=0.5)],
        checks=[Check(kind="exec_proof")]))
    assert ex["verified_any"], ex
    assert ex["boundary_verdict"]["shell_restriction_bypass"]
    assert not ex["boundary_verdict"]["privilege_escalation"]
    # tmux lesson: write.textedit is verified, and on this (traceless)
    # host the exec proof rests on the marker file alone -> the harness
    # must FLAG the forgeability instead of silently accepting the verdict
    assert ex["checks"][0]["basis"], ex
    assert any("file marker alone" in c for c in ex["checks"][0]["caveats"]), \
        ex["checks"][0]
    assert any("file marker alone" in c
               for c in ex["boundary_verdict"]["caveats"])

    # 3) read primitive: editor :r escapes the cat jail -> canary on screen
    rd = runner.run(Experiment(
        hypothesis="textedit :r reads files the rshell jail forbids",
        expected_capability="read", source="textedit",
        steps=[Step(send="textedit<Enter>", wait=0.8),
               Step(send=":r ../outside_jail_canary<Enter>", wait=0.6),
               Step(send="p<Enter>", wait=0.6),
               Step(send=":q<Enter>", wait=0.5)],
        checks=[Check(kind="outside_canary_read")]))
    assert rd["verified_any"], rd
    assert rd["boundary_verdict"]["fs_containment_escape"]

    # graph + log consistency
    assert "execute.textedit" in graph.closure()
    assert "read.textedit" in graph.closure()
    log = [json.loads(l) for l in
           open(os.path.join(run.root, "experiments.jsonl"))]
    assert len(log) == 4
    assert log[0]["verified_capability"] is None      # false lead logged
    term.stop()


# ---------------------------------------------------------------- channels

class FakeTarget:
    name = "fake"
    home = "/home/lab"
    root = "/home/lab"
    _exec_token = "TOK123"
    sentinels = {"exec_proof_path": "/home/lab/_jimmy/exec_proof"}

    def host_exec(self, argv):
        raise AssertionError("model plane must never reach host_exec here")


def test_broker_routes_to_strongest_channel():
    from jimmy.channels import ChannelBroker, FsChannel
    seen = []

    def make(tag, rc_out):
        def fn(argv):
            seen.append(tag)
            return rc_out, "content here", ""
        return fn

    weak = FsChannel(FakeTarget(), id="guest-c", trust="guest",
                     exec_fn=make("guest", 0))
    strong = FsChannel(FakeTarget(), id="ctrl-c", trust="control",
                       exec_fn=make("ctrl", 0))
    b = ChannelBroker([weak, strong], FakeTarget(), CapabilityGraph())
    ev = b.evaluate("file_contains", path="/home/lab/f", marker="content here")
    assert ev.ok
    assert ev.basis == [{"channel": "ctrl-c", "trust": "control"}]
    assert seen[0] == "ctrl"           # strongest consulted first
    chans = {c["channel"] for c in b.status()}
    assert {"guest-c", "ctrl-c"} <= chans


def test_execve_event_parsing():
    from jimmy.channels import execve_paths
    raw = ['1234  execve("/bin/sh", ["/bin/sh"], 0x7fff) = 0',
           '1235  execve("/nope/x", ["/nope/x"], 0x7fff) = -1 ENOENT',
           '1236  --- SIGCHLD {si_signo=17} ---',
           '1237  execve("/usr/bin/id", ["/usr/bin/id"], 0x7fff) = 0']
    kept = [ln for ln in raw if "execve(" in ln and "= -1" not in ln]
    assert execve_paths(kept) == ["/bin/sh", "/usr/bin/id"]


def _proof_broker(graph):
    from jimmy.channels import ChannelBroker, FsChannel
    tgt = FakeTarget()

    def fn(argv):   # marker file contains the token; no trace events exist
        if argv[0] == "cat":
            return 0, "TOK123\n", ""
        return 1, "", "n/a"
    fs = FsChannel(tgt, id="ctrl-fs", trust="control", exec_fn=fn)
    return ChannelBroker([fs], tgt, graph)


def test_exec_proof_caveat_only_when_write_verified():
    g_clean = CapabilityGraph()
    ev = _proof_broker(g_clean).evaluate(
        "exec_proof", events=[],
        snapshot={"marker": "TOK123\n", "procs": ""})
    assert ev.ok and not ev.caveats      # marker-only is fine: no writer known

    g_write = CapabilityGraph()
    g_write.add_or_update("textedit", "write", verified=True, evidence_id="e")
    ev2 = _proof_broker(g_write).evaluate(
        "exec_proof", events=[],
        snapshot={"marker": "TOK123\n", "procs": ""})
    assert ev2.ok                        # verdict stands
    assert any("file marker alone" in c for c in ev2.caveats)  # but flagged


def test_trace_event_clears_the_caveat():
    g = CapabilityGraph()
    g.add_or_update("textedit", "write", verified=True, evidence_id="e")
    b = _proof_broker(g)
    ev = b.evaluate("exec_proof", events=[
        '99 execve("/bin/sh", ["/bin/sh"], 0x0) = 0 '
        '# wrote /home/lab/_jimmy/exec_proof'],
        snapshot={"marker": "TOK123\n", "procs": ""})
    assert ev.ok
    assert not ev.caveats
    assert {"channel": "trace-execve", "trust": "trace"} in ev.basis


def test_trace_channel_unavailable_off_linux(tmp_path):
    from jimmy.channels import TraceChannel
    ch = TraceChannel(lambda: 42)
    ch.out_path = str(tmp_path / "strace.log")
    if sys.platform != "linux":
        assert not ch.available()
        assert ch.arm() is False          # graceful: windows are no-ops
        assert ch.harvest() == []


def test_process_exec_check_via_events():
    from jimmy.channels import ChannelBroker, FsChannel
    tgt = FakeTarget()
    fs = FsChannel(tgt, id="c", trust="control",
                   exec_fn=lambda a: (0, "1 0 root\n2 1000 lab\n", ""))
    b = ChannelBroker([fs], tgt, CapabilityGraph())
    ev = b.evaluate("process_exec", pattern="payload",
                    events=['7 execve("/tmp/payload", []) = 0'],
                    snapshot={"marker": "",
                              "procs": "1 0 root\n7 1000 payload\n"})
    assert ev.ok
    assert {"channel": "trace-execve", "trust": "trace"} in ev.basis
    assert {"channel": "c", "trust": "control"} in ev.basis
