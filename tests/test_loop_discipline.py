"""Loop discipline tests (no API calls): the conversion-accounting nudge
and composition-rule support in record_capability.

Background: in a live run the model poked the session for 30+ turns and
never converted a single observation into an experiment or a recorded
capability — free exploration crowded out research. The harness now
keeps the streak and interrupts (text block alongside the tool_results,
not a fake user turn) when it runs long.
"""

import os

import pytest

from jimmy.agent import Harness
from jimmy.targets import LocalDemoTarget


@pytest.fixture
def harness(tmp_path):
    # basename must scream disposable (LocalDemoTarget's safety check)
    t = LocalDemoTarget(root=str(tmp_path / "jimmy-discipline-lab"))
    run = tmp_path / "run"
    run.mkdir()
    return Harness(t, str(run), client=object())  # client never touched


# ------------------------------------------------------ conversion streak

def test_nudge_fires_after_threshold_of_idle_turns(harness):
    h = harness
    n = h.policy.explore_nudge_turns
    for _ in range(n - 1):
        assert h._conversion_tick(["observe_terminal"]) is None
    text = h._conversion_tick(["observe_terminal"])
    assert text and "[HARNESS]" in text
    assert h._explore_streak == n


def test_productive_turn_resets_streak(harness):
    h = harness
    n = h.policy.explore_nudge_turns
    for _ in range(n - 1):
        h._conversion_tick(["send_keys"])
    assert h._conversion_tick(["record_capability"]) is None
    assert h._explore_streak == 0
    # a full threshold of idling is needed again
    for _ in range(n - 1):
        assert h._conversion_tick(["observe_terminal"]) is None
    assert h._conversion_tick(["observe_terminal"]) is not None


def test_nudge_repeats_only_at_multiples(harness):
    h = harness
    n = h.policy.explore_nudge_turns
    fired = [h._conversion_tick(["observe_terminal"]) is not None
             for _ in range(2 * n)]
    assert fired == [(i + 1) % n == 0 for i in range(2 * n)]


def test_experiment_proposal_counts_as_productive(harness):
    h = harness
    for _ in range(h.policy.explore_nudge_turns - 1):
        h._conversion_tick(["send_keys"])
    assert h._conversion_tick(["propose_experiment"]) is None
    assert h._explore_streak == 0


def test_no_nudge_when_experiment_budget_is_gone(harness):
    h = harness
    h.policy.experiments_used = h.policy.max_experiments
    for _ in range(h.policy.explore_nudge_turns * 2):
        assert h._conversion_tick(["observe_terminal"]) is None


def test_nudge_text_reflects_graph_state(harness):
    h = harness
    h.graph.add_or_update("textedit", "read", verified=True, evidence_id="ev-1")
    text = h._conversion_nudge()
    assert "read.textedit" in text                 # what is proven
    assert "write" in text                          # what is still unexplored
    assert "read," not in text.split("Unexplored classes:")[1]


# ------------------------------------------------ record_capability rules

def test_record_capability_stores_composition_rule(harness):
    h = harness
    res = h._tool("record_capability", {
        "source": "textedit", "capability": "execute",
        "rule_requires": ["write.textedit"],
        "rule_produces": ["execute.unrestricted"],
        "note": ":sh gate reads ~/.texteditrc"})
    assert res["rule"] and res["rule"]["tentative"] is True
    assert "execute.unrestricted" not in h.graph.closure()
    assert "execute.unrestricted" not in h.graph.all_facts()  # requires unmet

    # evidence for the requirement lifts it into the hypothesized view,
    # never the planner closure, until the rule itself is demonstrated
    h.graph.add_or_update("textedit", "write", verified=True,
                          evidence_id="ev-2")
    assert "execute.unrestricted" in h.graph.all_facts()
    assert "execute.unrestricted" not in h.graph.closure()

    # persisted: the graph file carries the rule across a reload
    g2 = type(h.graph)(path=os.path.join(h.evidence.root, "graph.json"))
    assert g2.rules and g2.rules[0].produces == ["execute.unrestricted"]


def test_record_capability_plain_still_works(harness):
    res = harness._tool("record_capability", {
        "source": "textedit", "capability": "write",
        "note": "editor write primitive"})
    assert res["rule"] is None
    assert "note" in res and "unverified" in res["note"]


# ------------------------------------------------------- cooperative stop
# (`jimmy run --watch`: quitting the TUI must stop the run thread
# cleanly, not orphan the lab session.)

def test_request_stop_writes_a_clean_report(harness):
    h = harness
    h._stop_requested = True          # as if q was pressed before turn one
    rep = h.run()                     # real demo PTY; API client untouched
    assert rep["status"] == "stopped"
    assert os.path.exists(os.path.join(h.evidence.root, "report.json"))
    assert not h.terminal.alive()


def test_request_stop_is_safe_before_start(harness):
    harness.request_stop()            # terminal never started yet
    assert harness._stop_requested is True
