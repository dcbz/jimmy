"""Structured experiments: the deterministic half of hypothesis -> test -> evidence.

The model proposes an Experiment (JSON, per the harness design); the
harness gates it through the scope policy, executes the keystroke steps on
the live PTY session, then evaluates *checks* exclusively through the
lab control plane (target.host_exec / transcript scan) — never through the
model's reading of the output. The result updates the capability graph and
appends a training-data-shaped record to the experiment log.
"""

from __future__ import annotations

import dataclasses
import secrets
import time
from typing import Optional

from .capability import CAPABILITY_CLASSES
from .channels import Evidence


@dataclasses.dataclass
class Step:
    send: str
    wait: float = 1.2
    note: str = ""


@dataclasses.dataclass
class Check:
    kind: str                      # see policy.ALLOWED_CHECK_KINDS
    path: Optional[str] = None     # lab-relative path ($HOME expanded by harness)
    marker: Optional[str] = None   # for file_contains / write_contains
    pattern: Optional[str] = None  # for process_exec (substring of execve/ps lines)
    note: str = ""


@dataclasses.dataclass
class Experiment:
    hypothesis: str
    expected_capability: str       # one of CAPABILITY_CLASSES
    source: str                    # app/command being probed
    steps: list
    checks: list
    expected_observation: str = ""
    reset_first: bool = False
    confidence: float = 0.5

    @classmethod
    def from_json(cls, d: dict) -> "Experiment":
        if d.get("expected_capability") not in CAPABILITY_CLASSES:
            raise ValueError(
                f"expected_capability must be one of {CAPABILITY_CLASSES}")
        test = d.get("test", {})
        steps = [Step(send=s["send"], wait=float(s.get("wait", 1.2)),
                      note=s.get("note", "")) for s in test.get("steps", [])]
        if not steps:
            raise ValueError("experiment needs at least one test step")
        checks = [Check(kind=c["kind"], path=c.get("path"),
                        marker=c.get("marker"), pattern=c.get("pattern"),
                        note=c.get("note", "")) for c in d.get("checks", [])]
        return cls(hypothesis=d["hypothesis"],
                   expected_capability=d["expected_capability"],
                   source=d.get("source", "unknown"),
                   steps=steps, checks=checks,
                   expected_observation=d.get("expected_observation", ""),
                   reset_first=bool(test.get("reset_first", False)),
                   confidence=float(d.get("confidence", 0.5)))


class ExperimentRunner:
    def __init__(self, terminal, target, policy, evidence, graph, verifier,
                 broker=None):
        self.terminal = terminal
        self.target = target
        self.policy = policy
        self.evidence = evidence
        self.graph = graph
        self.verifier = verifier
        self.broker = broker or getattr(verifier, "broker", None)
        self.last_result: Optional[dict] = None

    # -- execution -------------------------------------------------------------

    def run(self, exp: Experiment) -> dict:
        self.policy.gate_experiment(exp, self.target)
        self.policy.spend_experiment()

        state_before = self._state()
        if exp.reset_first:
            self.target.reset()
            self.terminal.stop()
            self.terminal.start()

        before = self.verifier.snapshot()
        # arm the trace channel for the duration of the keystroke window so
        # exec proofs get a basis a pure write primitive cannot forge
        if self.broker:
            self.broker.window_start()
        actions = []
        final_obs = None
        for step in exp.steps:
            obs = self.terminal.send(step.send)
            time.sleep(max(0.0, step.wait))
            obs = self.terminal.read(timeout=0.3)
            actions.append({"send": step.send, "screen_tail":
                            obs.screen.strip().splitlines()[-3:]})
            final_obs = obs
        events = self.broker.window_stop() if self.broker else []
        after = self.verifier.snapshot()

        results = []
        for chk in exp.checks:
            ev = self._check(chk, after, events)
            eid = self.evidence.put(f"check:{chk.kind}", ev.detail,
                                    note=f"{'PASS' if ev.ok else 'FAIL'}: "
                                         f"{chk.note or chk.path or chk.kind}")
            results.append({"kind": chk.kind, "path": chk.path,
                            "marker": chk.marker, "pattern": chk.pattern,
                            "passed": ev.ok, "detail": ev.detail[:400],
                            "basis": ev.basis, "caveats": ev.caveats,
                            "evidence_id": eid})

        verdict = self.verifier.evaluate(before, after, events=events)
        # the full channel roster belongs in verify_boundary /
        # list_channels, not in every experiment payload
        verdict.pop("channels", None)
        passed = [r for r in results if r["passed"]]
        all_checks_pass = bool(results) and len(passed) == len(results)
        any_pass = bool(passed)

        # -- graph update: possible vs verified is decided HERE, not by the model
        ev_ids = [r["evidence_id"] for r in results]
        primary_ev = ev_ids[0] if ev_ids else None
        if any_pass:
            self.graph.add_or_update(
                source=exp.source, capability=exp.expected_capability,
                verified=True, evidence_id=primary_ev, confidence=exp.confidence,
                notes=f"experiment: {exp.hypothesis}")
        else:
            self.graph.add_or_update(
                source=exp.source, capability=exp.expected_capability,
                verified=False, evidence_id=primary_ev,
                confidence=min(exp.confidence, 0.2),
                notes=f"failed experiment: {exp.hypothesis}")
            self.graph.disprove(exp.hypothesis, primary_ev)

        result = {
            "experiment": exp.hypothesis,
            "capability": exp.expected_capability,
            "source": exp.source,
            "checks": results,
            "verified_any": any_pass,
            "verified_all": all_checks_pass,
            "boundary_verdict": verdict,
            "actions": actions,
            "screen_after": (final_obs.screen if final_obs else ""),
            "at_prompt": (final_obs.at_prompt if final_obs else False),
        }
        self.evidence.log_experiment({
            "id": f"exp-{self.policy.experiments_used:04d}",
            "initial_state": state_before,
            "hypothesis": exp.hypothesis,
            "expected_capability": exp.expected_capability,
            "source": exp.source,
            "action": actions,
            "observation": {"checks": results, "verdict": verdict},
            "verified_capability": (exp.expected_capability + "." + exp.source)
                                   if any_pass else None,
            "next_state": self._state(),
            "confidence": exp.confidence,
        })
        self.graph.add_event({
            "hypothesis": exp.hypothesis,
            "capability": f"{exp.expected_capability}.{exp.source}",
            "outcome": "verified" if any_pass else "disproven",
            "evidence": ev_ids,
        })
        self.graph.save()
        self.last_result = result
        return result

    # -- checks ------------------------------------------------------------
    # Every check is routed through the ChannelBroker, which picks the
    # strongest available channel for the kind and records the basis.
    # Session text is trusted only for sentinel-token appearance (a READ
    # primitive) — never for anything else.

    def _check(self, chk: Check, after, events=None):
        path = self._lab_path(chk.path) if chk.path else None
        if self.broker is None:  # defensive: no channels wired
            return Evidence(False, "no channel broker configured", [])
        return self.broker.evaluate(chk.kind, path=path, marker=chk.marker,
                                    pattern=chk.pattern, events=events,
                                    snapshot=after)

    def _lab_path(self, p: str) -> str:
        if p.startswith("$HOME"):
            p = self.target.home + p[5:]
        elif p.startswith("~"):
            p = self.target.home + p[1:]
        return p

    def _state(self) -> dict:
        return {"verified_facts": sorted(self.graph.closure()),
                "experiments_used": self.policy.experiments_used}


def gen_marker(prefix: str = "jimmy") -> str:
    """A random marker the model can put into files; harness finds it."""
    return f"{prefix}-{secrets.token_hex(6)}"
