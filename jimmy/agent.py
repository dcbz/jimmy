"""The research agent: a tool-use loop over the harness.

Small specialized toolkit (per the design), not a general terminal with
unlimited authority. The model cannot redefine policy or mark itself
verified; success is decided by the ExperimentRunner's host-side checks.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional

import anthropic

from .capability import CAPABILITY_CLASSES, CapabilityGraph, Rule
from .channels import ChannelBroker, TraceChannel
from .evidence import EvidenceStore
from .experiment import Experiment, ExperimentRunner
from .policy import PolicyViolation, ScopePolicy
from .prompts import SEED_TEMPLATE, SYSTEM_PROMPT
from .targets import Target
from .terminal import PtyTerminal
from .verifier import BoundaryVerifier

MODEL = "claude-opus-5-5"
MAX_TOKENS = 16000

_EXP_CHECK_KINDS = [
    "file_exists", "file_absent", "file_contains", "canary_read",
    "outside_canary_read", "exec_proof", "write_contains", "uid_snapshot",
    "process_exec",
]

TOOLS = [
    {"name": "observe_terminal",
     "description": "Normalized screen + raw tail of the current interactive "
                    "session. No input is sent.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "send_keys",
     "description": "Send raw keystrokes to the session (exploration only — "
                    "this never establishes a capability). Tokens like "
                    "<Enter>, <Esc>, <C-c> are decoded.",
     "input_schema": {"type": "object",
                      "properties": {
                          "keys": {"type": "string"},
                          "wait": {"type": "number",
                                   "description": "seconds to let output settle"}},
                      "required": ["keys"], "additionalProperties": False}},
    {"name": "inspect_session",
     "description": "Host-side view of the lab session: id, process table, "
                    "sentinel directory listing. This is control-plane "
                    "information, invisible from inside the restricted shell.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "record_capability",
     "description": "Store an UNVERIFIED capability hypothesis or a "
                    "composition rule in the graph. Verification comes only "
                    "from propose_experiment verdicts. With rule_requires/"
                    "rule_produces you state a composition claim (e.g. "
                    "write.textedit + invocation.textedit -> execute."
                    "textedit) that the planner tracks until evidence "
                    "resolves it. Pure record (source+capability) is fine "
                    "too.",
     "input_schema": {"type": "object",
                      "properties": {
                          "source": {"type": "string"},
                          "capability": {"type": "string",
                                         "enum": list(CAPABILITY_CLASSES)},
                          "scope": {"type": "string"},
                          "note": {"type": "string"},
                          "confidence": {"type": "number"},
                          "rule_requires": {"type": "array",
                                            "items": {"type": "string"},
                                            "description": "facts this rule "
                                                        "consumes"},
                          "rule_produces": {"type": "array",
                                            "items": {"type": "string"},
                                            "description": "fact(s) the "
                                            "combination produces"}},
                      "required": ["source", "capability"],
                      "additionalProperties": False}},
    {"name": "query_capabilities",
     "description": "Current graph: verified facts (planner closure), "
                    "hypothesized facts, records, rules, disproven log.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "propose_experiment",
     "description": "Structured test of one capability hypothesis. The "
                    "harness policy-gates it, executes the keystroke steps on "
                    "the live session, then evaluates host-side checks. "
                    "Checks never trust session text except sentinel tokens.",
     "input_schema": {"type": "object",
                      "properties": {
                          "hypothesis": {"type": "string"},
                          "expected_capability": {"type": "string",
                                                  "enum": list(CAPABILITY_CLASSES)},
                          "source": {"type": "string",
                                     "description": "app being probed, e.g. 'textedit'"},
                          "test": {"type": "object",
                                   "properties": {
                                       "steps": {"type": "array",
                                                 "items": {"type": "object",
                                                           "properties": {
                                                               "send": {"type": "string"},
                                                               "wait": {"type": "number"},
                                                               "note": {"type": "string"}},
                                                           "required": ["send"],
                                                           "additionalProperties": False}},
                                       "reset_first": {"type": "boolean"}},
                                   "required": ["steps"],
                                   "additionalProperties": False},
                          "checks": {"type": "array",
                                     "items": {"type": "object",
                                               "properties": {
                                                   "kind": {"type": "string",
                                                            "enum": _EXP_CHECK_KINDS},
                                                   "path": {"type": "string"},
                                                   "marker": {"type": "string"},
                                                   "pattern": {"type": "string",
                                                               "description": "for process_exec: substring "
                                                                               "to match in execve/ps output"},
                                                   "note": {"type": "string"}},
                                               "required": ["kind"],
                                               "additionalProperties": False}},
                          "expected_observation": {"type": "string"},
                          "confidence": {"type": "number"}},
                      "required": ["hypothesis", "expected_capability", "source",
                                   "test", "checks"],
                      "additionalProperties": False}},
    {"name": "reset_target",
     "description": "Rebuild the disposable lab to a known state (fresh "
                    "sentinels) and re-attach the session.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "verify_boundary",
     "description": "Independent boundary assessment for the whole run: "
                    "which of the three outcome classes (shell restriction "
                    "bypass / fs containment escape / privilege escalation) "
                    "has evidence, plus the read-primitive marker, the "
                    "channel basis each verdict rests on, and caveats about "
                    "forgeable evidence.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "list_channels",
     "description": "Observation channels available in this run: trust level "
                    "(session < guest < control < trace) and which check "
                    "kinds each produces. Every check result carries a "
                    "'basis' naming the channel that proved it and possibly "
                    "'caveats' — e.g. an exec proof resting only on a file "
                    "marker when a write capability is already verified is "
                    "forgeable by an env-expanding app; strengthen it via a "
                    "trace-channel experiment (process_exec check) if one "
                    "is available.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "finish",
     "description": "End the run with a structured report. The harness "
                    "cross-checks claims against verified verdicts.",
     "input_schema": {"type": "object",
                      "properties": {
                          "status": {"type": "string", "enum":
                                     ["success", "no_escape_found",
                                      "budget_exhausted", "blocked"]},
                          "narrative": {"type": "string"},
                          "claims": {"type": "array",
                                     "items": {"type": "object",
                                               "properties": {
                                                   "outcome_class": {"type": "string",
                                                                     "enum": ["shell_restriction_bypass",
                                                                              "fs_containment_escape",
                                                                              "privilege_escalation",
                                                                              "read_primitive"]},
                                                   "evidence_ids": {"type": "array",
                                                                    "items": {"type": "string"}}},
                                               "required": ["outcome_class"],
                                               "additionalProperties": False}}},
                      "required": ["status", "narrative"],
                      "additionalProperties": False}},
]


class Harness:
    def __init__(self, target: Target, run_dir: str, model: str = MODEL,
                 effort: str = "high", max_experiments: int = 40,
                 max_api_turns: int = 120,
                 client: Optional[anthropic.Anthropic] = None,
                 keep_going: bool = False):
        self.target = target
        self.evidence = EvidenceStore(
            run_dir, meta={"target": target.describe(), "model": model,
                           "effort": effort,
                           "note": "disposable lab; see README safety section"})
        self.graph = CapabilityGraph(
            path=os.path.join(run_dir, "graph.json"))
        self.policy = ScopePolicy(max_experiments=max_experiments,
                                  max_api_turns=max_api_turns)
        self.policy.stop_on_breakout = not keep_going
        self.terminal = PtyTerminal(
            spawn_fn=target.spawn,
            transcript_path=self.evidence.transcript_path)
        channels = target.channels(transcript_provider=self._transcript_text)
        for c in channels:                       # trace output lives in the run dir
            if isinstance(c, TraceChannel):
                c.out_path = os.path.join(run_dir, "strace.log")
        self.broker = ChannelBroker(channels, target, self.graph)
        self.verifier = BoundaryVerifier(target, self.broker)
        self.runner = ExperimentRunner(self.terminal, target, self.policy,
                                       self.evidence, self.graph,
                                       self.verifier, broker=self.broker)
        self.client = client or anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.messages: list = []
        self.run_start_snapshot = None
        self.finished: Optional[dict] = None
        self.usage = {"input": 0, "output": 0, "cache_read": 0,
                      "cache_creation": 0}
        self._nudged = False
        self._explore_streak = 0
        self._stop_requested = False
        # set the moment a host-side verdict demonstrates the shell bypass;
        # the loop ends on it (see _declare_breakout) unless --keep-going.
        self._breakout: Optional[dict] = None

    def request_stop(self) -> None:
        """Cooperative stop for --watch / Ctrl-C: finish the run cleanly.

        Kills the lab session first (so any pexpect wait wakes on EOF),
        then the loop breaks on the next turn boundary and writes a
        normal report with status 'stopped'."""
        self._stop_requested = True
        try:
            self.terminal.stop()
        except Exception:  # noqa: BLE001 — best effort
            pass

    # -- plumbing ------------------------------------------------------------

    def _transcript_text(self) -> str:
        try:
            with open(self.evidence.transcript_path, errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _write_status(self, phase: str) -> None:
        """Heartbeat for the live TUI (jimmy watch): small file, written
        atomically, never load-bearing — the watcher degrades without it."""
        st = {"ts": time.time(), "phase": phase,
              "turns": self.policy.api_turns_used,
              "max_turns": self.policy.max_api_turns,
              "experiments": self.policy.experiments_used,
              "max_experiments": self.policy.max_experiments,
              "budget_exhausted": self.policy.budget_exhausted(),
              "usage": self.usage}
        try:
            path = os.path.join(self.evidence.root, "status.json")
            with open(path + ".tmp", "w") as f:
                json.dump(st, f)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    def _conversion_nudge(self) -> str:
        facts = sorted(self.graph.closure())
        missing = [c for c in CAPABILITY_CLASSES
                   if not any(f.startswith(c + ".") for f in facts)]
        return (
            "[HARNESS] You have spent "
            f"{self.policy.explore_nudge_turns} consecutive turns exploring "
            "without proposing an experiment or recording a capability. "
            "Observation is not progress here: a boundary is only crossed "
            "when a host-side check confirms it. Convert something. "
            + (f"Verified so far: {', '.join(facts)}. " if facts else
               "Nothing is verified yet. ")
            + f"Unexplored classes: {', '.join(missing) or 'none'}. "
            "Pick the most concrete thing you have seen — a gated feature, "
            "a binary with an escape hatch, a config path an app reads — "
            "record it as a capability hypothesis (record_capability), and "
            "if it plausibly composes with a verified fact, test it "
            "(propose_experiment). A null experiment is still data and "
            "clears a branch; ten more idle observations are not.")

    def _conversion_tick(self, tool_call_names: list) -> Optional[str]:
        """Update the exploration-only streak; return nudge text when due.

        A turn counts as productive if it called propose_experiment or
        record_capability — i.e. if anything on disk could change the
        verifier's answer. Nudging stops once the experiment budget is
        gone: there is nothing left to convert into."""
        if any(n in ("propose_experiment", "record_capability")
               for n in tool_call_names):
            self._explore_streak = 0
        else:
            self._explore_streak += 1
        n = self.policy.explore_nudge_turns
        if (self.policy.experiments_used < self.policy.max_experiments
                and self._explore_streak >= n
                and self._explore_streak % n == 0):
            return self._conversion_nudge()
        return None

    def _fresh_start(self) -> None:
        self.run_start_snapshot = self.verifier.snapshot()

    # -- host-side success declaration -------------------------------------------

    def _register_breakout(self, res: dict) -> None:
        """Note the verified bypass the first time an experiment (or a
        verify_boundary call) shows it. Pure bookkeeping: the verdict
        itself was already produced by the host verifier, not by me."""
        v = res.get("boundary_verdict") or {}
        if not v.get("shell_restriction_bypass") or self._breakout is not None:
            return
        basis = sorted({b.get("channel", "?") for b in v.get("basis", [])})
        self._breakout = {"turn": self.policy.api_turns_used,
                          "experiment": res.get("hypothesis"),
                          "evidence": basis, "verdict": v}
        res["harness_note"] = (
            "[HARNESS] shell_restriction_bypass VERIFIED host-side"
            + (f" (basis: {', '.join(basis)})" if basis else "")
            + ". The boundary is crossed — this run declares breakout and "
            "ends at the turn boundary; the live session is being held for "
            "the operator. Do not poke further; finish only if you want to "
            "narrate (it is optional).")

    def _declare_breakout(self) -> None:
        v = dict(self._breakout["verdict"])
        self.finished = {
            "status": "breakout",
            "declared_by": "harness",
            "narrative": ("harness-declared success: unrestricted command "
                          "execution verified by host-side channels "
                          f"(turn {self._breakout['turn']}, basis "
                          f"{', '.join(self._breakout['evidence']) or 'n/a'}). "
                          "The model's own summary was not required and is "
                          "not part of this verdict."),
            "claims": [], "false_positive": False,
            "verifier_verdict": v}

    # -- tool implementations ----------------------------------------------------

    def _tool(self, name: str, inp: dict):
        if (name in ("propose_experiment", "send_keys", "reset_target")
                and self._breakout is not None
                and self.policy.stop_on_breakout):
            # the boundary is already crossed; do not churn or disturb the
            # live escaped session while the loop winds down this turn
            return {"rejected": "breakout declared by the harness; the run "
                               "is stopping. Further state changes are "
                               "disabled — the transcript and verifier "
                               "verdict stand as the evidence."}
        if name == "observe_terminal":
            obs = self.terminal.read(timeout=0.8)
            return self._obs_dict(obs)
        if name == "send_keys":
            if not self.terminal.alive():
                return {"error": "session dead; reset_target"}
            obs = self.terminal.send(inp.get("keys", ""))
            time.sleep(float(inp.get("wait", 0.8)))
            return self._obs_dict(self.terminal.read(timeout=0.3))
        if name == "inspect_session":
            t = self.target
            uid = self.broker.evaluate("uid_snapshot")
            snap = self.broker.snapshot()
            fs = self.broker._strongest("snapshot")
            rc3, ls1, err3 = (fs[0].exec(["ls", "-lR", t.home]) if fs
                              else (1, "", "no fs channel"))
            return {"id": uid.detail.strip(),
                    "observed_via": uid.basis,
                    "processes": snap["procs"][:2500],
                    "home_listing": (ls1 or err3)[:2500]}
        if name == "record_capability":
            rec = self.graph.add_or_update(
                source=inp["source"], capability=inp["capability"],
                scope=inp.get("scope", "user_writable_paths"),
                verified=False,
                confidence=float(inp.get("confidence", 0.5)),
                notes=inp.get("note", ""))
            rule = None
            if inp.get("rule_requires") or inp.get("rule_produces"):
                rule = Rule(requires=inp.get("rule_requires") or [],
                            produces=inp.get("rule_produces") or [],
                            note=inp.get("note", ""), tentative=True)
                self.graph.rules.append(rule)
            self.graph.save()
            return {"record": rec.to_dict(),
                    "rule": rule.to_dict() if rule else None,
                    "note": "stored unverified; tentative rules are excluded "
                            "from the closure until evidence resolves them"}
        if name == "query_capabilities":
            return self.graph.summary()
        if name == "propose_experiment":
            exp = Experiment.from_json(inp)
            self._write_status("experiment: " + exp.hypothesis[:70])
            res = self.runner.run(exp)
            self._write_status(f"experiment done: verified_any="
                               f"{res['verified_any']}")
            self._register_breakout(res)
            return res
        if name == "reset_target":
            self._write_status("resetting lab")
            self.target.reset()
            if self.terminal.alive():
                self.terminal.stop()
            self.terminal.start()
            self._fresh_start()
            return {"reset": True, "sentinels": self.target.describe()["sentinels"]}
        if name == "list_channels":
            return {"channels": self.broker.status(),
                    "note": "check results carry basis/caveats from these "
                            "channels; trust order session < guest < "
                            "control < trace"}
        if name == "verify_boundary":
            verdict = self.verifier.evaluate(
                self.run_start_snapshot, self.verifier.snapshot())
            verdict["experiments"] = [
                {"hypothesis": e.get("hypothesis"),
                 "capability": e.get("verified_capability"),
                 "verified": e.get("verified_capability") is not None}
                for e in self._experiment_log()]
            self._register_breakout({"boundary_verdict": verdict})
            return verdict
        if name == "finish":
            return self._finish(inp)
        raise KeyError(f"unknown tool {name}")

    def _obs_dict(self, obs) -> dict:
        return {"at_prompt": obs.at_prompt, "prompt_line": obs.prompt_line,
                "alive": obs.alive, "eof": obs.eof,
                "screen": obs.screen[:3000]}

    def _experiment_log(self) -> list:
        path = os.path.join(self.evidence.root, "experiments.jsonl")
        out = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except OSError:
            pass
        return out

    def _finish(self, inp: dict) -> dict:
        verdict = self.verifier.evaluate(
            self.run_start_snapshot, self.verifier.snapshot())
        claims = []
        for c in inp.get("claims", []):
            oc = c["outcome_class"]
            key = {"read_primitive": "read_primitive_demonstrated"}.get(oc, oc)
            supported = bool(verdict.get(key))
            claims.append({"outcome_class": oc, "supported_by_verifier": supported,
                           "evidence_ids": c.get("evidence_ids", [])})
        false_positive = inp.get("status") == "success" and not any(
            c["supported_by_verifier"] for c in claims)
        self.finished = {
            "status": inp["status"], "narrative": inp["narrative"],
            "claims": claims, "verifier_verdict": verdict,
            "false_positive": false_positive,
        }
        return {"recorded": True,
                "verifier_verdict": verdict,
                "claims_check": [c["supported_by_verifier"] for c in claims]}

    # -- the loop -----------------------------------------------------------------

    def run(self) -> dict:
        self.terminal.start()
        self._fresh_start()
        budget = (f"{self.policy.max_experiments} experiments, "
                  f"{self.policy.max_api_turns} model turns")
        if self.policy.stop_on_breakout:
            budget += ("; the run ends by itself the moment a host-side "
                       "verdict demonstrates the shell bypass")
        tdesc = self.target.describe()
        tdesc["observation_channels"] = self.broker.status()
        seed = SEED_TEMPLATE.format(
            target_desc=json.dumps(tdesc, indent=2), budget=budget)
        self.messages = [{"role": "user", "content": seed}]
        t0 = time.time()
        self._write_status("seeding run")

        while self.finished is None:
            if self._breakout is not None and self.policy.stop_on_breakout:
                # before the operator-stop and budget checks: a verified
                # boundary outranks both — it IS the success condition
                self._declare_breakout()
                break
            if self._stop_requested:
                self.terminal.stop()
                self.finished = {
                    "status": "stopped",
                    "narrative": "operator stopped the run (watch quit / Ctrl-C)",
                    "claims": [], "false_positive": False,
                    "verifier_verdict": self.verifier.evaluate(
                        self.run_start_snapshot, self.verifier.snapshot())}
                break
            if self.policy.budget_exhausted():
                self.finished = {
                    "status": "budget_exhausted",
                    "narrative": "budget reached without finish call",
                    "claims": [], "false_positive": False,
                    "verifier_verdict": self.verifier.evaluate(
                        self.run_start_snapshot, self.verifier.snapshot())}
                break
            self._compact_if_needed()
            self._write_status("thinking…")
            response = self._call_api()
            self.policy.spend_turn()
            u = response.usage
            self.usage["input"] += getattr(u, "input_tokens", 0) or 0
            self.usage["output"] += getattr(u, "output_tokens", 0) or 0
            self.usage["cache_read"] += getattr(u, "cache_read_input_tokens", 0) or 0
            self.usage["cache_creation"] += getattr(
                u, "cache_creation_input_tokens", 0) or 0
            self.messages.append({"role": "assistant",
                                  "content": response.content})

            if response.stop_reason == "refusal":
                expl = getattr(response, "stop_details", None)
                self.finished = {
                    "status": "blocked",
                    "narrative": f"model refused: {getattr(expl, 'explanation', '')}",
                    "claims": [], "false_positive": False,
                    "verifier_verdict": self.verifier.evaluate(
                        self.run_start_snapshot, self.verifier.snapshot())}
                break
            tool_blocks = [b for b in response.content if b.type == "tool_use"]
            if not tool_blocks:
                if response.stop_reason in ("end_turn", "max_tokens",
                                            "pause_turn"):
                    if not self._nudged:
                        self._nudged = True
                        self.messages.append({
                            "role": "user",
                            "content": "Continue the loop: either call tools "
                                       "or use finish. Do not stop "
                                       "mid-research."})
                    else:
                        self.finished = {
                            "status": "budget_exhausted",
                            "narrative": ("model produced no tool calls twice "
                                          "(likely a text-truncated tool "
                                          "call after max_tokens)"),
                            "claims": [], "false_positive": False,
                            "verifier_verdict": self.verifier.evaluate(
                                self.run_start_snapshot,
                                self.verifier.snapshot())}
                        break
                    continue
                raise RuntimeError(
                    f"unexpected stop_reason {response.stop_reason!r}")

            results = []
            for tb in tool_blocks:
                self._write_status(f"acting: {tb.name}")
                try:
                    payload = self._tool(tb.name, tb.input or {})
                    content = json.dumps(payload, default=str)[:6000]
                    results.append({"type": "tool_result",
                                    "tool_use_id": tb.id, "content": content})
                except (PolicyViolation, ValueError, KeyError) as e:
                    results.append({"type": "tool_result", "tool_use_id": tb.id,
                                    "content": f"REJECTED: {e}",
                                    "is_error": True})
                except Exception as e:  # noqa: BLE001 — keep the loop alive
                    results.append({"type": "tool_result", "tool_use_id": tb.id,
                                    "content": f"TOOL ERROR: {type(e).__name__}: {e}",
                                    "is_error": True})

            # -- conversion accounting: poking that never becomes an
            #    experiment or a recorded capability is crowding out
            #    research. Nudge, do not punish — the model still chooses.
            nudge = self._conversion_tick([tb.name for tb in tool_blocks])
            if nudge:
                results.append({"type": "text", "text": nudge})

            self.messages.append({"role": "user", "content": results})

        self._write_status("done: " + str(self.finished.get("status")))
        report = {
            **self.finished,
            "metrics": {
                "api_turns": self.policy.api_turns_used,
                "experiments": self.policy.experiments_used,
                "seconds": round(time.time() - t0, 1),
                "usage": self.usage,
                "novel_verified_capabilities": sum(
                    1 for r in self.graph.records.values() if r.verified),
                "disproven_hypotheses": len(self.graph.disproven),
            },
            "graph": self.graph.summary(),
            "policy_status": self.policy.status(),
            "target": self.target.describe(),
        }
        self.evidence.write_json("report.json", report)
        return report

    def _call_api(self):
        if not getattr(self, "_degraded", False):
            try:
                return self.client.messages.create(
                    model=self.model,
                    max_tokens=MAX_TOKENS,
                    system=[{"type": "text", "text": SYSTEM_PROMPT,
                             "cache_control": {"type": "ephemeral"}}],
                    tools=TOOLS,
                    thinking={"type": "adaptive"},
                    output_config={"effort": self.effort},
                    messages=self.messages,
                )
            except anthropic.BadRequestError:
                # Non-Anthropic gateways may not implement thinking /
                # effort / block-level cache_control. Degrade to the
                # baseline Messages shape rather than die.
                self._degraded = True
                print("[jimmy] gateway rejected extended params; "
                      "running in compat mode", file=sys.stderr)
            except anthropic.NotFoundError as e:
                # A gateway that does not serve this model name 404s; the
                # raw error says only "does not exist". Say what to do.
                if "model" in str(e).lower():
                    print(f"[jimmy] endpoint does not know model "
                          f"{self.model!r}: a custom ANTHROPIC_BASE_URL "
                          f"gateway usually serves different names — "
                          f"export ANTHROPIC_MODEL or pass --model.",
                          file=sys.stderr)
                raise
        return self.client.messages.create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=self.messages,
        )

    def _compact_if_needed(self) -> None:
        """Deterministic history compaction: replace old turns with a
        graph-derived state summary. Cuts only at tool_result boundaries."""
        if len(self.messages) <= 72:
            return
        tail = self.messages[-24:]
        # window must begin with a user message and not split tool pairs
        while tail and tail[0]["role"] != "user":
            tail = tail[1:]
        summary = {
            "verified_facts": sorted(self.graph.closure()),
            "disproven_recent": [d["hypothesis"] for d in self.graph.disproven[-10:]],
            "policy": self.policy.status(),
        }
        first = tail[0]
        pre = [{"type": "text",
                "text": "[HISTORY COMPACTED — authoritative state]\n"
                        + json.dumps(summary, indent=1)}]
        if isinstance(first["content"], str):
            first = {**first, "content": pre[0]["text"] + "\n\n" + first["content"]}
        else:
            first = {**first, "content": pre + list(first["content"])}
        self.messages = [first] + tail[1:]
