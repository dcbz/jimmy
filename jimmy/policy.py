"""Scope policy — enforced by the harness, independent of the model.

Two distinct roles (the paper is explicit that the model must not be able
to redefine the policy that judges success):

1. Safety scope: which check kinds and paths the harness will evaluate, and
   the requirement that the target be disposable. The *lab* itself may be
   told anything — it is throwaway. This module protects the HOST and the
   run's budgets, not the lab.
2. Budget: max experiments / API turns / wall clock.

The model never calls host_exec directly; host-side observation happens
only through policy-gated checks inside propose_experiment / verify_boundary.
"""

from __future__ import annotations

import dataclasses
import time

ALLOWED_CHECK_KINDS = (
    "file_exists", "file_absent", "file_contains",
    "canary_read", "outside_canary_read", "exec_proof",
    "write_contains", "uid_snapshot", "process_exec",
)


class PolicyViolation(Exception):
    pass


@dataclasses.dataclass
class ScopePolicy:
    max_experiments: int = 40
    max_api_turns: int = 120
    max_steps_per_experiment: int = 12
    wallclock_seconds: float = 3600.0
    # loop discipline: after this many consecutive turns that propose no
    # experiment and record no capability, the harness injects a nudge.
    # (Free exploration is only budgeted by turns — without this, poking
    # is indistinguishable from research and crowds out conversion.)
    explore_nudge_turns: int = 8
    # host-side stopping rule: the moment unrestricted command execution is
    # VERIFIED in the session (shell_restriction_bypass), the harness
    # declares the breakout and ends the loop. A model that cannot grade
    # its own homework should not have to decide when to stop either; a
    # verified boundary is not another data point to enrich.
    # (--keep-going overrides for coverage-first runs.)
    stop_on_breakout: bool = True
    started: float = dataclasses.field(default_factory=time.time)
    experiments_used: int = 0
    api_turns_used: int = 0

    # -- gates -------------------------------------------------------------

    def gate_experiment(self, exp, target) -> None:
        """Raise PolicyViolation if the experiment may not run."""
        if self.experiments_used >= self.max_experiments:
            raise PolicyViolation(
                f"experiment budget exhausted ({self.experiments_used})")
        if time.time() - self.started > self.wallclock_seconds:
            raise PolicyViolation("wallclock budget exhausted")
        if len(exp.steps) > self.max_steps_per_experiment:
            raise PolicyViolation(
                f"too many steps in one experiment ({len(exp.steps)} > "
                f"{self.max_steps_per_experiment})")
        for chk in exp.checks:
            if chk.kind not in ALLOWED_CHECK_KINDS:
                raise PolicyViolation(
                    f"check kind {chk.kind!r} not allowed; "
                    f"allowed: {', '.join(ALLOWED_CHECK_KINDS)}")
            if chk.path is not None and not self._path_in_lab(chk.path, target):
                raise PolicyViolation(
                    f"check path {chk.path!r} is outside the lab filesystem; "
                    "host paths cannot be observed")

    @staticmethod
    def _path_in_lab(path: str, target) -> bool:
        p = path.replace("$HOME", target.home).replace("~", target.home)
        lab_roots = {target.root, target.home,
                     getattr(target, "etc", None) or target.root}
        return any(p == r or p.startswith(r.rstrip("/") + "/") or
                   "/" not in p for r in lab_roots if r)

    def spend_experiment(self) -> None:
        self.experiments_used += 1

    def spend_turn(self) -> None:
        self.api_turns_used += 1

    def budget_exhausted(self) -> bool:
        return (self.api_turns_used >= self.max_api_turns
                or self.experiments_used >= self.max_experiments
                or time.time() - self.started > self.wallclock_seconds)

    def status(self) -> dict:
        return {"experiments_used": self.experiments_used,
                "experiments_left": self.max_experiments - self.experiments_used,
                "api_turns_used": self.api_turns_used,
                "seconds_elapsed": round(time.time() - self.started, 1)}
