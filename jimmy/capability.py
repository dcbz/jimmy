"""Capability graph: the system's memory of what has been *demonstrated*.

Design principle from the paper: breakouts are compositions of legitimate
capabilities, so the unit of memory is a capability record, not a command
recipe. Possible != verified — an unverified record is an LLM guess; only
records with evidence_id set (backed by an executed experiment) feed the
deterministic planner.

Six capability classes:
    read, write, execute, environment, invocation, persistence
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
import uuid
from typing import Optional

CAPABILITY_CLASSES = (
    "read", "write", "execute", "environment", "invocation", "persistence",
)


def _now() -> float:
    return time.time()


@dataclasses.dataclass
class CapabilityRecord:
    source: str                       # app/command the capability belongs to, e.g. "textedit"
    capability: str                   # one of CAPABILITY_CLASSES
    scope: str = "user_writable_paths"
    requirements: list = dataclasses.field(default_factory=list)  # fact names
    verified: bool = False
    evidence_id: Optional[str] = None
    confidence: float = 0.5
    notes: str = ""
    id: str = dataclasses.field(default_factory=lambda: "cap-" + uuid.uuid4().hex[:8])
    created_at: float = dataclasses.field(default_factory=_now)
    updated_at: float = dataclasses.field(default_factory=_now)

    @property
    def fact(self) -> str:
        return f"{self.capability}.{self.source}"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["fact"] = self.fact
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityRecord":
        d = {k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}}
        return cls(**d)


@dataclasses.dataclass
class Rule:
    """Symbolic transition: requires (facts) -> produces (facts).

    Rules are hypotheses about how applications compose; a rule earns a
    place when a verified chain demonstrates it, or it is tagged
    ``tentative`` for planner display only."""
    requires: list
    produces: list
    note: str = ""
    tentative: bool = True
    evidence_id: Optional[str] = None
    id: str = dataclasses.field(default_factory=lambda: "rule-" + uuid.uuid4().hex[:8])

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        d = {k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}}
        return cls(**d)


class CapabilityGraph:
    """JSON-persisted capability records + facts + rules + disproven log."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.records: dict[str, CapabilityRecord] = {}
        self.rules: list[Rule] = []
        self.disproven: list[dict] = []   # {"hypothesis":..., "evidence_id":..., "ts":...}
        self.events: list[dict] = []      # experiment state transitions (training data)
        if path and os.path.exists(path):
            self.load(path)

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "updated_at": _now(),
            "records": [r.to_dict() for r in self.records.values()],
            "rules": [r.to_dict() for r in self.rules],
            "disproven": self.disproven,
            "events": self.events[-2000:],
        }

    def load(self, path: str) -> None:
        with open(path) as f:
            d = json.load(f)
        self.records = {r["id"]: CapabilityRecord.from_dict(r) for r in d.get("records", [])}
        self.rules = [Rule.from_dict(r) for r in d.get("rules", [])]
        self.disproven = d.get("disproven", [])
        self.events = d.get("events", [])
        self.path = path

    def save(self, path: Optional[str] = None) -> None:
        p = path or self.path
        if not p:
            return
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=False)
        os.replace(tmp, p)

    # -- mutation ---------------------------------------------------------

    def add_or_update(self, source: str, capability: str, scope: str = "user_writable_paths",
                      requirements: Optional[list] = None, verified: bool = False,
                      evidence_id: Optional[str] = None, confidence: float = 0.5,
                      notes: str = "") -> CapabilityRecord:
        if capability not in CAPABILITY_CLASSES:
            raise ValueError(f"unknown capability class {capability!r}; "
                             f"must be one of {CAPABILITY_CLASSES}")
        for r in self.records.values():
            if r.source == source and r.capability == capability and r.scope == scope:
                r.confidence = max(r.confidence, confidence)
                r.notes = notes or r.notes
                r.updated_at = _now()
                if verified:
                    r.verified = True
                if evidence_id:
                    r.evidence_id = evidence_id
                if requirements:
                    r.requirements = sorted(set(r.requirements) | set(requirements))
                return r
        rec = CapabilityRecord(source=source, capability=capability, scope=scope,
                               requirements=requirements or [], verified=verified,
                               evidence_id=evidence_id, confidence=confidence, notes=notes)
        self.records[rec.id] = rec
        return rec

    def disprove(self, hypothesis: str, evidence_id: Optional[str] = None) -> None:
        self.disproven.append({"hypothesis": hypothesis,
                               "evidence_id": evidence_id, "ts": _now()})

    def is_disproven(self, text: str) -> Optional[dict]:
        key = " ".join(text.lower().split())
        for d in self.disproven:
            if " ".join(d["hypothesis"].lower().split()) == key:
                return d
        return None

    def add_event(self, event: dict) -> None:
        """initial_state -> hypothesis -> action -> observation -> verified -> next_state"""
        self.events.append({"ts": _now(), **event})

    # -- deterministic planner ---------------------------------------------

    def verified_facts(self) -> set[str]:
        facts = set()
        for r in self.records.values():
            if r.verified:
                facts.add(r.fact)
                for req in r.requirements:
                    facts.add(req)
        return facts

    def closure(self) -> set[str]:
        """Forward-chain verified facts through non-tentative rules.

        Tentative (proposed but undemonstrated) rules are EXCLUDED — the
        planner must never treat an LLM hypothesis as reachable state."""
        facts = self.verified_facts()
        while True:
            new = set(facts)
            for rule in self.rules:
                if rule.tentative:
                    continue
                if set(rule.requires) <= facts:
                    new.update(rule.produces)
            if new == facts:
                return facts
            facts = new

    def all_facts(self) -> set[str]:
        """closure incl. tentative rules — displayed to the model as 'hypothesized'."""
        facts = self.verified_facts()
        while True:
            new = set(facts)
            for rule in self.rules:
                if set(rule.requires) <= facts:
                    new.update(rule.produces)
            if new == facts:
                return facts
            facts = new

    def summary(self) -> dict:
        return {
            "verified_facts": sorted(self.closure()),
            "hypothesized_facts": sorted(self.all_facts() - self.closure()),
            "records": [
                {"source": r.source, "capability": r.capability, "scope": r.scope,
                 "verified": r.verified, "confidence": r.confidence,
                 "evidence_id": r.evidence_id, "fact": r.fact}
                for r in sorted(self.records.values(), key=lambda r: (r.capability, r.source))
            ],
            "rules": [
                {"id": ru.id, "requires": ru.requires, "produces": ru.produces,
                 "tentative": ru.tentative, "note": ru.note}
                for ru in self.rules
            ],
            "disproven_count": len(self.disproven),
            "disproven_recent": [d["hypothesis"] for d in self.disproven[-12:]],
        }
