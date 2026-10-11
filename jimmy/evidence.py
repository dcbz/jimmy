"""Evidence store + replay corpus.

Every run gets a directory under runs/:
    meta.json            run configuration + target description
    transcript.raw       complete PTY byte stream (lossless)
    screens/NNNN.txt     normalized screen snapshots
    evidence/ev-XXXX     individual pieces of evidence (outputs, file contents)
    experiments.jsonl    one structured record per experiment — the
                         training-data shape: initial_state -> hypothesis ->
                         action -> observation -> verified capability -> next_state
    graph.json           capability graph (persisted live)
    report.json          final outcome + metrics
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Optional


class EvidenceStore:
    def __init__(self, root: str, meta: Optional[dict] = None):
        self.root = root
        os.makedirs(root, exist_ok=True)
        os.makedirs(os.path.join(root, "evidence"), exist_ok=True)
        os.makedirs(os.path.join(root, "screens"), exist_ok=True)
        self.transcript_path = os.path.join(root, "transcript.raw")
        self._counter = 0
        if meta is not None:
            with open(os.path.join(root, "meta.json"), "w") as f:
                json.dump({"started_at": time.time(), **meta}, f, indent=2)

    @staticmethod
    def new_run_dir(base: str = "runs", label: str = "") -> str:
        ts = time.strftime("%Y%m%d-%H%M%S")
        slug = f"-{label}" if label else ""
        path = os.path.join(base, f"{ts}{slug}-{uuid.uuid4().hex[:6]}")
        return path

    def put(self, kind: str, content: str | bytes, note: str = "") -> str:
        """Store a piece of evidence; return its id."""
        self._counter += 1
        eid = f"ev-{self._counter:04d}"
        ext = "bin" if isinstance(content, bytes) else "txt"
        path = os.path.join(self.root, "evidence", f"{eid}.{ext}")
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as f:
            f.write(content)
        with open(os.path.join(self.root, "evidence", "index.jsonl"), "a") as f:
            f.write(json.dumps({"id": eid, "kind": kind, "note": note,
                                "path": path, "ts": time.time()}) + "\n")
        return eid

    def save_screen(self, screen: str) -> str:
        self._counter += 1
        eid = f"scr-{self._counter:04d}"
        path = os.path.join(self.root, "screens", f"{eid}.txt")
        with open(path, "w") as f:
            f.write(screen)
        return eid

    def log_experiment(self, record: dict) -> None:
        record = {"ts": time.time(), **record}
        with open(os.path.join(self.root, "experiments.jsonl"), "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def write_json(self, name: str, obj) -> None:
        with open(os.path.join(self.root, name), "w") as f:
            json.dump(obj, f, indent=2, default=str)
