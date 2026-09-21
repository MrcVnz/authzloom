from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import LimitExceeded, RunIncomplete, RunNotFound
from .limits import Limits
from .redact import redact_with_stats

SCHEMA_VERSION = 2
RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class Store:
    def __init__(self, root: Path, limits: Limits | None = None, *, compress_raw: bool = True):
        self.root = root
        self.limits = limits or Limits()
        self.compress_raw = compress_raw
        root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(root / "metadata.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._migrate()
        self._recover()
        self.db.commit()

    def _migrate(self) -> None:
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS runs ("
            "id TEXT PRIMARY KEY, action_id TEXT, created_at TEXT, path TEXT, "
            "state TEXT, request_count INTEGER, byte_count INTEGER, sha256 TEXT)"
        )
        cols = {row[1] for row in self.db.execute("PRAGMA table_info(runs)")}
        for name, decl in (
            ("state", "TEXT"),
            ("request_count", "INTEGER"),
            ("byte_count", "INTEGER"),
            ("sha256", "TEXT"),
        ):
            if name not in cols:
                self.db.execute(f"ALTER TABLE runs ADD COLUMN {name} {decl}")
        self.db.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    def _recover(self) -> None:
        known = {row[0] for row in self.db.execute("SELECT id FROM runs")}
        now = datetime.now(timezone.utc).isoformat()
        for entry in self.root.iterdir():
            if not entry.is_dir() or not RUN_ID.fullmatch(entry.name):
                continue
            if entry.is_symlink():
                continue
            if entry.name not in known:
                self.db.execute(
                    "INSERT INTO runs (id, action_id, created_at, path, state) VALUES (?, ?, ?, ?, ?)",
                    (entry.name, "", now, entry.name, "incomplete"),
                )
            for tmp in entry.glob("*.tmp"):
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def _resolve(self, run_id: str) -> Path:
        if not RUN_ID.fullmatch(run_id):
            raise RunNotFound("unknown run")
        root = self.root.resolve()
        candidate = root / run_id
        if candidate.is_symlink() or candidate.parent != root:
            raise RunNotFound("unknown run")
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            raise RunNotFound("unknown run") from None
        if resolved != candidate.resolve():
            raise RunNotFound("unknown run")
        with self.lock:
            row = self.db.execute("SELECT id, state FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise RunNotFound("unknown run")
        if row[1] == "incomplete":
            raise RunIncomplete("run is incomplete")
        return candidate

    def save(self, result: dict[str, Any]) -> str:
        run_id = new_run_id()
        run_dir = self.root / run_id
        run_dir.mkdir()
        raw_bytes = json.dumps(result, separators=(",", ":")).encode("utf-8")
        clean, redaction_count = redact_with_stats(result)
        compact = len(raw_bytes) >= 262_144
        redacted_bytes = (json.dumps(clean, indent=None if compact else 2, separators=(",", ":") if compact else None) + "\n").encode("utf-8")
        lines = [f"# AuthzLoom evidence capsule: {run_id}", "", f"Action: `{result['action_id']}`", f"Requests: {result['request_count']}", ""]
        for case in clean.get("cases", []):
            parts = []
            for step in case.get("steps", []):
                status = (step.get("response") or {}).get("status")
                parts.append(f"{step.get('kind')}={status} assertion={step.get('assertion_passed')}")
            lines.append(f"- **{case.get('case', {}).get('name', '?')}**: " + ", ".join(parts))
        markdown = ("\n".join(lines) + "\n").encode("utf-8")
        stored_raw = gzip.compress(raw_bytes, compresslevel=1) if self.compress_raw else raw_bytes
        total = len(stored_raw) + len(redacted_bytes) + len(markdown)
        if total > self.limits.max_run_bytes:
            raise LimitExceeded("input or output exceeds configured limits")
        digest = hashlib.sha256(redacted_bytes).hexdigest()
        if self.compress_raw:
            atomic_write(run_dir / "result.raw.json.gz", stored_raw)
        else:
            atomic_write(run_dir / "result.raw.json", stored_raw)
        atomic_write(run_dir / "capsule.redacted.json", redacted_bytes)
        atomic_write(run_dir / "capsule.redacted.md", markdown)
        meta = {
            "run_id": run_id,
            "state": result.get("state", "complete"),
            "redaction_count": redaction_count,
            "raw_bytes": len(raw_bytes),
            "stored_raw_bytes": len(stored_raw),
            "redacted_bytes": len(redacted_bytes),
            "sha256": digest,
            "compressed": self.compress_raw,
        }
        atomic_write(run_dir / "meta.json", (json.dumps(meta, indent=2) + "\n").encode("utf-8"))
        with self.lock:
            self.db.execute(
                "INSERT INTO runs (id, action_id, created_at, path, state, request_count, byte_count, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    result["action_id"],
                    datetime.now(timezone.utc).isoformat(),
                    run_id,
                    result.get("state", "complete"),
                    int(result.get("request_count") or 0),
                    total,
                    digest,
                ),
            )
            self.db.commit()
        return run_id

    def get(self, run_id: str) -> dict[str, Any]:
        run_dir = self._resolve(run_id)
        path = run_dir / "capsule.redacted.json"
        if path.is_symlink():
            raise RunNotFound("unknown run")
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, str]]:
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        with self.lock:
            rows = self.db.execute(
                "SELECT id, action_id, created_at, state FROM runs WHERE state IS NULL OR state != 'incomplete' "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(zip(("id", "action_id", "created_at", "state"), row)) for row in rows]

    def close(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_):
        self.close()
