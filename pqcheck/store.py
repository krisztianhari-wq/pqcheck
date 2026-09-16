"""Result history: every run is stored in a local SQLite database (stdlib only).

Default location: $PQCHECK_DB or ~/.pqcheck/history.db
"""
import csv
import io
import json
import os
import socket
import sqlite3
import time
from typing import List, Optional

from .knowledge import Verdict
from .report import Finding, worst

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  host TEXT,
  command TEXT NOT NULL,
  targets TEXT NOT NULL,
  overall TEXT,
  n_findings INTEGER NOT NULL,
  n_vulnerable INTEGER NOT NULL,
  n_weak INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  location TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  category TEXT,
  verdict TEXT NOT NULL,
  bits INTEGER,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_runs_ts ON runs(ts);
"""


def default_path() -> str:
    return os.environ.get("PQCHECK_DB") or os.path.join(os.path.expanduser("~"), ".pqcheck", "history.db")


class Store:
    def __init__(self, path: Optional[str] = None):
        self.path = path or default_path()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def save_run(self, command: str, targets: List[str], findings: List[Finding]) -> int:
        w = worst(findings)
        cur = self.db.execute(
            "INSERT INTO runs(ts, host, command, targets, overall, n_findings, n_vulnerable, n_weak) VALUES (?,?,?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%dT%H:%M:%S"), socket.gethostname(), command, json.dumps(targets), w.value if w else None,
             len(findings), sum(f.verdict is Verdict.VULNERABLE for f in findings), sum(f.verdict is Verdict.WEAK for f in findings)))
        run_id = cur.lastrowid
        self.db.executemany(
            "INSERT INTO findings(run_id, target, location, algorithm, category, verdict, bits, note) VALUES (?,?,?,?,?,?,?,?)",
            [(run_id, f.target, f.location, f.algorithm, f.category, f.verdict.value, f.bits, f.note) for f in findings])
        self.db.commit()
        return run_id

    def runs(self, limit: int = 50, target: Optional[str] = None) -> List[dict]:
        if target:
            rows = self.db.execute(
                "SELECT DISTINCT r.id, r.ts, r.host, r.command, r.targets, r.overall, r.n_findings, r.n_vulnerable, r.n_weak "
                "FROM runs r JOIN findings f ON f.run_id = r.id WHERE f.target LIKE ? OR r.targets LIKE ? ORDER BY r.id DESC LIMIT ?",
                ("%" + target + "%", "%" + target + "%", limit)).fetchall()
        else:
            rows = self.db.execute("SELECT id, ts, host, command, targets, overall, n_findings, n_vulnerable, n_weak FROM runs "
                                   "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        keys = ("id", "ts", "host", "command", "targets", "overall", "n_findings", "n_vulnerable", "n_weak")
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["targets"] = json.loads(d["targets"])
            out.append(d)
        return out

    def findings(self, run_id: int) -> List[Finding]:
        rows = self.db.execute("SELECT target, location, algorithm, category, verdict, bits, note FROM findings WHERE run_id=? ORDER BY id",
                               (run_id,)).fetchall()
        return [Finding(t, l, a, c or "", Verdict(v), b, n or "") for t, l, a, c, v, b, n in rows]

    def latest_per_target(self) -> List[dict]:
        """Newest overall verdict for every distinct target (trend / inventory view)."""
        rows = self.db.execute("""
            SELECT f.target, r.ts, r.id, MIN(CASE f.verdict WHEN 'QUANTUM_VULNERABLE' THEN 0 WHEN 'WEAK' THEN 1 WHEN 'UNKNOWN' THEN 2
                   WHEN 'INFO' THEN 3 WHEN 'HYBRID_PQC' THEN 4 ELSE 5 END) AS sev, COUNT(*)
            FROM findings f JOIN runs r ON r.id = f.run_id
            WHERE r.id = (SELECT MAX(r2.id) FROM runs r2 JOIN findings f2 ON f2.run_id = r2.id WHERE f2.target = f.target)
            GROUP BY f.target ORDER BY sev, f.target""").fetchall()
        sev_names = ["QUANTUM_VULNERABLE", "WEAK", "UNKNOWN", "INFO", "HYBRID_PQC", "QUANTUM_SAFE"]
        return [{"target": t, "ts": ts, "run_id": rid, "overall": sev_names[s], "n_findings": n} for t, ts, rid, s, n in rows]

    def delete_run(self, run_id: int) -> None:
        self.db.execute("DELETE FROM runs WHERE id=?", (run_id,))
        self.db.commit()

    def export(self, fmt: str = "csv", run_id: Optional[int] = None) -> str:
        q = ("SELECT r.id, r.ts, r.command, f.target, f.location, f.algorithm, f.category, f.verdict, f.bits, f.note "
             "FROM findings f JOIN runs r ON r.id = f.run_id")
        args = ()
        if run_id:
            q += " WHERE r.id = ?"
            args = (run_id,)
        rows = self.db.execute(q + " ORDER BY r.id, f.id", args).fetchall()
        cols = ["run_id", "ts", "command", "target", "location", "algorithm", "category", "verdict", "bits", "note"]
        if fmt == "json":
            return json.dumps([dict(zip(cols, r)) for r in rows], indent=2, ensure_ascii=False)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        w.writerows(rows)
        return buf.getvalue()
