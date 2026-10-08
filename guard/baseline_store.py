"""
Phase 4 Trusted Baseline Store Module
Provides persistent SQLite storage for trusted tool definitions, versioning, and rollback.
"""

import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


def normalize_tool_def(tool_def: Optional[Dict[str, Any]]) -> str:
    """Canonical JSON serialization for deterministic hashing."""
    if tool_def is None:
        return "__NONE__"
    return json.dumps(tool_def, sort_keys=True, separators=(',', ':'))


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()


class BaselineStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        os_dir = self.db_path.parent
        os_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    server_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    version_id INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'TRUSTED',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (server_id, tool_name)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    hash_val TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    version_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def get_trusted_definition(self, server_id: str, tool_name: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Returns (trusted_tool_dict, current_hash) for a given server and tool.
        Returns (None, None) if not present.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT current_hash, canonical_json FROM baselines WHERE server_id = ? AND tool_name = ? AND status = 'TRUSTED'",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            if not row:
                return None, None
            
            curr_hash = row["current_hash"]
            raw_json = row["canonical_json"]
            if raw_json == "__NONE__":
                return None, curr_hash
            try:
                tool_dict = json.loads(raw_json)
                return tool_dict, curr_hash
            except Exception:
                return None, curr_hash

    def get_root_definition(self, server_id: str, tool_name: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Returns the original trusted V1 root definition (tool_dict, root_hash)
        for a given server and tool.
        Retrieves from baseline_history (version_id=1 or earliest SUPERSEDED/TRUSTED record),
        or from the baselines table if version_id=1 and has not been updated yet.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Check baseline_history for the earliest version_id == 1
            cursor.execute(
                "SELECT hash_val, canonical_json FROM baseline_history WHERE server_id = ? AND tool_name = ? AND version_id = 1 ORDER BY history_id ASC LIMIT 1",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            if row:
                raw_json = row["canonical_json"]
                h_val = row["hash_val"]
                if raw_json == "__NONE__":
                    return None, h_val
                try:
                    return json.loads(raw_json), h_val
                except Exception:
                    return None, h_val

            # 2. Check baseline_history for any earliest recorded version
            cursor.execute(
                "SELECT hash_val, canonical_json FROM baseline_history WHERE server_id = ? AND tool_name = ? ORDER BY version_id ASC, history_id ASC LIMIT 1",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            if row:
                raw_json = row["canonical_json"]
                h_val = row["hash_val"]
                if raw_json == "__NONE__":
                    return None, h_val
                try:
                    return json.loads(raw_json), h_val
                except Exception:
                    return None, h_val

            # 3. If no history exists, check the current baselines table
            cursor.execute(
                "SELECT current_hash, canonical_json FROM baselines WHERE server_id = ? AND tool_name = ?",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            if not row:
                return None, None
            curr_hash = row["current_hash"]
            raw_json = row["canonical_json"]
            if raw_json == "__NONE__":
                return None, curr_hash
            try:
                return json.loads(raw_json), curr_hash
            except Exception:
                return None, curr_hash

    def get_version_history(self, server_id: str, tool_name: str) -> List[Dict[str, Any]]:
        """
        Returns complete audit history of all recorded versions for a tool in chronological order.
        """
        history = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT history_id, hash_val, canonical_json, version_id, status, reason, created_at FROM baseline_history WHERE server_id = ? AND tool_name = ? ORDER BY version_id ASC, history_id ASC",
                (server_id, tool_name)
            )
            for r in cursor.fetchall():
                try:
                    t_def = json.loads(r["canonical_json"]) if r["canonical_json"] != "__NONE__" else None
                except Exception:
                    t_def = None
                history.append({
                    "history_id": r["history_id"],
                    "version_id": r["version_id"],
                    "hash": r["hash_val"],
                    "status": r["status"],
                    "reason": r["reason"],
                    "created_at": r["created_at"],
                    "tool_definition": t_def
                })
        return history

    def update_trusted_baseline(self, server_id: str, tool_name: str, tool_def: Dict[str, Any], reason: str = "BENIGN_UPDATE") -> str:
        """
        Updates baseline to a new trusted tool definition.
        Saves previous version in baseline_history. Returns new hash.
        """
        canonical_str = normalize_tool_def(tool_def)
        new_hash = compute_sha256(canonical_str)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Fetch existing
            cursor.execute(
                "SELECT current_hash, canonical_json, version_id FROM baselines WHERE server_id = ? AND tool_name = ?",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            
            if row:
                old_hash = row["current_hash"]
                old_json = row["canonical_json"]
                old_ver = row["version_id"]
                new_ver = old_ver + 1

                # Record history
                cursor.execute(
                    "INSERT INTO baseline_history (server_id, tool_name, hash_val, canonical_json, version_id, status, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (server_id, tool_name, old_hash, old_json, old_ver, 'SUPERSEDED', reason)
                )

                # Upsert main
                cursor.execute(
                    "UPDATE baselines SET current_hash = ?, canonical_json = ?, version_id = ?, status = 'TRUSTED', updated_at = CURRENT_TIMESTAMP WHERE server_id = ? AND tool_name = ?",
                    (new_hash, canonical_str, new_ver, server_id, tool_name)
                )
            else:
                cursor.execute(
                    "INSERT INTO baselines (server_id, tool_name, current_hash, canonical_json, version_id, status) VALUES (?, ?, ?, ?, 1, 'TRUSTED')",
                    (server_id, tool_name, new_hash, canonical_str)
                )

            conn.commit()
        return new_hash

    def record_blocked_update(self, server_id: str, tool_name: str, tool_def: Dict[str, Any], status: str = "QUARANTINED", reason: str = "MALICIOUS_DRIFT") -> str:
        """
        Records a blocked/suspicious update in history WITHOUT overwriting current_trusted baseline.
        """
        canonical_str = normalize_tool_def(tool_def)
        blocked_hash = compute_sha256(canonical_str)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT version_id FROM baselines WHERE server_id = ? AND tool_name = ?",
                (server_id, tool_name)
            )
            row = cursor.fetchone()
            curr_ver = row["version_id"] if row else 0

            cursor.execute(
                "INSERT INTO baseline_history (server_id, tool_name, hash_val, canonical_json, version_id, status, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (server_id, tool_name, blocked_hash, canonical_str, curr_ver + 1, status, reason)
            )
            conn.commit()
        return blocked_hash

    def clear(self):
        """Resets baseline database for testing."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM baselines")
            cursor.execute("DELETE FROM baseline_history")
            conn.commit()
