"""SQLite backend for persisting scan results and discovered artifacts.

Stores every module run plus extracted entities (emails, IPs, domains, etc.)
so results survive across sessions and can be queried later.
"""
import os
import json
import sqlite3
import threading
from datetime import datetime
from core.config import Config
from core.utils import print_status


class Database:
    def __init__(self, path=None):
        config = Config()
        self.path = path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            config.get("database.path", "osint.db"),
        )
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=15, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self._write_lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                results TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source_module TEXT,
                timestamp TEXT NOT NULL,
                module_count INTEGER DEFAULT 1,
                confidence TEXT,
                modules TEXT,
                first_seen TEXT,
                last_seen TEXT,
                UNIQUE(target, entity_type, value)
            )
        """)
        # Databases created before correlation existed lack the extra columns.
        existing = {row[1] for row in cur.execute("PRAGMA table_info(entities)")}
        for column, decl in (
            ("module_count", "INTEGER DEFAULT 1"),
            ("confidence", "TEXT"),
            ("modules", "TEXT"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
        ):
            if column not in existing:
                cur.execute(f"ALTER TABLE entities ADD COLUMN {column} {decl}")

        cur.execute("CREATE INDEX IF NOT EXISTS idx_entities_value "
                    "ON entities(value)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_entities_target "
                    "ON entities(target)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_target "
                    "ON scans(target)")
        self.conn.commit()

    def save_scan(self, target, module, results):
        with self._write_lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO scans (target, module, timestamp, results) VALUES (?, ?, ?, ?)",
                (target, module, datetime.now().isoformat(),
                 json.dumps(results, ensure_ascii=False, default=str)),
            )
            return cur.lastrowid

    def save_entity(self, target, entity_type, value, source_module=""):
        with self._write_lock:
            cur = self.conn.cursor()
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO entities "
                    "(target, entity_type, value, source_module, timestamp) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (target, entity_type, value, source_module, datetime.now().isoformat()),
                )
            except sqlite3.Error as e:
                # Always surface - a silently dropped entity is a persistence bug
                # the operator must see, not just under verbose.
                print_status(f"save_entity failed for {entity_type}={value}: {e}", "error")

    def save_entities(self, target, entity_type, values, source_module=""):
        for value in values:
            self.save_entity(target, entity_type, value, source_module)

    def save_correlation(self, target, correlation):
        """Persist a core.correlate result and report what changed.

        Returns {"new": [...], "returning": [...], "absent": [...]}. `absent`
        means the entity is stored from an earlier scan but did not turn up in
        this one -- which can equally mean a module failed, so it is a lead to
        check rather than a confirmed disappearance.
        """
        entities = (correlation or {}).get("entities") or {}
        incoming = {}
        for kind, group in entities.items():
            for entity in group:
                incoming[(kind, entity["value"])] = entity

        previous = {
            (row["entity_type"], row["value"]): row
            for row in self.get_entities(target)
        }

        now = datetime.now().isoformat()
        new, returning = [], []
        persist_errors = []

        with self._write_lock:
            cur = self.conn.cursor()
            for (kind, value), entity in incoming.items():
                modules = entity.get("modules") or []
                row = {
                    "type": kind,
                    "value": value,
                    "module_count": entity.get("module_count", len(modules)),
                    "confidence": entity.get("confidence", ""),
                    "modules": modules,
                }
                if (kind, value) in previous:
                    returning.append(row)
                else:
                    new.append(row)
                try:
                    cur.execute(
                        "INSERT INTO entities (target, entity_type, value, "
                        "source_module, timestamp, module_count, confidence, "
                        "modules, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(target, entity_type, value) DO UPDATE SET "
                        "  module_count = excluded.module_count,"
                        "  confidence   = excluded.confidence,"
                        "  modules      = excluded.modules,"
                        "  last_seen    = excluded.last_seen,"
                        "  first_seen   = COALESCE(entities.first_seen, "
                        "                          excluded.first_seen)",
                        (target, kind, value, ",".join(modules[:5]), now,
                         row["module_count"], row["confidence"],
                         json.dumps(modules, ensure_ascii=False), now, now),
                    )
                except sqlite3.Error as exc:
                    persist_errors.append((kind, value, exc))
                    if Config().get("verbose"):
                        print_status(
                            f"save_correlation failed for {kind}={value}: {exc}",
                            "error")

        # Never silent: a failed persist means the entity map did NOT reach the
        # DB (so `db overlap`/`db history` will be wrong). Warn once with a count.
        if persist_errors:
            print_status(
                f"{len(persist_errors)} of {len(incoming)} entities failed to "
                f"persist (e.g. {persist_errors[0][0]}={persist_errors[0][1]}: "
                f"{persist_errors[0][2]}) - run with verbose for the full list",
                "warning")

        absent = [
            {"type": kind, "value": value,
             "last_seen": previous[(kind, value)].get("last_seen")
             or previous[(kind, value)].get("timestamp")}
            for (kind, value) in previous
            if (kind, value) not in incoming
        ]

        return {
            "new": sorted(new, key=lambda e: -e["module_count"]),
            "returning": returning,
            "absent": absent,
        }

    def entities_across_targets(self, min_targets=2, entity_type=None):
        """Entities seen for more than one target -- the cross-scan overlap."""
        cur = self.conn.cursor()
        query = (
            "SELECT value, entity_type, COUNT(DISTINCT target) AS target_count, "
            "       GROUP_CONCAT(DISTINCT target) AS targets, "
            "       MAX(module_count) AS best_module_count, "
            "       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
            "FROM entities "
        )
        params = []
        if entity_type:
            query += "WHERE entity_type = ? "
            params.append(entity_type)
        query += (
            "GROUP BY value, entity_type "
            "HAVING target_count >= ? "
            "ORDER BY target_count DESC, best_module_count DESC, value"
        )
        params.append(min_targets)
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def entity_history(self, value):
        """Every target an entity has been recorded against."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT target, entity_type, value, module_count, confidence, "
            "       modules, "
            "       COALESCE(first_seen, timestamp) AS first_seen, "
            "       COALESCE(last_seen, timestamp)  AS last_seen "
            # lower() on both sides: Base58 wallets are stored case-preserved.
            "FROM entities WHERE lower(value) = ? "
            "ORDER BY last_seen DESC, target",
            (value.strip().lower(),),
        )
        rows = []
        for row in cur.fetchall():
            item = dict(row)
            try:
                item["modules"] = json.loads(item["modules"] or "[]")
            except (TypeError, ValueError):
                item["modules"] = []
            rows.append(item)
        return rows

    def get_scans(self, target=None, module=None, limit=50):
        cur = self.conn.cursor()
        query = "SELECT * FROM scans"
        conditions, params = [], []
        if target:
            conditions.append("target = ?")
            params.append(target)
        if module:
            conditions.append("module = ?")
            params.append(module)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def get_entities(self, target=None, entity_type=None):
        cur = self.conn.cursor()
        query = "SELECT * FROM entities"
        conditions, params = [], []
        if target:
            conditions.append("target = ?")
            params.append(target)
        if entity_type:
            conditions.append("entity_type = ?")
            params.append(entity_type)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY entity_type, value"
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def list_targets(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT target, COUNT(*) as scan_count, MAX(timestamp) as last_seen "
            "FROM scans GROUP BY target ORDER BY last_seen DESC"
        )
        return [dict(row) for row in cur.fetchall()]

    def stats(self):
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans")
        scans = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT target) FROM scans")
        targets = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM entities")
        entities = cur.fetchone()[0]
        cur.execute("SELECT entity_type, COUNT(*) FROM entities GROUP BY entity_type")
        by_type = {row[0]: row[1] for row in cur.fetchall()}
        return {
            "total_scans": scans,
            "total_targets": targets,
            "total_entities": entities,
            "entities_by_type": by_type,
        }

    def close(self):
        self.conn.close()
