"""SQLite cache of synced presets. Stores the raw API JSON verbatim so JSON
export and diffing both work directly off the same source of truth."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "presets.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS presets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    is_custom INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    raw_json TEXT NOT NULL,
    synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_catalog (
    query_id TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    name TEXT NOT NULL,
    group_name TEXT,
    severity TEXT,
    raw_json TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def _is_custom(preset: dict) -> bool:
    # Be defensive: different tenants/API versions may name this flag differently.
    for key in ("isCustom", "custom", "isUserDefined"):
        if key in preset:
            return bool(preset[key])
    for key in ("isDefault", "isBuiltIn", "builtIn"):
        if key in preset:
            return not bool(preset[key])
    return False


def upsert_preset(preset: dict) -> None:
    preset_id = preset.get("id")
    name = preset.get("name", f"Preset {preset_id}")
    description = preset.get("description")
    is_custom = 1 if _is_custom(preset) else 0
    synced_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO presets (id, name, is_custom, description, raw_json, synced_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                is_custom=excluded.is_custom,
                description=excluded.description,
                raw_json=excluded.raw_json,
                synced_at=excluded.synced_at
            """,
            (preset_id, name, is_custom, description, json.dumps(preset), synced_at),
        )


def delete_preset(preset_id) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM presets WHERE id = ?", (preset_id,))


def list_cached_presets() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, name, is_custom, description, synced_at FROM presets ORDER BY name"
        ).fetchall()


def get_cached_preset(preset_id) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT raw_json FROM presets WHERE id = ?", (preset_id,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["raw_json"])


def get_cached_preset_meta(preset_id) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, name, is_custom, description, synced_at FROM presets WHERE id = ?",
            (preset_id,),
        ).fetchone()


def upsert_query_catalog_entry(family: str, query: dict) -> None:
    """Cache one flattened entry from GET /query-families/{family}/queries
    (see cx_client._flatten_query_tree). The "key" field is the same
    identifier a preset's queryIds array references; "title" is the query's
    display name (e.g. "CSRF"); "group" is the category it was nested under
    (e.g. "Python_Medium_Threat")."""
    query_id = str(query.get("key") or query.get("queryId") or query.get("id"))
    name = query.get("title") or query.get("name") or query.get("queryName") or query_id
    group = query.get("group") or query.get("category") or family
    severity = query.get("severity")

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO query_catalog (query_id, family, name, group_name, severity, raw_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(query_id) DO UPDATE SET
                family=excluded.family,
                name=excluded.name,
                group_name=excluded.group_name,
                severity=excluded.severity,
                raw_json=excluded.raw_json
            """,
            (query_id, family, name, group, severity, json.dumps(query)),
        )


def query_catalog_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM query_catalog").fetchone()[0]


def get_query_metadata(query_id) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT query_id, family, name, group_name, severity FROM query_catalog WHERE query_id = ?",
            (str(query_id),),
        ).fetchone()
    if row is None:
        return None
    return {
        "queryId": row["query_id"],
        "language": row["family"],
        "group": row["group_name"],
        "name": row["name"],
        "severity": row["severity"],
    }


def normalize_preset_queries(preset: dict) -> list[dict]:
    """Returns a flat list of query dicts (queryId, language, group, name,
    severity), regardless of whether the preset stores queries as a flat
    list (older assumption) or -- as confirmed against the real API --
    grouped by family with bare queryIds:
    "queries": [{"familyName": "Java", "queryIds": ["123", ...]}, ...]

    Grouped-format queryIds are resolved against the local query_catalog
    (populated by a sync). An id with no catalog match still renders,
    labeled with its family and a placeholder name, rather than being
    silently dropped.
    """
    raw_queries = preset.get("queries") or []
    if not raw_queries:
        return []

    is_grouped = isinstance(raw_queries[0], dict) and "queryIds" in raw_queries[0]
    if not is_grouped:
        return raw_queries

    flat = []
    for group in raw_queries:
        family = group.get("familyName") or group.get("family") or "Unknown"
        for query_id in group.get("queryIds", []) or []:
            meta = get_query_metadata(query_id)
            if meta:
                flat.append(meta)
            else:
                flat.append(
                    {
                        "queryId": str(query_id),
                        "language": family,
                        "group": "Uncategorized",
                        "name": f"Query {query_id}",
                    }
                )
    return flat


def group_queries_by_family(queries: list[dict]) -> dict[str, list[str]]:
    """Inverse of normalize_preset_queries: takes a flat list of query dicts
    and regroups their ids by family (language), sorted, for building a
    create/update preset request body."""
    by_family: dict[str, list[str]] = {}
    for q in queries:
        query_id = q.get("queryId")
        if query_id is None:
            continue
        by_family.setdefault(q.get("language") or "Unknown", []).append(str(query_id))
    for family in by_family:
        by_family[family].sort()
    return dict(sorted(by_family.items()))


def full_query_catalog() -> dict:
    """The entire synced query catalog -- every query known to the tenant's
    engines (not just ones already used by a preset) -- grouped by
    language -> category -> [{"queryId", "name"}, ...], for the
    check-everything-that-applies picker on the update-preset screen."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT query_id, family, name, group_name FROM query_catalog "
            "ORDER BY family, group_name, name"
        ).fetchall()

    groups: dict[str, dict[str, list]] = {}
    for row in rows:
        category = row["group_name"] or "Uncategorized"
        groups.setdefault(row["family"], {}).setdefault(category, []).append(
            {"queryId": row["query_id"], "name": row["name"]}
        )
    return groups
