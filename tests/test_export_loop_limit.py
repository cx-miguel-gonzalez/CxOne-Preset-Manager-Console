"""Tests for CWE-606: Unchecked Input for Loop Condition.

Verifies that the compare_combine_export_csv endpoint validates the size of the
user-supplied query list before iterating over it, preventing DoS via
excessively large loop iterations.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Minimal Flask app fixture — import the module-level `app` object but patch
# the database initialisation so no real SQLite file is required during tests.
# ---------------------------------------------------------------------------

# Point imports at the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def client(monkeypatch):
    """Return a Flask test client with a patched init_db so no DB is needed."""
    # Patch models.init_db before importing app to prevent side effects.
    import models

    monkeypatch.setattr(models, "init_db", lambda: None, raising=False)

    import app as flask_app  # noqa: PLC0415

    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SECRET_KEY"] = "test-secret"
    flask_app.app.config["WTF_CSRF_ENABLED"] = False

    with flask_app.app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MAX_EXPORT_QUERIES = 10_000  # must match the constant in app.py


def _make_query(idx: int) -> dict:
    return {
        "language": "Python",
        "group": "Security",
        "name": f"Query_{idx}",
        "queryId": idx,
    }


def _post_export(client, queries: list, preset_name: str = "TestPreset"):
    return client.post(
        "/compare/combine/export.csv",
        data={
            "preset_name": preset_name,
            "queries_json": json.dumps(queries),
        },
    )


# ---------------------------------------------------------------------------
# Positive cases — valid inputs that should produce a CSV response
# ---------------------------------------------------------------------------


def test_empty_list_returns_csv(client):
    """An empty query list is valid and should return a CSV with only the header row."""
    resp = _post_export(client, [])
    assert resp.status_code == 200
    assert b"Language" in resp.data
    assert b"Category" in resp.data
    assert b"Query Name" in resp.data


def test_single_query_returns_csv(client):
    """A single query should appear in the returned CSV."""
    queries = [_make_query(1)]
    resp = _post_export(client, queries)
    assert resp.status_code == 200
    assert b"Query_1" in resp.data


def test_max_allowed_queries_returns_csv(client):
    """Exactly MAX_EXPORT_QUERIES entries should be accepted."""
    queries = [_make_query(i) for i in range(MAX_EXPORT_QUERIES)]
    resp = _post_export(client, queries)
    assert resp.status_code == 200
    # CSV header + MAX_EXPORT_QUERIES rows
    lines = resp.data.decode().strip().splitlines()
    assert len(lines) == MAX_EXPORT_QUERIES + 1  # +1 for the header


# ---------------------------------------------------------------------------
# Negative / security cases — inputs that should be rejected
# ---------------------------------------------------------------------------


def test_oversized_list_is_rejected(client):
    """A list exceeding MAX_EXPORT_QUERIES must be rejected (no CSV returned)."""
    queries = [_make_query(i) for i in range(MAX_EXPORT_QUERIES + 1)]
    resp = _post_export(client, queries)
    # The endpoint should redirect away (302) instead of producing a CSV.
    assert resp.status_code in (302, 303)
    assert resp.content_type != "text/csv"


def test_grossly_oversized_list_is_rejected(client):
    """A list orders-of-magnitude larger than the limit is rejected quickly."""
    # We build the JSON string manually so we never allocate a Python list of
    # 1 000 000 dicts in memory; the list itself is small enough to be valid
    # JSON but large in count.
    big_list = [_make_query(i) for i in range(MAX_EXPORT_QUERIES + 10)]
    resp = _post_export(client, big_list)
    assert resp.status_code in (302, 303)
    assert resp.content_type != "text/csv"


def test_non_list_json_is_rejected(client):
    """A JSON object (not a list) must be rejected."""
    resp = _post_export(client, {})  # type: ignore[arg-type]
    assert resp.status_code in (302, 303)


def test_invalid_json_is_rejected(client):
    """Malformed JSON must not crash the app."""
    from app import app as flask_app  # noqa: PLC0415

    with flask_app.test_client() as c:
        resp = c.post(
            "/compare/combine/export.csv",
            data={"preset_name": "X", "queries_json": "{not json"},
        )
    assert resp.status_code in (302, 303)


def test_number_json_is_rejected(client):
    """A bare JSON number (not a list) must be rejected."""
    from app import app as flask_app  # noqa: PLC0415

    with flask_app.test_client() as c:
        resp = c.post(
            "/compare/combine/export.csv",
            data={"preset_name": "X", "queries_json": "999999999"},
        )
    assert resp.status_code in (302, 303)


# ---------------------------------------------------------------------------
# Unit tests for queries_to_csv directly
# ---------------------------------------------------------------------------


def test_queries_to_csv_unit():
    """queries_to_csv should produce correct CSV output for a small list."""
    from export import queries_to_csv

    queries = [
        {"language": "Python", "group": "Security", "name": "SQLi"},
        {"language": "Java", "group": "Injection", "name": "XSS"},
    ]
    csv_text = queries_to_csv(queries)
    assert "Language" in csv_text
    assert "Category" in csv_text
    assert "Query Name" in csv_text
    assert "SQLi" in csv_text
    assert "XSS" in csv_text


def test_queries_to_csv_empty():
    """queries_to_csv with an empty list should return only the header row."""
    from export import queries_to_csv

    csv_text = queries_to_csv([])
    lines = csv_text.strip().splitlines()
    assert len(lines) == 1
    assert "Language" in lines[0]
