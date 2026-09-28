"""Checkmarx One Preset Manager Console.

Local Flask app: authenticate to a CxOne tenant, sync SAST presets, compare
two presets' query selections grouped by language/category, export the diff
to CSV, export a single preset as raw JSON, and push query add/update
changes back to a preset.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from datetime import datetime

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import cx_client
import models
from diff import compare_presets, group_single_preset, has_differences
from export import combined_export_filename, diff_to_csv, queries_to_csv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# In-memory, per-process session store. Deliberately never persisted to disk:
# credentials and tokens live only as long as this process runs.
_SESSIONS: dict[str, dict] = {}

# In-memory sync-job progress, keyed by session id, for the polling progress bar.
_SYNC_STATUS: dict[str, dict] = {}
_sync_lock = threading.Lock()

models.init_db()


def _current_session() -> dict | None:
    sid = session.get("sid")
    if not sid:
        return None
    return _SESSIONS.get(sid)


def _ensure_token(sess: dict) -> None:
    """Refresh the access token in-place if it has expired."""
    if sess["expires_at"] > time.time() + 5:
        return
    token, expires_in = cx_client.get_access_token(
        sess["iam_url"],
        sess["tenant"],
        sess["auth_method"],
        client_id=sess.get("client_id"),
        client_secret=sess.get("client_secret"),
        api_key=sess.get("api_key"),
    )
    sess["token"] = token
    sess["expires_at"] = time.time() + expires_in


def _env_config() -> dict | None:
    """Credentials supplied via a local .env file (see .env.example), so the
    login form doesn't need to be retyped every run. Returns None if no
    usable set of credentials is present."""
    tenant = os.environ.get("CX_TENANT", "").strip()
    if not tenant:
        return None

    api_key = os.environ.get("CX_API_KEY", "").strip() or None
    client_id = os.environ.get("CX_CLIENT_ID", "").strip() or None
    client_secret = os.environ.get("CX_CLIENT_SECRET", "").strip() or None
    if not api_key and not (client_id and client_secret):
        return None

    auth_method = os.environ.get("CX_AUTH_METHOD", "").strip()
    if auth_method not in ("api_key", "client_credentials"):
        auth_method = "api_key" if api_key else "client_credentials"

    return {
        "tenant": tenant,
        "base_url": os.environ.get("CX_BASE_URL", "").strip() or cx_client.DEFAULT_BASE_URL,
        "iam_url": os.environ.get("CX_IAM_URL", "").strip() or cx_client.DEFAULT_IAM_URL,
        "auth_method": auth_method,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
    }


def _establish_session(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key):
    """Attempts to authenticate and, on success, starts a server-side session.
    Returns None on success, or the CxApiError on failure -- the caller
    decides how to surface that (flash + redirect, or fall through to
    rendering the login form directly, depending on where it's called from)."""
    try:
        token, expires_in = cx_client.get_access_token(
            iam_url,
            tenant,
            auth_method,
            client_id=client_id,
            client_secret=client_secret,
            api_key=api_key,
        )
    except cx_client.CxApiError as exc:
        return exc

    sid = secrets.token_hex(16)
    _SESSIONS[sid] = {
        "base_url": base_url,
        "iam_url": iam_url,
        "tenant": tenant,
        "auth_method": auth_method,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
        "token": token,
        "expires_at": time.time() + expires_in,
    }
    session["sid"] = sid
    return None


def _complete_login(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key):
    error = _establish_session(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key)
    if error is not None:
        flash(f"Authentication failed: {error}", "error")
        return redirect(url_for("login"))
    flash("Signed in.", "success")
    return redirect(url_for("presets"))


@app.before_request
def require_login():
    if request.endpoint in ("login", "login_env", "static"):
        return None
    if _current_session() is None:
        return redirect(url_for("login"))
    return None


@app.route("/")
def index():
    return redirect(url_for("presets"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        env_config = _env_config()
        # Auto-attempt sign-in with .env credentials so the user doesn't have
        # to click through -- but not if it already failed once this browser
        # session (avoids retrying forever on every redirect back here), and
        # not right after an explicit sign-out (the whole point of clicking
        # "Sign out" is to get back to the login form and pick different
        # credentials, not be silently logged back in).
        if env_config is not None and not session.get("suppress_auto_login"):
            error = _establish_session(
                env_config["base_url"],
                env_config["iam_url"],
                env_config["tenant"],
                env_config["auth_method"],
                env_config["client_id"],
                env_config["client_secret"],
                env_config["api_key"],
            )
            if error is None:
                flash("Signed in automatically using .env credentials.", "success")
                return redirect(url_for("presets"))
            session["suppress_auto_login"] = True
            flash(f"Automatic .env sign-in failed: {error}", "error")

        return render_template(
            "login.html",
            default_base_url=cx_client.DEFAULT_BASE_URL,
            default_iam_url=cx_client.DEFAULT_IAM_URL,
            env_config=env_config,
        )

    base_url = request.form.get("base_url", "").strip() or cx_client.DEFAULT_BASE_URL
    iam_url = request.form.get("iam_url", "").strip() or cx_client.DEFAULT_IAM_URL
    tenant = request.form.get("tenant", "").strip()
    auth_method = request.form.get("auth_method")
    client_id = request.form.get("client_id", "").strip() or None
    client_secret = request.form.get("client_secret", "").strip() or None
    api_key = request.form.get("api_key", "").strip() or None

    if not tenant:
        flash("Tenant name is required.", "error")
        return redirect(url_for("login"))

    return _complete_login(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key)


@app.route("/login/env", methods=["POST"])
def login_env():
    cfg = _env_config()
    if cfg is None:
        flash("No usable credentials found in .env.", "error")
        return redirect(url_for("login"))
    return _complete_login(
        cfg["base_url"],
        cfg["iam_url"],
        cfg["tenant"],
        cfg["auth_method"],
        cfg["client_id"],
        cfg["client_secret"],
        cfg["api_key"],
    )


@app.route("/logout", methods=["POST"])
def logout():
    sid = session.pop("sid", None)
    if sid:
        _SESSIONS.pop(sid, None)
    # An explicit sign-out means "let me pick different credentials" -- so
    # suppress the .env auto-login for the rest of this browser session
    # instead of immediately logging them back in with the same ones. They
    # can still use the "Sign in using .env credentials" button manually.
    session["suppress_auto_login"] = True
    flash("Signed out.", "success")
    return redirect(url_for("login"))


@app.route("/presets")
def presets():
    rows = models.list_cached_presets()
    return render_template("presets.html", presets=rows)


@app.route("/presets/delete")
def presets_delete():
    # Built-in presets can't be deleted, so they aren't worth showing here.
    rows = [p for p in models.list_cached_presets() if p["is_custom"]]
    return render_template("presets_delete.html", presets=rows)


@app.route("/presets/delete/confirm", methods=["POST"])
def presets_delete_confirm():
    ids = [int(i) for i in request.form.getlist("selected_preset_ids")]
    if not ids:
        flash("Select at least one preset to delete.", "error")
        return redirect(url_for("presets_delete"))

    # Built-in presets can't be deleted (same restriction as updating them);
    # the checkbox for them is already disabled client-side, but re-check
    # server-side rather than trusting form data.
    to_delete = [
        meta
        for meta in (models.get_cached_preset_meta(pid) for pid in ids)
        if meta is not None and meta["is_custom"]
    ]
    if not to_delete:
        flash("No deletable presets were selected (Built-in presets cannot be deleted).", "error")
        return redirect(url_for("presets_delete"))

    return render_template("presets_delete_confirm.html", presets=to_delete)


@app.route("/presets/delete/apply", methods=["POST"])
def presets_delete_apply():
    sess = _current_session()
    ids = [int(i) for i in request.form.getlist("preset_ids")]
    if not ids:
        flash("No presets selected to delete.", "error")
        return redirect(url_for("presets_delete"))

    try:
        _ensure_token(sess)
    except cx_client.CxApiError as exc:
        flash(f"Could not refresh authentication: {exc}", "error")
        return redirect(url_for("presets_delete"))

    deleted, failed = [], []
    for preset_id in ids:
        try:
            cx_client.delete_preset(sess["base_url"], sess["token"], preset_id)
            models.delete_preset(preset_id)
            deleted.append(preset_id)
        except cx_client.CxApiError as exc:
            failed.append((preset_id, str(exc)))

    if deleted:
        flash(f"Deleted {len(deleted)} preset(s).", "success")
    if failed:
        detail = "; ".join(f"id {pid}: {err}" for pid, err in failed)
        flash(f"Failed to delete {len(failed)} preset(s): {detail}", "error")

    return redirect(url_for("presets"))


def _run_sync(sid: str, refresh_catalog: bool = False) -> None:
    status = _SYNC_STATUS[sid]
    sess = _SESSIONS.get(sid)
    if sess is None:
        status.update(state="error", message="Session expired. Please sign in again.")
        return
    try:
        _ensure_token(sess)

        # The query catalog (families -> categories -> queries) is stored in
        # SQLite and mostly static, so it's only (re)fetched when the local
        # cache is empty or a refresh was explicitly requested -- not on
        # every sync/login. Presets only reference queries by id grouped
        # under a family, with no name/category/severity attached, so those
        # must be resolved against this catalog to display anything
        # meaningful.
        cached_catalog_count = models.query_catalog_count()
        need_catalog = refresh_catalog or cached_catalog_count == 0

        families = cx_client.list_query_families(sess["base_url"], sess["token"]) if need_catalog else []
        summaries = cx_client.list_presets(sess["base_url"], sess["token"])
        total = len(families) + len(summaries)
        status.update(state="running", current=0, total=total, message="Starting…")

        done = 0
        if need_catalog:
            status.update(message="Syncing query catalog…")
            for family in families:
                queries = cx_client.list_queries_in_family(sess["base_url"], sess["token"], family)
                for query in queries:
                    models.upsert_query_catalog_entry(family, query)
                done += 1
                status.update(
                    current=done, message=f"Syncing query catalog… {done} of {len(families)} families"
                )
        else:
            status.update(message=f"Using cached query catalog ({cached_catalog_count} queries)…")

        status.update(message="Syncing presets…")
        for summary in summaries:
            preset_id = summary.get("id")
            if preset_id is not None:
                full = cx_client.get_preset(sess["base_url"], sess["token"], preset_id)
                models.upsert_preset(full)
            done += 1
            status.update(current=done)

        if need_catalog:
            done_message = f"Synced {len(families)} query families and {len(summaries)} preset(s)."
        else:
            done_message = f"Synced {len(summaries)} preset(s) (query catalog already cached)."
        status.update(state="done", message=done_message)
    except cx_client.CxApiError as exc:
        status.update(state="error", message=f"Sync failed: {exc}")
    except Exception as exc:  # safety net so the UI never polls forever on an unexpected error
        status.update(state="error", message=f"Sync failed: {exc}")


@app.route("/sync/start", methods=["POST"])
def sync_start():
    sid = session["sid"]
    refresh_catalog = request.args.get("refresh_catalog") == "1"
    with _sync_lock:
        existing = _SYNC_STATUS.get(sid)
        if existing and existing.get("state") == "running":
            return existing
        _SYNC_STATUS[sid] = {"state": "running", "current": 0, "total": 0, "message": "Starting…"}
        threading.Thread(target=_run_sync, args=(sid, refresh_catalog), daemon=True).start()
    return _SYNC_STATUS[sid]


@app.route("/sync/status")
def sync_status():
    sid = session["sid"]
    return _SYNC_STATUS.get(sid, {"state": "idle", "current": 0, "total": 0, "message": ""})


@app.route("/preset/<int:preset_id>/detail")
def preset_detail(preset_id):
    preset = models.get_cached_preset(preset_id)
    meta = models.get_cached_preset_meta(preset_id)
    if preset is None or meta is None:
        return {"error": "Preset not found in the local cache. Try syncing first."}, 404

    queries = models.normalize_preset_queries(preset)
    return {
        "id": meta["id"],
        "name": meta["name"],
        "is_custom": bool(meta["is_custom"]),
        "description": meta["description"],
        "total_queries": len(queries),
        "groups": group_single_preset(queries),
    }


@app.route("/compare")
def compare():
    rows = models.list_cached_presets()
    a_id = request.args.get("a", type=int)
    b_id = request.args.get("b", type=int)

    if a_id is None or b_id is None:
        return render_template("compare.html", presets=rows, groups=None)

    preset_a = models.get_cached_preset(a_id)
    preset_b = models.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache. Try syncing again.", "error")
        return redirect(url_for("presets"))

    groups = compare_presets(
        models.normalize_preset_queries(preset_a), models.normalize_preset_queries(preset_b)
    )
    return render_template(
        "compare.html",
        presets=rows,
        groups=groups,
        preset_a=preset_a,
        preset_b=preset_b,
        a_id=a_id,
        b_id=b_id,
        any_differences=has_differences(groups),
    )


@app.route("/compare/export.csv")
def compare_export_csv():
    a_id = request.args.get("a", type=int)
    b_id = request.args.get("b", type=int)
    preset_a = models.get_cached_preset(a_id)
    preset_b = models.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache.", "error")
        return redirect(url_for("presets"))

    groups = compare_presets(
        models.normalize_preset_queries(preset_a), models.normalize_preset_queries(preset_b)
    )
    csv_text = diff_to_csv(groups, preset_a.get("name", str(a_id)), preset_b.get("name", str(b_id)))
    filename = f"preset_diff_{a_id}_vs_{b_id}.csv"
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/compare/combine", methods=["POST"])
def compare_combine():
    a_id = request.form.get("a_id", type=int)
    b_id = request.form.get("b_id", type=int)
    selected_ids = set(request.form.getlist("selected_query_ids"))

    preset_a = models.get_cached_preset(a_id)
    preset_b = models.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache.", "error")
        return redirect(url_for("presets"))

    groups = compare_presets(
        models.normalize_preset_queries(preset_a), models.normalize_preset_queries(preset_b)
    )

    # Queries common to both presets are always carried over unconditionally
    # (they aren't a "difference" and were never shown with a checkbox);
    # only-in-Base/only-in-Target queries are included only if their
    # checkbox was checked.
    final_queries: dict[str, dict] = {}
    for bucket in groups.values():
        for q in bucket["common"]:
            final_queries[q["queryId"]] = q
        for q in bucket["only_a"] + bucket["only_b"]:
            if q["queryId"] in selected_ids:
                final_queries[q["queryId"]] = q

    final_list = sorted(
        final_queries.values(), key=lambda q: (q["language"], q["group"], q["name"])
    )

    return render_template(
        "combine_preview.html",
        preset_a=preset_a,
        preset_b=preset_b,
        suggested_name=preset_a.get("name", ""),
        suggested_description=preset_a.get("description") or "",
        groups=group_single_preset(final_list),
        total_queries=len(final_list),
        queries_json=json.dumps(final_list),
    )


@app.route("/compare/combine/export.csv", methods=["POST"])
def compare_combine_export_csv():
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    queries_json = request.form.get("queries_json", "[]")
    try:
        final_list = json.loads(queries_json)
    except json.JSONDecodeError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("presets"))

    csv_text = queries_to_csv(final_list)
    filename = combined_export_filename(preset_name)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/compare/combine/confirm", methods=["POST"])
def compare_combine_confirm():
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    description = request.form.get("description", "").strip()
    queries_json = request.form.get("queries_json", "[]")
    try:
        final_list = json.loads(queries_json)
    except json.JSONDecodeError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("presets"))

    existing = next(
        (p for p in models.list_cached_presets() if p["name"].lower() == preset_name.lower()),
        None,
    )
    final_by_family = models.group_queries_by_family(final_list)

    # Pretty-printed exactly as it will be sent, so the preview never drifts
    # from the real request body (cx_client._preset_body).
    payload = {
        "name": preset_name,
        "description": description,
        "queries": [
            {"familyName": family, "queryIds": ids} for family, ids in final_by_family.items()
        ],
    }

    return render_template(
        "combine_confirm.html",
        preset_name=preset_name,
        description=description,
        existing=existing,
        total_queries=len(final_list),
        payload_json=json.dumps(payload, indent=2),
        queries_json=queries_json,
    )


@app.route("/compare/combine/apply", methods=["POST"])
def compare_combine_apply():
    sess = _current_session()
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    description = request.form.get("description", "").strip()
    queries_json = request.form.get("queries_json", "[]")
    target_preset_id = request.form.get("target_preset_id", type=int)

    try:
        final_list = json.loads(queries_json)
    except json.JSONDecodeError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("presets"))

    final_by_family = models.group_queries_by_family(final_list)

    try:
        _ensure_token(sess)
        if target_preset_id is not None:
            cx_client.update_preset(
                sess["base_url"], sess["token"], target_preset_id, preset_name, description, final_by_family
            )
            saved_id = target_preset_id
            verb = "updated"
        else:
            created = cx_client.create_preset(
                sess["base_url"], sess["token"], preset_name, description, final_by_family
            )
            saved_id = created.get("id")
            verb = "created"

        if saved_id is not None:
            refreshed = cx_client.get_preset(sess["base_url"], sess["token"], saved_id)
            models.upsert_preset(refreshed)
        flash(f"Preset '{preset_name}' {verb} with {len(final_list)} queries.", "success")
    except cx_client.CxApiError as exc:
        error_message = f"Could not save the combined preset: {exc}"
        if exc.body:
            error_message = error_message + " Response body: " + exc.body
        flash(error_message, "error")
        return redirect(url_for("presets"))

    return redirect(url_for("presets"))


@app.route("/preset/<int:preset_id>/export.json")
def preset_export_json(preset_id):
    preset = models.get_cached_preset(preset_id)
    if preset is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("presets"))
    filename = f"preset_{preset_id}.json"
    return Response(
        json.dumps(preset, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/preset/<int:preset_id>/update", methods=["GET", "POST"])
def preset_update(preset_id):
    preset = models.get_cached_preset(preset_id)
    meta = models.get_cached_preset_meta(preset_id)
    if preset is None or meta is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("presets"))

    current_queries = models.normalize_preset_queries(preset)
    current_ids = {q["queryId"] for q in current_queries if q.get("queryId") is not None}

    if request.method == "GET":
        return render_template(
            "update_preset.html",
            meta=meta,
            catalog=models.full_query_catalog(),
            current_ids=current_ids,
            total_queries=len(current_ids),
        )

    is_builtin = not meta["is_custom"]
    new_preset_name = request.form.get("new_preset_name", "").strip()

    if is_builtin and not new_preset_name:
        flash("Built-in presets cannot be modified directly — enter a New Preset Name.", "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    selected_ids = set(request.form.getlist("selected_query_ids"))
    added_ids = selected_ids - current_ids
    removed_ids = current_ids - selected_ids

    def _resolve(query_id):
        return models.get_query_metadata(query_id) or {
            "queryId": query_id,
            "language": "Unknown",
            "group": "Uncategorized",
            "name": query_id,
        }

    def _sorted_resolved(ids):
        return sorted(
            (_resolve(q) for q in ids), key=lambda q: (q["language"], q["group"], q["name"])
        )

    final_by_family = models.group_queries_by_family(_resolve(q) for q in selected_ids)

    target_name = new_preset_name if is_builtin else meta["name"]
    target_description = request.form.get("description", "").strip()

    # Pretty-printed exactly as it will be sent (see cx_client._preset_body).
    payload = {
        "name": target_name,
        "description": target_description,
        "queries": [
            {"familyName": family, "queryIds": ids} for family, ids in final_by_family.items()
        ],
    }

    return render_template(
        "update_preset_confirm.html",
        preset=preset,
        meta=meta,
        is_builtin=is_builtin,
        target_name=target_name,
        target_description=target_description,
        new_preset_name=new_preset_name,
        added=_sorted_resolved(added_ids),
        removed=_sorted_resolved(removed_ids),
        current_count=len(current_ids),
        final_count=len(selected_ids),
        payload_json=json.dumps(payload, indent=2),
        final_by_family_json=json.dumps(final_by_family),
    )


@app.route("/preset/<int:preset_id>/update/confirm", methods=["POST"])
def preset_update_confirm(preset_id):
    sess = _current_session()
    meta = models.get_cached_preset_meta(preset_id)
    if meta is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("presets"))

    final_by_family_json = request.form.get("final_by_family_json", "{}")
    try:
        final_by_family = json.loads(final_by_family_json)
    except json.JSONDecodeError:
        flash("Could not read the confirmed query list; please try again.", "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    new_preset_name = request.form.get("new_preset_name", "").strip()
    description = request.form.get("description", "").strip()
    total_queries = sum(len(ids) for ids in final_by_family.values())

    try:
        _ensure_token(sess)
        if new_preset_name:
            # Built-in source preset: never PATCH it -- create a new preset
            # with the selected queries instead.
            created = cx_client.create_preset(
                sess["base_url"], sess["token"], new_preset_name, description, final_by_family
            )
            new_id = created.get("id")
            if new_id is not None:
                refreshed = cx_client.get_preset(sess["base_url"], sess["token"], new_id)
                models.upsert_preset(refreshed)
            flash(f"Created new preset '{new_preset_name}' with {total_queries} queries.", "success")
        else:
            cx_client.update_preset(
                sess["base_url"],
                sess["token"],
                preset_id,
                meta["name"],
                description,
                final_by_family,
            )
            refreshed = cx_client.get_preset(sess["base_url"], sess["token"], preset_id)
            models.upsert_preset(refreshed)
            flash(f"Preset {preset_id} updated with {total_queries} queries.", "success")
    except cx_client.CxApiError as exc:
        error_message = f"Could not apply preset changes: {exc}"
        if exc.body:
            error_message = error_message + " Response body: " + exc.body
        flash(error_message, "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    return redirect(url_for("presets"))


@app.context_processor
def inject_globals():
    return {"now": datetime.utcnow(), "logged_in": _current_session() is not None}


if __name__ == "__main__":
    app.run(debug=True, port=5050, threaded=True)
