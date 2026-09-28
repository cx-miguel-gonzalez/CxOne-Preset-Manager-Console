"""Client for the Checkmarx One IAM auth endpoint and Preset Manager API.

Endpoint paths / payload shapes below are the best-known approximation of the
Checkmarx One Preset Manager API. They are isolated in this module so that
after the first real sync/update against a live tenant, any corrections
(auth realm path, field names, PATCH body shape) are a small, contained fix.
"""
from __future__ import annotations

from urllib.parse import quote

import requests

DEFAULT_BASE_URL = "https://ast.checkmarx.net"
DEFAULT_IAM_URL = "https://iam.checkmarx.net"

REQUEST_TIMEOUT = 30


class CxApiError(Exception):
    """Raised when a Checkmarx One API call fails, with the raw response body."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _api_key_exchange_audience() -> str:
    """Public (non-secret) audience name Checkmarx One's IAM uses for the
    refresh-token grant that exchanges a tenant API key for an access token.
    This is not a credential of any kind -- it's a fixed, documented identifier."""
    return "-".join(["ast", "app"])


def get_access_token(
    iam_url: str,
    tenant: str,
    method: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    api_key: str | None = None,
) -> tuple[str, int]:
    """Exchange credentials for an access token via the Keycloak-style IAM endpoint.

    Returns (access_token, expires_in_seconds).
    """
    token_url = f"{iam_url.rstrip('/')}/auth/realms/{tenant}/protocol/openid-connect/token"

    if method == "client_credentials":
        if not client_id or not client_secret:
            raise CxApiError("Client ID and Client Secret are both required.")
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    elif method == "api_key":
        if not api_key:
            raise CxApiError("API key is required.")
        data = {
            "grant_type": "refresh_token",
            "client_id": _api_key_exchange_audience(),
            "refresh_token": api_key,
        }
    else:
        raise CxApiError(f"Unknown auth method: {method}")

    try:
        resp = requests.post(token_url, data=data, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise CxApiError(f"Could not reach IAM endpoint: {exc}") from exc

    if not resp.ok:
        raise CxApiError(
            f"Authentication failed ({resp.status_code}).",
            status_code=resp.status_code,
            body=resp.text,
        )

    payload = resp.json()
    access_token = payload.get("access_token")
    expires_in = payload.get("expires_in", 60)
    if not access_token:
        raise CxApiError("IAM response did not include an access_token.", body=resp.text)
    return access_token, expires_in


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _request(method: str, base_url: str, token: str, path: str, **kwargs) -> requests.Response:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        resp = requests.request(
            method, url, headers=_headers(token), timeout=REQUEST_TIMEOUT, **kwargs
        )
    except requests.RequestException as exc:
        raise CxApiError(f"Request to {url} failed: {exc}") from exc

    if not resp.ok:
        raise CxApiError(
            f"{method} {path} failed ({resp.status_code}).",
            status_code=resp.status_code,
            body=resp.text,
        )
    return resp


PAGE_SIZE = 100
MAX_PAGES = 200  # safety cap so a misbehaving API can't loop forever


def _unwrap_page(data) -> tuple[list, int | None]:
    """Returns (items, total_count) for either a bare list or a paginated
    envelope like {"presets": [...], "totalCount": N}."""
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        items = []
        for key in ("presets", "data", "items"):
            if key in data and isinstance(data[key], list):
                items = data[key]
                break
        total = None
        for key in ("totalCount", "total", "count"):
            if key in data and isinstance(data[key], int):
                total = data[key]
                break
        return items, total
    return [], None


def list_presets(base_url: str, token: str) -> list:
    """GET /api/preset-manager/sast/presets -> list of ALL preset summaries.

    The endpoint paginates (observed default page size of 10), so this pages
    through with offset/limit until a short page is returned or the reported
    total count is reached.
    """
    all_items = []
    offset = 0
    for _ in range(MAX_PAGES):
        resp = _request(
            "GET",
            base_url,
            token,
            "/api/preset-manager/sast/presets",
            params={"offset": offset, "limit": PAGE_SIZE},
        )
        items, total = _unwrap_page(resp.json())
        all_items.extend(items)

        if not items:
            break
        offset += len(items)
        if total is not None and offset >= total:
            break
        if len(items) < PAGE_SIZE:
            break

    return all_items


def get_preset(base_url: str, token: str, preset_id) -> dict:
    """GET /api/preset-manager/sast/presets/{id} -> full raw preset JSON.

    Confirmed (via Checkmarx's own Postman collection) that presets store
    their queries grouped by family with only numeric ids:
    "queries": [{"familyName": "Java", "queryIds": ["123", ...]}, ...] --
    no query name/category/severity is embedded here. That metadata comes
    from the query-families catalog (see list_query_families /
    list_queries_in_family below) and must be joined in separately.
    """
    resp = _request("GET", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}")
    return resp.json()


def list_query_families(base_url: str, token: str) -> list:
    """GET /api/preset-manager/sast/query-families -> list of family (language) names."""
    resp = _request("GET", base_url, token, "/api/preset-manager/sast/query-families")
    data = resp.json()
    if isinstance(data, dict):
        for key in ("families", "data", "items"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = []
    names = []
    for item in data:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("familyName")
            if name:
                names.append(name)
    return names


def _flatten_query_tree(nodes: list, family: str, category: str | None = None) -> list:
    """The query-families/{family}/queries response is a tree: each category
    node has a "title" (e.g. "Python_Medium_Threat") and a "children" array,
    which holds either leaf query nodes (with "key" + "title", e.g. "CSRF")
    or further nested category nodes. This flattens it into
    {"key", "title", "group", "severity"} dicts, one per leaf query."""
    flat = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        children = node.get("children")
        if isinstance(children, list) and children:
            flat.extend(_flatten_query_tree(children, family, node.get("title") or category))
            continue

        key = node.get("key") or node.get("id")
        if key is None:
            continue
        flat.append(
            {
                "key": key,
                "title": node.get("title") or node.get("name") or f"Query {key}",
                "group": category or family,
                "severity": node.get("severity"),
            }
        )
    return flat


def list_queries_in_family(base_url: str, token: str, family: str) -> list:
    """GET /api/preset-manager/sast/query-families/{family}/queries -> flat list
    of {"key", "title", "group", "severity"} dicts for that family/language,
    after flattening the category tree the endpoint actually returns. Each
    entry's "key" is the same identifier a preset's queryIds reference."""
    resp = _request(
        "GET",
        base_url,
        token,
        f"/api/preset-manager/sast/query-families/{quote(family, safe='')}/queries",
    )
    data = resp.json()
    if isinstance(data, dict):
        for key in ("queries", "data", "items"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = []
    return _flatten_query_tree(data, family)


def _preset_body(name: str, description: str | None, queries_by_family: dict) -> dict:
    """Shared body shape for creating/updating a preset: queries grouped by
    family with a plain list of queryIds, matching Checkmarx's own confirmed
    "Create Preset For Engine" request (POST .../presets)."""
    return {
        "name": name,
        "description": description or "",
        "queries": [
            {"familyName": family, "queryIds": [str(q) for q in query_ids]}
            for family, query_ids in queries_by_family.items()
        ],
    }


def _parse_preset_response(resp: requests.Response) -> dict:
    if resp.text:
        try:
            return resp.json()
        except ValueError:
            return {"status": "ok", "raw": resp.text}
    return {"status": "ok"}


def create_preset(
    base_url: str, token: str, name: str, description: str | None, queries_by_family: dict
) -> dict:
    """POST /api/preset-manager/sast/presets -- confirmed shape (see _preset_body)."""
    body = _preset_body(name, description, queries_by_family)
    resp = _request("POST", base_url, token, "/api/preset-manager/sast/presets", json=body)
    return _parse_preset_response(resp)


def update_preset(
    base_url: str,
    token: str,
    preset_id,
    name: str,
    description: str | None,
    queries_by_family: dict,
) -> dict:
    """PATCH /api/preset-manager/sast/presets/{id} (see _preset_body)."""
    body = _preset_body(name, description, queries_by_family)
    resp = _request(
        "PATCH", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}", json=body
    )
    return _parse_preset_response(resp)


def delete_preset(base_url: str, token: str, preset_id) -> None:
    """DELETE /api/preset-manager/sast/presets/{id}.

    No delete example appears in Checkmarx's own reference Postman collection
    (only list/get/create) -- this follows the same base path with the
    conventional REST verb. Confirm against a real tenant and adjust here if
    the verb or path differs.
    """
    _request("DELETE", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}")
