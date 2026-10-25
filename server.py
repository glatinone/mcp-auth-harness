"""Minimal MCP (2026-07-28 stateless Streamable HTTP) server with two tools and two auth modes.

--mode naive     deliberately naive baseline (see README for the exact list of mistakes)
--mode hardened  implements the 2026-07-28 authorization requirements this harness tests

The official `mcp` SDK was not used: the 2026-07-28 revision removed initialize/sessions and
requires per-request _meta + Mcp-Method headers; this is a minimal JSON-RPC implementation of
tools/list and tools/call only. Binds 127.0.0.1 only.
"""
import argparse, json, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import jwt
from jwt import PyJWKClient

TOOLS = [
    {"name": "read_notes", "description": "Read all notes (scope notes:read)",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "delete_note", "description": "Delete a note (scope notes:write)",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
]
TOOL_SCOPE = {"read_notes": "notes:read", "delete_note": "notes:write"}


class Cfg:  # filled in main()
    mode = "naive"; port = 0; as_url = ""; downstream = ""; downstream_token = ""
    jwks = None

    @property
    def resource(self):
        return f"http://127.0.0.1:{self.port}/mcp"

    @property
    def prm_url(self):
        return f"http://127.0.0.1:{self.port}/.well-known/oauth-protected-resource/mcp"


cfg = Cfg()


def call_downstream(method, path, authorization):
    req = urllib.request.Request(cfg.downstream + path, method=method)
    if authorization:
        req.add_header("Authorization", authorization)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


class AuthError(Exception):
    def __init__(self, status, error=None, scope=None, desc=None):
        self.status, self.error, self.scope, self.desc = status, error, scope, desc


def www_authenticate(error=None, scope=None, desc=None):
    parts = [f'resource_metadata="{cfg.prm_url}"']
    if scope:
        parts.append(f'scope="{scope}"')
    if error:
        parts.append(f'error="{error}"')
    if desc:
        parts.append(f'error_description="{desc}"')
    return "Bearer " + ", ".join(parts)


def signing_key(token):
    return cfg.jwks.get_signing_key_from_jwt(token).key


# ---------------------------------------------------------------- NAIVE auth
def naive_authenticate(handler, method, tool):
    """Typical quickstart: bearer token is decoded; signature checked, nothing else.
    - tools/list needs no token at all
    - token accepted from Authorization header OR ?access_token= query string
    - no aud, iss or scope validation (exp is checked only because PyJWT does so by default)
    - bare 401, no WWW-Authenticate, no PRM endpoint
    """
    if method == "tools/list":
        return None, None
    token = None
    h = handler.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        token = h[7:]
    else:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
        token = (q.get("access_token") or [None])[0]
    if not token:
        raise AuthError(401)
    try:
        claims = jwt.decode(token, signing_key(token), algorithms=["RS256"],
                            options={"verify_aud": False})
    except Exception:
        raise AuthError(401)
    return claims, token


# ------------------------------------------------------------- HARDENED auth
def hardened_authenticate(handler, method, tool):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
    if "access_token" in q:
        # Spec: access tokens MUST NOT be included in the URI query string. Reject outright.
        raise AuthError(401, "invalid_request", desc="token in query string not allowed")
    h = handler.headers.get("Authorization", "")
    if not h.lower().startswith("bearer ") or not h[7:].strip():
        raise AuthError(401)  # challenge carries resource_metadata, no error code (RFC 6750 3.1)
    token = h[7:].strip()
    try:
        claims = jwt.decode(
            token, signing_key(token),
            algorithms=["RS256"],                      # never trust header alg; rejects "none"
            audience=cfg.resource,                     # MUST validate audience (RFC 8707)
            issuer=cfg.as_url,                         # token must come from our AS
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as e:
        raise AuthError(401, "invalid_token", desc=type(e).__name__)
    if method == "tools/call":
        need = TOOL_SCOPE.get(tool)
        have = set(str(claims.get("scope", "")).split())
        if need and need not in have:
            raise AuthError(403, "insufficient_scope", scope=need,
                            desc=f"{need} required for this operation")
    return claims, token


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, headers=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if cfg.mode == "hardened" and path in ("/.well-known/oauth-protected-resource/mcp",
                                               "/.well-known/oauth-protected-resource"):
            return self._send(200, {
                "resource": cfg.resource, "authorization_servers": [cfg.as_url],
                "scopes_supported": ["notes:read", "notes:write"],
                "bearer_methods_supported": ["header"]})
        if path == "/mcp":
            return self._send(405, {"error": "GET stream removed in 2026-07-28"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path != "/mcp":
            return self._send(404, {"error": "not found"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        rid, method = body.get("id"), body.get("method")
        params = body.get("params", {}) or {}
        tool = params.get("name") if method == "tools/call" else None

        # --- transport-level checks (both modes) ---
        meta = params.get("_meta", {})
        if (self.headers.get("MCP-Protocol-Version") != meta.get("io.modelcontextprotocol/protocolVersion")
                or self.headers.get("Mcp-Method") != method):
            return self._send(400, {"jsonrpc": "2.0", "id": rid,
                                    "error": {"code": -32020, "message": "HeaderMismatch"}})

        # --- authorization ---
        auth = naive_authenticate if cfg.mode == "naive" else hardened_authenticate
        try:
            claims, token = auth(self, method, tool)
        except AuthError as e:
            hdrs = {}
            if cfg.mode == "hardened":
                hdrs["WWW-Authenticate"] = www_authenticate(e.error, e.scope, e.desc)
            return self._send(e.status, {"error": e.error or "unauthorized"}, hdrs)

        # --- methods ---
        if method == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        if method == "tools/call":
            # naive forwards the caller's token (passthrough); hardened uses its own credential.
            ds_auth = f"Bearer {token}" if cfg.mode == "naive" else f"Bearer {cfg.downstream_token}"
            args = params.get("arguments", {}) or {}
            if tool == "read_notes":
                out = call_downstream("GET", "/notes", ds_auth)
            elif tool == "delete_note":
                out = call_downstream("DELETE", f"/notes/{args.get('id')}", ds_auth)
            else:
                return self._send(200, {"jsonrpc": "2.0", "id": rid,
                                        "error": {"code": -32602, "message": "unknown tool"}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": json.dumps(out)}]}})
        self._send(404, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["naive", "hardened"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--as-url", required=True)
    ap.add_argument("--downstream", required=True)
    ap.add_argument("--downstream-token", default="mcp-server-own-credential")
    a = ap.parse_args()
    cfg.mode, cfg.port, cfg.as_url, cfg.downstream, cfg.downstream_token = (
        a.mode, a.port, a.as_url, a.downstream, a.downstream_token)
    cfg.jwks = PyJWKClient(a.as_url + "/jwks.json")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
