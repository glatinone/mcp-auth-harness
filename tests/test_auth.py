"""Auth harness for MCP 2026-07-28. Each test docstring starts with the spec requirement (R-id)."""
import re
import httpx
from conftest import rpc

BOTH = "notes:read notes:write"


def tok(env, **kw):
    kw.setdefault("aud", env.resource)
    kw.setdefault("scope", BOTH)
    return env.as_.mint(**kw)


def test_00_control_valid_token_works(env):
    """CONTROL (not a spec requirement): a correct token must succeed, so rejections below are meaningful."""
    r = rpc(env, "tools/list", token=tok(env))
    assert r.status_code == 200 and len(r.json()["result"]["tools"]) == 2
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}}, token=tok(env))
    assert r.status_code == 200 and "buy milk" in r.text


def test_01_no_token_401_with_resource_metadata(env):
    """R1: 'Include the resource metadata URL in the WWW-Authenticate HTTP header under resource_metadata
    when returning 401 Unauthorized responses'."""
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}})
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert wa.lower().startswith("bearer") and re.search(r'resource_metadata="https?://[^"]+"', wa), wa


def test_02_prm_endpoint_correct(env):
    """R2: 'MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)... MUST include the
    authorization_servers field containing at least one authorization server.'"""
    r = httpx.get(env.base + "/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    doc = r.json()
    assert doc["resource"] == env.resource
    assert env.issuer in doc["authorization_servers"]


def test_03_expired_token_401(env):
    """R3: 'Invalid or expired tokens MUST receive a HTTP 401 response.'"""
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}}, token=tok(env, exp_in=-60))
    assert r.status_code == 401


def test_04_wrong_audience_rejected(env):
    """R4: 'MCP servers MUST validate that access tokens were issued specifically for them as the intended
    audience' / 'MUST reject tokens that do not include them in the audience claim'."""
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}},
            token=tok(env, aud="http://127.0.0.1:1/some-other-mcp"))
    assert r.status_code == 401


def test_05_wrong_issuer_rejected(env):
    """R5: 'MCP servers MUST validate access tokens as described in OAuth 2.1 Section 5.2' (issuer must be
    the server's authorization server, from PRM authorization_servers)."""
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}},
            token=tok(env, iss="https://evil.example"))
    assert r.status_code == 401


def test_06_bad_signature_and_alg_none_rejected(env):
    """R6: same MUST as R5 (OAuth 2.1 5.2 token validation): forged signature and alg=none must fail."""
    forged = tok(env, key=env.rogue_key)  # same kid, different private key
    unsigned = env.as_.mint_alg_none(env.resource)
    for t in (forged, unsigned):
        r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}}, token=t)
        assert r.status_code == 401, t[:20]


def test_07_insufficient_scope_403(env):
    """R7: 'the server SHOULD respond with HTTP 403 Forbidden ... WWW-Authenticate header ... error="insufficient_scope"
    ... scope="required_scope"'."""
    r = rpc(env, "tools/call", {"name": "delete_note", "arguments": {"id": "2"}},
            token=tok(env, scope="notes:read"))
    assert r.status_code == 403
    wa = r.headers.get("WWW-Authenticate", "")
    assert 'error="insufficient_scope"' in wa and 'scope="notes:write"' in wa, wa


def test_08_tools_list_not_anonymous(env):
    """R8: 'Servers SHOULD implement proper authentication for all connections' and 'authorization MUST be
    included in every HTTP request from client to server' -> anonymous tools/list gets 401."""
    r = rpc(env, "tools/list")
    assert r.status_code == 401


def test_09_no_token_passthrough(env):
    """R9: 'The MCP server MUST NOT pass through the token it received from the MCP client.'"""
    t = tok(env)
    env.ds.seen.clear()
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}}, token=t)
    assert r.status_code == 200
    assert env.ds.seen, "downstream was not called"
    assert all(a != f"Bearer {t}" for _, _, a in env.ds.seen), env.ds.seen


def test_10_token_in_query_string_rejected(env):
    """R10: 'Access tokens MUST NOT be included in the URI query string.' (token only in query, none in header)"""
    r = rpc(env, "tools/call", {"name": "read_notes", "arguments": {}}, query=f"?access_token={tok(env)}")
    assert r.status_code in (400, 401)
