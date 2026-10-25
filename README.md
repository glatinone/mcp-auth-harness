# mcp-auth-harness

A small pytest harness that checks an HTTP MCP server against the authorization requirements of the MCP 2026-07-28 revision, plus two reference servers: a deliberately naive one and a hardened one. See `research.md` for the exact spec lines and `results.json` for the scoreboard. Write-up: [I wrote an MCP server auth test harness for the 2026-07-28 spec](https://www.kielltampubolon.id/writing/i-wrote-an-mcp-server-auth-test-harness-for-the-2026-07-28-spec-here-is-what-broke-first/).

## Results

| | requirement tests passed (of 10) |
|---|---|
| naive | 2 |
| hardened | 10 |

The control test (a valid token works) passes on both. Per-test detail is in `results.json`; raw pytest output in `results-naive.txt` and `results-hardened.txt`.

## Files

- `as_stub.py`: local authorization-server stub. Mints RS256 JWTs with configurable aud/scope/exp/iss, serves `/jwks.json` and RFC 8414 metadata. Fixture only; no real OAuth flows.
- `downstream.py`: fake notes API that records every `Authorization` header it receives.
- `server.py`: minimal MCP 2026-07-28 (stateless, no `initialize`) Streamable HTTP server. Tools: `read_notes` (notes:read), `delete_note` (notes:write). `--mode naive|hardened`.
- `tests/`: 1 control test + 10 requirement tests.
- `make_results.py`: builds `results.json` from the raw outputs.

## Run

```bash
uv sync
MCP_MODE=naive    uv run pytest tests -v --no-header > results-naive.txt
MCP_MODE=hardened uv run pytest tests -v --no-header > results-hardened.txt
uv run python make_results.py
```

(PowerShell: `$env:MCP_MODE="naive"; uv run pytest tests -v`.) The fixtures start the AS stub and fake downstream in-process and launch `server.py` as a subprocess on free ports; everything binds to 127.0.0.1. Nothing leaves the machine.

To run the server by hand: `uv run python server.py --mode hardened --port 8000 --as-url http://127.0.0.1:9000 --downstream http://127.0.0.1:9001`.

## What the naive baseline does (exactly)

It is a deliberately naive baseline I wrote to represent common quickstart shortcuts. It is not a model of any real product.

1. `tools/list` requires no token.
2. For `tools/call`: token read from `Authorization: Bearer` or, failing that, from an `?access_token=` query parameter.
3. Token verified with `jwt.decode(token, jwks_key, algorithms=["RS256"], options={"verify_aud": False})`: signature checked; `exp` checked only because PyJWT does so by default; no audience check, no issuer check, no scope check.
4. Failures return a bare `401` with no `WWW-Authenticate`; no Protected Resource Metadata endpoint (404).
5. The caller's bearer token is forwarded verbatim to the downstream API.

Note that naive pins `algorithms=["RS256"]` and verifies signatures, so forged-signature and `alg: none` tokens are rejected there by library usage, not by design effort.

## What hardened does

PRM at `/.well-known/oauth-protected-resource[/mcp]`; 401 with `WWW-Authenticate: Bearer resource_metadata="..."`; full validation (RS256 only, `aud` == this server's resource URI, `iss` == the AS, `exp/iss/aud` required); per-tool scope check returning 403 `insufficient_scope` with `scope` and `resource_metadata`; all methods need auth; query-string tokens rejected; downstream calls use the server's own credential.

## Limitations

- Local stub AS; no authorization-code flow, no PKCE, no DCR/CIMD, no refresh tokens. Clients' side of the spec (resource parameter, RFC 9207 iss validation) is not tested.
- The naive baseline is intentionally weak; the scoreboard measures my strawman, not real-world servers or products.
- Hardened is not a complete production server: no Origin validation (a spec MUST for Streamable HTTP, not tested), no rate limiting, no key rotation/JWKS cache policy, HTTP not HTTPS (loopback only).
- Test 08 (anonymous tools/list) and test 10 (query token) encode a strict reading; the spec text for those is client-side or SHOULD-level (see research.md). Test 10 is weak for hardened: the request carries no header, so a 401 would also result from a missing token; hardened additionally rejects the query token explicitly.
- Minimal hand-written JSON-RPC rather than the official `mcp` SDK (not tried).
- Tested on Python 3.12 and 3.14 (Windows); both give the same results.
- The tests are deterministic; each mode was run several times with identical results.
