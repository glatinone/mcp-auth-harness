# Research: MCP 2026-07-28 authorization for HTTP servers

Fetched 2026-10-24 via WebFetch (content is passed through a summarising model for the blogs; spec pages returned near-verbatim text). I did not search for additional Oct 2026 commentary; no Oct 2026-dated source was consulted. Spec pages carry no visible date, only the revision id 2026-07-28.

## Sources

| Source | URL | Date | Use |
|---|---|---|---|
| MCP spec: Authorization | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization | revision 2026-07-28 (page undated) | primary |
| MCP spec: Authorization Server Discovery | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery | rev 2026-07-28 | primary |
| MCP spec: Authorization Security Considerations | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations | rev 2026-07-28 | primary |
| MCP spec: Streamable HTTP transport | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http | rev 2026-07-28 | primary |
| MCP Security Best Practices | https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices | rev 2026-07-28 | primary |
| WorkOS blog | https://workos.com/blog/mcp-2026-spec-agent-authentication | 2026-06-18 (as reported by fetch summary) | secondary, summary only |
| Claude blog | https://claude.com/it/blog/bringing-mcp-2026-07-28-to-claude | 2026-07-28 (as reported by fetch summary) | secondary, summary only |

## Requirements tested (exact lines) -- CONFIRMED from spec text

- R1 (discovery, 401): "MCP servers **MUST** implement one of the following discovery mechanisms ... 1. **WWW-Authenticate Header**: Include the resource metadata URL in the `WWW-Authenticate` HTTP header under `resource_metadata` when returning `401 Unauthorized` responses, as described in RFC9728 Section 5.1. 2. **Well-Known URI** ..." (Authorization Server Discovery). NOTE: the spec says "one of" the two, so a server with only the well-known URI is technically conformant; the harness tests both because it is what clients rely on and the spec's own example 401 includes `resource_metadata`.
- R2 (PRM): "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728)." and "The Protected Resource Metadata document returned by the MCP server **MUST** include the `authorization_servers` field containing at least one authorization server."
- R3 (expired): "Invalid or expired tokens **MUST** receive a HTTP 401 response." (Authorization, Token Handling)
- R4 (audience): "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2." and "MCP servers **MUST** only accept tokens specifically intended for themselves and **MUST** reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient of the token."
- R5/R6 (issuer, signature): "MCP servers, acting in their role as an OAuth 2.1 resource server, **MUST** validate access tokens as described in OAuth 2.1 Section 5.2." The spec does not itself spell out issuer or alg=none; those checks come from the referenced OAuth 2.1 draft section (not fetched by me) and general JWT practice. UNCLEAR: exact wording of OAuth 2.1 s5.2 not read.
- R7 (scope): "When a client makes a request with an access token with insufficient scope during runtime operations, the server **SHOULD** respond with: `HTTP 403 Forbidden` ... `WWW-Authenticate` header with the `Bearer` scheme and additional parameters: `error="insufficient_scope"`, `scope="required_scope1 required_scope2"`, `resource_metadata`". (SHOULD, not MUST. Error table: "403 Forbidden: Invalid scopes or insufficient permissions", servers MUST return appropriate status codes.)
- R8 (no anonymous tools/list): "Note that authorization **MUST** be included in every HTTP request from client to server." (this is a client requirement) and "Servers **SHOULD** implement proper authentication for all connections." (Streamable HTTP). Also "Authorization is **OPTIONAL** for MCP implementations. When supported: Implementations using an HTTP-based transport **SHOULD** conform to this specification." UNCLEAR/honest caveat: the spec does not say a server MUST reject anonymous tools/list; a server may legitimately expose some methods publicly. Test 08 encodes a policy reading (SHOULD authenticate all connections), not a hard MUST.
- R9 (passthrough): "The MCP server **MUST NOT** pass through the token it received from the MCP client." (Security Considerations, Access Token Privilege Restriction); also "MCP servers **MUST NOT** accept or transit any other tokens."
- R10 (query string): "Access tokens **MUST NOT** be included in the URI query string". (Strictly this is a client requirement; the server-side reading "reject it" is an inference.)

## Other 2026-07-28 facts that shaped the harness -- CONFIRMED

- Stateless core: Streamable HTTP "Removal of protocol-level sessions", "Removal of the GET stream endpoint"; the `initialize` handshake is gone. Every request carries `_meta.io.modelcontextprotocol/protocolVersion` etc. in the body and MUST carry `MCP-Protocol-Version` and `Mcp-Method` headers (+ `Mcp-Name` for tools/call). Mismatch => 400 with JSON-RPC error -32020 HeaderMismatch. The harness server implements these checks; its client sends these headers. Consequence: the harness does not do `initialize`.
- Streamable HTTP: "Servers **MUST** validate the `Origin` header ... If present and invalid, ... HTTP 403"; "servers **SHOULD** bind only to localhost (127.0.0.1)". Binding is done; Origin validation is NOT implemented or tested in this harness.
- WWW-Authenticate `scope` parameter on 401: "Servers **SHOULD** include a `scope` parameter" (scope selection strategy). Not tested.
- Issuer verification (RFC 9207) and RFC 8707 `resource` are client-side/AS-side MUSTs; not testable against a resource server and not tested.

## Secondary sources (unverified quotes; summaries only)

- WorkOS: auth hardening incl. mandatory PRM (RFC 9728), deprecation of DCR in favour of Client ID Metadata Documents, issuer verification, RFC 8707 enforcement. Consistent with the spec pages above.
- Claude blog: stateless core; enterprise-managed authentication. No normative content used.
- I did not try the official `mcp` Python SDK. Whether it supports 2026-07-28 stateless HTTP is UNCLEAR; I wrote a minimal JSON-RPC server instead.
