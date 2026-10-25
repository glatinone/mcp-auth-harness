"""Builds results.json from the raw pytest -v outputs."""
import json, re
REQ = {
 "test_00_control_valid_token_works": "CONTROL (valid token must work)",
 "test_01_no_token_401_with_resource_metadata": "401 + WWW-Authenticate resource_metadata (RFC 9728 s5.1)",
 "test_02_prm_endpoint_correct": "PRM served, authorization_servers present (RFC 9728)",
 "test_03_expired_token_401": "expired token -> 401",
 "test_04_wrong_audience_rejected": "audience validation (RFC 8707 / MCP security considerations)",
 "test_05_wrong_issuer_rejected": "token validation per OAuth 2.1 s5.2: issuer",
 "test_06_bad_signature_and_alg_none_rejected": "token validation per OAuth 2.1 s5.2: signature / alg none",
 "test_07_insufficient_scope_403": "403 insufficient_scope + scope + resource_metadata",
 "test_08_tools_list_not_anonymous": "auth on every request (no anonymous tools/list)",
 "test_09_no_token_passthrough": "MUST NOT pass through client token downstream",
 "test_10_token_in_query_string_rejected": "access token MUST NOT be in URI query string",
}
def parse(p):
    out = {}
    for line in open(p, encoding="utf-8"):
        m = re.match(r"tests/test_auth.py::(\w+) (PASSED|FAILED)", line)
        if m: out[m.group(1)] = "pass" if m.group(2) == "PASSED" else "fail"
    return out
n, h = parse("results-naive.txt"), parse("results-hardened.txt")
rows = [{"test": t, "requirement": r, "naive": n[t], "hardened": h[t], **({"control": True} if t.startswith("test_00") else {})} for t, r in REQ.items()]
json.dump(rows, open("results.json", "w"), indent=2)
spec = [r for r in rows if not r.get("control")]
print({"naive_pass": sum(r["naive"]=="pass" for r in spec), "hardened_pass": sum(r["hardened"]=="pass" for r in spec), "total": len(spec)})
