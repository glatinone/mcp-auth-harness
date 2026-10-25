"""Tiny local authorization-server stub: mints signed JWTs (RS256) and serves JWKS + RFC 8414 metadata.
Local test fixture only. Not a real OAuth AS (no /authorize, /token flows)."""
import base64, json, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class AuthServerStub:
    def __init__(self):
        self.key = new_key()
        self.kid = "stub-key-1"
        self.issuer = None  # set once bound
        self.httpd = None

    # ---- token minting -------------------------------------------------
    def mint(self, aud, scope="", exp_in=300, iss=None, sub="alice", key=None, kid=None):
        now = int(time.time())
        claims = {"iss": iss or self.issuer, "sub": sub, "aud": aud, "scope": scope,
                  "iat": now, "exp": now + exp_in, "jti": str(uuid.uuid4())}
        return jwt.encode(claims, key or self.key, algorithm="RS256",
                          headers={"kid": kid or self.kid})

    def mint_alg_none(self, aud, scope="notes:read notes:write"):
        now = int(time.time())
        header = {"alg": "none", "typ": "JWT", "kid": self.kid}
        claims = {"iss": self.issuer, "sub": "mallory", "aud": aud, "scope": scope,
                  "iat": now, "exp": now + 300}
        return _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode()) + "."

    # ---- http ----------------------------------------------------------
    def jwks(self):
        pub = self.key.public_key().public_numbers()
        n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
        e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
        return {"keys": [{"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                          "n": _b64(n), "e": _b64(e)}]}

    def start(self, port=0):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/jwks.json":
                    body = outer.jwks()
                elif self.path.startswith("/.well-known/oauth-authorization-server"):
                    body = {"issuer": outer.issuer, "jwks_uri": outer.issuer + "/jwks.json",
                            "code_challenge_methods_supported": ["S256"]}
                else:
                    self.send_response(404); self.end_headers(); return
                data = json.dumps(body).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.issuer

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
