"""Fake downstream notes API. Records the Authorization header of every request so the harness
can detect token passthrough. Local test fixture."""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Downstream:
    def __init__(self):
        self.seen = []  # list of (method, path, authorization header or None)
        self.notes = {"1": "buy milk", "2": "call bob"}
        self.httpd = None

    def start(self, port=0):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

            def do_GET(self):
                outer.seen.append(("GET", self.path, self.headers.get("Authorization")))
                self._reply(200, outer.notes)

            def do_DELETE(self):
                outer.seen.append(("DELETE", self.path, self.headers.get("Authorization")))
                outer.notes.pop(self.path.rsplit("/", 1)[-1], None)
                self._reply(200, {"deleted": True})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()
