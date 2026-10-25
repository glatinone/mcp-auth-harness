import os, socket, subprocess, sys, time
import httpx, pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from as_stub import AuthServerStub, new_key  # noqa: E402
from downstream import Downstream  # noqa: E402

MODE = os.environ.get("MCP_MODE", "hardened")


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Env:
    pass


@pytest.fixture(scope="session")
def env():
    e = Env()
    e.mode = MODE
    e.as_ = AuthServerStub(); e.issuer = e.as_.start()
    e.ds = Downstream(); ds_url = e.ds.start()
    port = free_port()
    e.base = f"http://127.0.0.1:{port}"
    e.resource = e.base + "/mcp"
    e.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--mode", MODE,
                               "--port", str(port), "--as-url", e.issuer, "--downstream", ds_url],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
        except OSError:
            time.sleep(0.1)
    e.rogue_key = new_key()
    yield e
    e.proc.terminate(); e.as_.stop(); e.ds.stop()


def rpc(env, method, params=None, token=None, query="", extra_headers=None):
    params = dict(params or {})
    params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                       "io.modelcontextprotocol/clientInfo": {"name": "harness", "version": "0"},
                       "io.modelcontextprotocol/clientCapabilities": {}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
    if method == "tools/call":
        headers["Mcp-Name"] = params["name"]
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(extra_headers or {})
    return httpx.post(env.resource + query, headers=headers,
                      json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10)
