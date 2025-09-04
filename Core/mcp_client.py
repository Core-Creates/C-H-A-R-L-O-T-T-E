# core/mcp_client.py
import asyncio, json, os
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession
from mcp.client.sse import sse_client

# -------------------------------------------------------
# Load .env if present (ASCII/UTF-8, no BOM; only KEY=VALUE and # comments)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

SETTINGS_FILE = Path("data/user_settings.json")

def _cfg_from_json():
    if not SETTINGS_FILE.exists():
        return None, None
    data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    htb = (data.get("mcp") or {}).get("htb") or {}
    return htb.get("url"), htb.get("token")

def load_cfg():
    # Priority: env > user_settings.json
    env_url = os.getenv("HTB_MCP_URL")
    env_tok = os.getenv("HTB_MCP_TOKEN")
    json_url, json_tok = (None, None)
    if not env_url or not env_tok:
        json_url, json_tok = _cfg_from_json()

    url = env_url or json_url
    token = env_tok or json_tok

    # Helpful source prints
    src_url = "env" if env_url else ("json" if json_url else "missing")
    src_tok = "env" if env_tok else ("json" if json_tok else "missing")
    print(f"[mcp] URL source: {src_url}")
    print(f"[mcp] TOK source: {src_tok}")

    problems = []
    if not url:
        problems.append("HTB_MCP_URL is missing. Set it in .env or data/user_settings.json.")
    if not token:
        problems.append("HTB_MCP_TOKEN is missing. Put your MCP token in .env or user_settings.json.")
    if problems:
        raise RuntimeError("\n".join(problems))

    if not url.startswith("http"):
        raise RuntimeError(f"HTB_MCP_URL looks wrong: {url}")

    # Hard fail if someone passed only the host (prevents 404s)
    base_hosts = {"https://mcp.ai.hackthebox.com", "https://mcp.ai.hackthebox.com/"}
    if url.rstrip("/") in base_hosts:
        raise RuntimeError(
            "HTB_MCP_URL must be the SSE endpoint, e.g. https://mcp.ai.hackthebox.com/v1/ctf/sse/"
        )

    return url, token

def _unwrap_call_result(res):
    """Return a plain dict/string from CallToolResult; fallback to res."""
    blocks = getattr(res, "content", []) or []
    for b in blocks:
        t = getattr(b, "type", None)
        if t == "json" and hasattr(b, "json"):
            return b.json
        if t == "text" and hasattr(b, "text"):
            try:
                return json.loads(b.text)
            except Exception:
                return b.text
    return res

class HtbMcpClient:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.exit = AsyncExitStack()
        self.session: ClientSession | None = None

    async def connect(self):
        transport = await self.exit.enter_async_context(
            sse_client(
                url=self.url,
                headers={"Authorization": f"Bearer {self.token}"},
                # timeout=30.0, verify=True,
            )
        )
        r, w = transport
        self.session = await self.exit.enter_async_context(ClientSession(r, w))
        await self.session.initialize()

    async def list_tools(self):
        tools = (await self.session.list_tools()).tools
        return [(t.name, t.description) for t in tools]

    async def call(self, tool_name: str, args: dict):
        res = await self.session.call_tool(tool_name, args)
        return _unwrap_call_result(res)

    # ---------------- Convenience wrappers ----------------
    async def my_teams(self):
        return await self.call("retrieve_my_teams", {})

    async def list_events(self):
        return await self.call("list_ctf_events", {})

    async def join_ctf(self, ctf_id: int, team_id: int, consent: bool = True, ctf_password: str = ""):
        return await self.call("join_ctf_event", {
            "ctf_id": ctf_id, "team_id": team_id, "consent": consent, "ctf_password": ctf_password
        })

    async def get_ctf(self, ctf_id: int):
        return await self.call("retrieve_ctf", {"ctf_id": ctf_id})

    async def start_container(self, challenge_id: int):
        return await self.call("start_container", {"challenge_id": challenge_id})

    async def get_download_link(self, challenge_id: int):
        return await self.call("get_download_link", {"challenge_id": challenge_id})

    async def submit_flag(self, challenge_id: int, flag: str):
        return await self.call("submit_flag", {"challenge_id": challenge_id, "flag": flag})

    async def close(self):
        await self.exit.aclose()

async def demo():
    url, token = load_cfg()
    print(f"[mcp] Connecting to: {url}")
    c = HtbMcpClient(url, token)
    try:
        await c.connect()
        tools = await c.list_tools()
        print("[mcp] Tools:")
        for name, desc in tools:
            print(f" - {name}: {desc}")
    finally:
        await c.close()

if __name__ == "__main__":
    asyncio.run(demo())
