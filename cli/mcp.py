# cli/mcp.py — Minimal CLI for HTB MCP
import os, sys, json, asyncio, argparse

# 🛠️ PATCH SYS.PATH EARLY
CURRENT_FILE = os.path.abspath(__file__)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(CURRENT_FILE), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.mcp_client import load_cfg, HtbMcpClient

def _print(obj, as_json: bool):
    if as_json:
        print(json.dumps(obj, indent=2))
    else:
        if isinstance(obj, dict):
            print(json.dumps(obj, indent=2))
        else:
            print(obj)

async def run(args):
    url, tok = load_cfg()
    c = HtbMcpClient(url, tok)
    await c.connect()
    try:
        if args.cmd == "list-events":
            res = await c.list_events()
            if args.json: return _print(res, True)
            for e in res["data"]:
                print(f"{e['id']:>6}  {e['title']}")
        elif args.cmd == "my-teams":
            res = await c.my_teams()
            if args.json: return _print(res, True)
            for t in res["teams"]:
                print(f"{t['id']:>6}  {t['name']}")
        elif args.cmd == "join":
            out = await c.join_ctf(args.ctf, args.team, bool(args.consent), args.password or "")
            return _print(out, args.json)
        elif args.cmd == "challenges":
            ctf = await c.get_ctf(args.ctf)
            if args.json: return _print(ctf, True)
            for ch in ctf["challenges"]:
                print(f"{ch['id']:>6}  {ch['name']}")
        elif args.cmd == "pick-event":
            res = await c.list_events()
            needle = args.name.lower()
            match = next((e for e in res["data"] if needle in e["title"].lower()), None)
            if not match:
                print(f"[!] No event title contains: {args.name}")
            else:
                _print(match, args.json)
        elif args.cmd == "pick-challenge":
            ctf = await c.get_ctf(args.ctf)
            needle = args.name.lower()
            match = next((ch for ch in ctf["challenges"] if needle in ch["name"].lower()), None)
            if not match:
                print(f"[!] No challenge name contains: {args.name}")
            else:
                _print(match, args.json)
        elif args.cmd == "start":
            out = await c.start_container(args.challenge)
            return _print(out, args.json)
        elif args.cmd == "download":
            out = await c.get_download_link(args.challenge)
            if args.json: return _print(out, True)
            print(out.get("url") or out)
        elif args.cmd == "submit":
            out = await c.submit_flag(args.challenge, args.flag)
            return _print(out, args.json)
        else:
            print("Unknown command")
    finally:
        await c.close()

def main():
    p = argparse.ArgumentParser(prog="charlotte mcp", description="CHARLOTTE ↔ HTB MCP")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-events")
    sub.add_parser("my-teams")

    pj = sub.add_parser("join")
    pj.add_argument("--ctf", type=int, required=True)
    pj.add_argument("--team", type=int, required=True)
    pj.add_argument("--consent", action="store_true", default=True)
    pj.add_argument("--password", type=str, default="")

    pc = sub.add_parser("challenges")
    pc.add_argument("--ctf", type=int, required=True)

    pe = sub.add_parser("pick-event")
    pe.add_argument("--name", required=True, help="substring match on event title")

    pch = sub.add_parser("pick-challenge")
    pch.add_argument("--ctf", type=int, required=True)
    pch.add_argument("--name", required=True, help="substring match on challenge name")

    ps = sub.add_parser("start")
    ps.add_argument("--challenge", type=int, required=True)

    pd = sub.add_parser("download")
    pd.add_argument("--challenge", type=int, required=True)

    psub = sub.add_parser("submit")
    psub.add_argument("--challenge", type=int, required=True)
    psub.add_argument("--flag", type=str, required=True)

    args = p.parse_args()
    asyncio.run(run(args))

if __name__ == "__main__":
    main()
# cli/mcp.py — Minimal CLI for HTB MCP