# cli/mcp_htb.py — Minimal CLI for HTB MCP
import os, sys, json, asyncio, argparse

# 🛠️ PATCH SYS.PATH EARLY
CURRENT_FILE = os.path.abspath(__file__)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(CURRENT_FILE), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.mcp_client import load_cfg, HtbMcpClient

# Accept either {"data":[...]} or [...] or {"events":[...]}
def _as_events(res):
    if isinstance(res, dict) and "data" in res and isinstance(res["data"], list):
        return res["data"]
    if isinstance(res, list):
        return res
    # last resort: maybe {"events":[...]}
    if isinstance(res, dict) and "events" in res and isinstance(res["events"], list):
        return res["events"]
    return []

# Accept either {"teams":[...]} or [...]
def _as_teams(res):
    if isinstance(res, dict) and "teams" in res and isinstance(res["teams"], list):
        return res["teams"]
    if isinstance(res, list):
        return res
    return []

# Accept only dict with "challenges" key
def _as_challenges(ctf):
    if isinstance(ctf, dict) and "challenges" in ctf and isinstance(ctf["challenges"], list):
        return ctf["challenges"]
    return []

# Pretty-print or raw JSON
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
        # Handles commands based on args 

        # checks if the command argument is list-events
        if args.cmd == "list-events":
            res = await c.list_events()
            if args.json: 
                return _print(res, True)
            for e in _as_events(res):
                title = e.get("title") or e.get("name") or "(no title)"
                print(f"{e.get('id', '?'):>6}  {title}")

        # checks if the command arg is my-teams or list-teams alias
        elif args.cmd in ("my-teams", "list-teams"):
            res = await c.my_teams()
            if args.json: 
                return _print(res, True)
            for t in _as_teams(res):
                print(f"{t.get('id','?'):>6}  {t.get('name','(no name)')}")
        
        # checks if the command arg is join
        elif args.cmd == "join":
            out = await c.join_ctf(args.ctf, args.team, bool(args.consent), args.password or "")
            return _print(out, args.json)
        
        # checks if the command arg is challenges
        elif args.cmd == "challenges":
            ctf = await c.get_ctf(args.ctf)
            if args.json: 
                return _print(ctf, True)
            for ch in _as_challenges(ctf):
                print(f"{ch.get('id','?'):>6}  {ch.get('name','(no name)')}")

        # checks if the command arg is pick-event
        elif args.cmd == "pick-event":
            res = await c.list_events()
            needle = args.name.lower()
            events = _as_events(res)
            match = next((e for e in events if needle in (e.get("title") or e.get("name","")).lower()), None)
            if not match:
                # If not, print an error message
                print(f"[!] No event title contains: {args.name}")
            else:
                # If we found a match, print it
                _print(match, args.json)
            
        # checks if the command arg is pick-challenge
        elif args.cmd == "pick-challenge":
            ctf = await c.get_ctf(args.ctf)
            needle = args.name.lower()
            chals = _as_challenges(ctf)
            match = next((ch for ch in chals if needle in (ch.get("name","")).lower()), None)
            if not match:
                # If not, print an error message
                print(f"[!] No challenge name contains: {args.name}")
            else:
                # If we found a match, print it
                _print(match, args.json)

        # checks if the command arg is start
        elif args.cmd == "start":
            out = await c.start_container(args.challenge)
            return _print(out, args.json)
        
        # checks if the command arg is download
        elif args.cmd == "download":
            out = await c.get_download_link(args.challenge)
            if args.json: 
                return _print(out, True)
            print(out.get("url") if isinstance(out, dict) else out)

        # checks if the command arg is submit
        elif args.cmd == "submit":
            out = await c.submit_flag(args.challenge, args.flag)
            return _print(out, args.json)
        
        # If the command is not recognized, print an error message
        else:
            print("Unknown command")
    finally:
        # Close the client connection
        await c.close()

def main():
    p = argparse.ArgumentParser(prog="charlotte mcp", description="CHARLOTTE ↔ HTB MCP")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-events")
    sub.add_parser("my-teams")
    sub.add_parser("list-teams")  # alias for my-teams

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
# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI.
# It provides a minimal CLI interface to interact with the Hack The Box MCP.
# ******************************************************************************************
# This script allows users to list events, join CTFs, list challenges, and perform other actions.
# It uses the HtbMcpClient to connect to the MCP and perform actions based on user input.
# It supports JSON output for easy integration with other tools.
# ******************************************************************************************