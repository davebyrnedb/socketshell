import json
import argparse
import os
import datetime

WHITELIST_PATH = "agent_whitelist.json"

def load_whitelist():
    try:
        with open(WHITELIST_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load whitelist: {e}")
        return {}

def save_whitelist(data):
    try:
        with open(WHITELIST_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to save whitelist: {e}")

def list_agents(whitelist):
    for guid, info in whitelist.items():
        print(f"{guid} - {info.get('hostname', 'unknown')} - {info.get('ip_local', 'n/a')}")

def show_agent(whitelist, guid):
    agent = whitelist.get(guid)
    if not agent:
        print(f"[!] No agent found with GUID {guid}")
        return
    print(json.dumps(agent, indent=2))

def delete_agent(whitelist, guid):
    if guid in whitelist:
        del whitelist[guid]
        save_whitelist(whitelist)
        print(f"[✓] Agent {guid} removed from whitelist")
    else:
        print(f"[!] No agent found with GUID {guid}")

def prune_duplicates(whitelist):
    seen = {}
    to_delete = []

    for guid, info in whitelist.items():
        hostname = info.get("hostname")
        key = hostname.lower()
        reg_time = info.get("registered_at", "")
        if key not in seen:
            seen[key] = (guid, reg_time)
        else:
            existing_guid, existing_time = seen[key]
            try:
                dt_existing = datetime.datetime.fromisoformat(existing_time)
                dt_new = datetime.datetime.fromisoformat(reg_time)
                if dt_new > dt_existing:
                    to_delete.append(existing_guid)
                    seen[key] = (guid, reg_time)
                else:
                    to_delete.append(guid)
            except Exception:
                pass

    for guid in to_delete:
        whitelist.pop(guid, None)
        print(f"[✓] Pruned duplicate GUID {guid}")

    if to_delete:
        save_whitelist(whitelist)
    else:
        print("[i] No duplicates found")

def main():
    parser = argparse.ArgumentParser(description="Whitelist Management Tool")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List all whitelisted agents")

    show_parser = subparsers.add_parser("show", help="Show details of a specific agent")
    show_parser.add_argument("guid", help="GUID of the agent")

    del_parser = subparsers.add_parser("delete", help="Delete a specific agent from whitelist")
    del_parser.add_argument("guid", help="GUID of the agent")

    subparsers.add_parser("prune-dupes", help="Remove duplicate hostnames (keep latest)")

    args = parser.parse_args()
    whitelist = load_whitelist()

    if args.command == "list":
        list_agents(whitelist)
    elif args.command == "show":
        show_agent(whitelist, args.guid)
    elif args.command == "delete":
        delete_agent(whitelist, args.guid)
    elif args.command == "prune-dupes":
        prune_duplicates(whitelist)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
