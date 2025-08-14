#!/usr/bin/env python3

import requests
import getpass
import argparse
import re
import sys

# Disable insecure request warnings (useful with self-signed certs)
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# -------------------------
# Zabbix API helper
# -------------------------
def api_call(api_url, method, params=None, auth=None):
    """
    Generic Zabbix API JSON-RPC call.
    :param api_url: full API endpoint URL
    :param method: API method name (string)
    :param params: method params (dict) or None
    :param auth: auth token (string) or None
    :return: parsed JSON result
    """
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1
    }
    if auth:
        payload["auth"] = auth

    headers = {"Content-Type": "application/json-rpc"}
    resp = requests.post(api_url, json=payload, headers=headers, verify=False)
    resp.raise_for_status()
    result = resp.json()
    if "error" in result:
        raise Exception(result["error"])
    return result["result"]


# -------------------------
# Positional macro replacement
# -------------------------
pos_macro_re = re.compile(r"\$(\d+)")

def extract_key_params(key_):
    """
    Extract arguments inside square brackets of key_ and return list of params.
    Handles escaped commas '\,'.
    Example: key_ = "net.if.in[eth0]" -> ["eth0"]
             key_ = "check[val1\,withcomma,val2]" -> ["val1,withcomma", "val2"]
    """
    m = re.search(r"\[(.*)\]", key_)
    if not m:
        return []
    params_str = m.group(1)
    # split on commas not preceded by backslash
    raw_params = re.split(r"(?<!\\),", params_str)
    # strip and unescape any '\,' to ','
    params = [p.strip().replace(r"\,", ",") for p in raw_params]
    return params

def replace_positional_macros(name, key_):
    """
    Replace $1, $2, ... in name using positional arguments extracted from key_.
    If index is out of range, leave the macro unchanged.
    """
    params = extract_key_params(key_)

    def repl(m):
        idx = int(m.group(1)) - 1
        return params[idx] if 0 <= idx < len(params) else m.group(0)

    return pos_macro_re.sub(repl, name)


# -------------------------
# Process regular items
# -------------------------
def process_items(api_url, auth_token, do_replace, limit):
    """
    Find items (non-templated) that contain positional macros in their name
    and replace them using key_ params. Optionally perform update.
    Returns number of items changed (or would be changed in dry-run).
    """
    changed = 0

    items = api_call(api_url, "item.get", {
        "output": ["itemid", "name", "key_", "templateid", "flags"],
        "filter": {"templateid": "0", "flags": "0"},
        "limit": limit
    }, auth_token)

    # Filter in Python for names containing $<digit>
    for item in items:
        name = item.get("name", "")
        if not pos_macro_re.search(name):
            continue

        key_ = item.get("key_", "")
        new_name = replace_positional_macros(name, key_)

        if new_name != name:
            changed += 1
            if do_replace:
                print(f"Updating item {item['itemid']}: '{name}' → '{new_name}'")
                api_call(api_url, "item.update", {
                    "itemid": item["itemid"],
                    "name": new_name
                }, auth_token)
            else:
                print(f"Would update item {item['itemid']}: '{name}' → '{new_name}'")

    return changed


# -------------------------
# Process item prototypes (templated)
# -------------------------
def process_item_prototypes(api_url, auth_token, do_replace, limit):
    """
    Find item prototypes (templated) that contain positional macros in their name
    and replace them using key_ params. Optionally perform itemprototype.update.
    Returns number of prototypes changed (or would be changed in dry-run).
    """
    changed = 0

    prototypes = api_call(api_url, "itemprototype.get", {
        "output": ["itemid", "name", "key_", "templateid", "flags", "hostid"],
        "templated": True,
        "limit": limit
    }, auth_token)

    for proto in prototypes:
        name = proto.get("name", "")
        if not pos_macro_re.search(name):
            continue

        key_ = proto.get("key_", "")
        new_name = replace_positional_macros(name, key_)

        if new_name != name:
            changed += 1
            if do_replace:
                print(f"Updating prototype {proto['itemid']} on template {proto.get('hostid')}: '{name}' → '{new_name}'")
                api_call(api_url, "itemprototype.update", {
                    "itemid": proto["itemid"],
                    "name": new_name
                }, auth_token)
            else:
                print(f"Would update prototype {proto['itemid']} on template {proto.get('hostid')}: '{name}' → '{new_name}'")

    return changed


# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Replace deprecated positional macros ($1, $2, ...) in Zabbix item names and item prototypes.")
    parser.add_argument("-a", "--api-url", required=True, help="Zabbix API URL, e.g. https://zabbix.example.com/api_jsonrpc.php")
    parser.add_argument("-u", "--user", default="Admin", help="Zabbix username (default: Admin)")
    parser.add_argument("-p", "--password", help="Zabbix user password (if omitted, you will be prompted)")
    parser.add_argument("-r", "--replace", "--do-replace", action="store_true", dest="replace",
                        help="Perform updates (otherwise dry-run)")
    parser.add_argument("-l", "--limit", type=int, default=50000, help="Limit for API results (default: 50000)")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Enter password for user {args.user}: ")

    try:
        # login (note: Zabbix API expects 'username' param)
        auth_token = api_call(args.api_url, "user.login", {
            "username": args.user,
            "password": password
        }, auth=None)
    except Exception as e:
        print("Authentication failed:", e, file=sys.stderr)
        sys.exit(1)

    print("Authenticated. Scanning items and item prototypes...")

    total_changed = 0
    try:
        items_changed = process_items(args.api_url, auth_token, args.replace, args.limit)
        prototypes_changed = process_item_prototypes(args.api_url, auth_token, args.replace, args.limit)
        total_changed = items_changed + prototypes_changed
    finally:
        # optional logout (ignore errors)
        try:
            api_call(args.api_url, "user.logout", {}, auth_token)
        except Exception:
            pass

    if args.replace:
        print(f"Done. Updated items: {items_changed}, updated item prototypes: {prototypes_changed}, Total updated entries: {total_changed}")
    else:
        print(f"Dry-run complete. Entries that would be updated: {items_changed} items, {prototypes_changed} item prototypes, {total_changed} in total.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
