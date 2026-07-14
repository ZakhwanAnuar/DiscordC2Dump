#!/usr/bin/env python3
"""
Discord CTF enumeration helper.

Given a bot TOKEN and a GUILD_ID (both usually extracted from malware
config/strings), this script:
  1. Verifies the token works (GET /users/@me)
  2. Confirms the bot is in the target guild
  3. Lists all channels (text, announcement, forum, etc.)
  4. Dumps message history + pinned messages from each channel
  5. Downloads attachments
  6. Greps everything (messages, embeds, channel topics, attachments,
     emoji names, role names) for a flag pattern

Usage:
    pip install requests --break-system-packages
    python3 enum.py

Fill in TOKEN, GUILD_ID, and FLAG_REGEX below.
"""

import os
import re
import time
import json
import requests

# ---- CONFIG: fill these in ----
TOKEN = "YOUR_BOT_TOKEN_HERE"
GUILD_ID = "YOUR_GUILD_ID_HERE"
FLAG_REGEX = re.compile(r"[A-Za-z0-9_]*\{[^}]+\}")  # matches flag{...}, CTF{...}, etc.
OUT_DIR = "dump"
# --------------------------------

API = "https://discord.com/api/v10"
HEADERS = {"Authorization": f"Bot {TOKEN}"}

os.makedirs(OUT_DIR, exist_ok=True)


def req(method, url, **kwargs):
    """Wrapper with basic rate-limit handling."""
    while True:
        r = requests.request(method, url, headers=HEADERS, **kwargs)
        if r.status_code == 429:
            retry_after = r.json().get("retry_after", 1)
            print(f"[rate limited] sleeping {retry_after}s")
            time.sleep(retry_after + 0.5)
            continue
        return r


def check_token():
    r = req("GET", f"{API}/users/@me")
    if r.status_code != 200:
        print(f"[!] Token check failed: {r.status_code} {r.text}")
        return None
    me = r.json()
    print(f"[+] Bot identity: {me.get('username')}#{me.get('discriminator')} (id={me.get('id')})")
    return me


def check_guild():
    r = req("GET", f"{API}/guilds/{GUILD_ID}?with_counts=true")
    if r.status_code != 200:
        print(f"[!] Could not fetch guild: {r.status_code} {r.text}")
        print("    (bot may not be a member of this guild)")
        return None
    g = r.json()
    print(f"[+] Guild: {g.get('name')} (id={g.get('id')})")
    hits = FLAG_REGEX.findall(json.dumps(g))
    if hits:
        print(f"    [FLAG CANDIDATE in guild object] {hits}")
    return g


def list_channels():
    r = req("GET", f"{API}/guilds/{GUILD_ID}/channels")
    if r.status_code != 200:
        print(f"[!] Could not list channels: {r.status_code} {r.text}")
        return []
    channels = r.json()
    print(f"[+] Found {len(channels)} channels")
    for c in channels:
        name = c.get("name")
        topic = c.get("topic")
        print(f"    - #{name} (id={c['id']}, type={c['type']})", f"topic={topic!r}" if topic else "")
        if topic:
            hits = FLAG_REGEX.findall(topic)
            if hits:
                print(f"      [FLAG CANDIDATE in topic] {hits}")
    return channels


def dump_messages(channel):
    cid = channel["id"]
    cname = channel.get("name", cid)
    all_msgs = []
    before = None
    while True:
        params = {"limit": 100}
        if before:
            params["before"] = before
        r = req("GET", f"{API}/channels/{cid}/messages", params=params)
        if r.status_code != 200:
            print(f"    [!] Could not read #{cname}: {r.status_code} {r.text}")
            break
        batch = r.json()
        if not batch:
            break
        all_msgs.extend(batch)
        before = batch[-1]["id"]
        if len(batch) < 100:
            break

    # pinned messages too
    r = req("GET", f"{API}/channels/{cid}/pins")
    if r.status_code == 200:
        all_msgs.extend(r.json())

    if all_msgs:
        with open(f"{OUT_DIR}/{cname}_{cid}.json", "w") as f:
            json.dump(all_msgs, f, indent=2)

    for m in all_msgs:
        text_blob = json.dumps(m)
        hits = FLAG_REGEX.findall(text_blob)
        if hits:
            print(f"    [FLAG CANDIDATE in #{cname}] {hits} -- msg id {m.get('id')}")

        # download attachments
        for att in m.get("attachments", []):
            url = att["url"]
            fname = att["filename"]
            try:
                resp = requests.get(url)
                path = os.path.join(OUT_DIR, fname)
                with open(path, "wb") as f:
                    f.write(resp.content)
                print(f"    [+] downloaded attachment {fname} from #{cname}")
                # try to grep text attachments directly
                try:
                    content = resp.content.decode("utf-8", errors="ignore")
                    ahits = FLAG_REGEX.findall(content)
                    if ahits:
                        print(f"      [FLAG CANDIDATE in attachment {fname}] {ahits}")
                except Exception:
                    pass
            except Exception as e:
                print(f"    [!] failed to download {fname}: {e}")

    return all_msgs


def list_emojis_and_roles():
    r = req("GET", f"{API}/guilds/{GUILD_ID}/emojis")
    if r.status_code == 200:
        for e in r.json():
            hits = FLAG_REGEX.findall(e.get("name", ""))
            if hits:
                print(f"[FLAG CANDIDATE in emoji name] {hits}")

    r = req("GET", f"{API}/guilds/{GUILD_ID}/roles")
    if r.status_code == 200:
        for role in r.json():
            hits = FLAG_REGEX.findall(role.get("name", ""))
            if hits:
                print(f"[FLAG CANDIDATE in role name] {hits}")


def main():
    if not check_token():
        return
    if not check_guild():
        return
    channels = list_channels()
    for c in channels:
        # 0 = text, 5 = announcement, 15 = forum -- skip categories(4)/voice(2)
        if c.get("type") in (0, 5, 15):
            print(f"[*] Scanning #{c.get('name')} ...")
            dump_messages(c)
    list_emojis_and_roles()
    print("\n[+] Done. Full message dumps saved in ./dump/. Re-grep with:")
    print(f"    grep -rEo '{FLAG_REGEX.pattern}' {OUT_DIR}/")


if __name__ == "__main__":
    main()
