# DiscordC2Dump

A small Threat Intel helper for enumerating a Discord bot's accessible guild
(server) when you've recovered a **bot token** and **guild ID** — e.g. from
a malware sample using Discord as a C2 (command-and-control) channel.

It walks the Discord REST API and dumps everything the bot can see, then
scans it for a flag pattern.

> ⚠️ **Intended use:** Malware Analysis in a sandbox/lab
> environment, and authorized security research only. Only use this against
> servers and tokens you own, that belong to a challenge you're authorized
> to solve, or that you have explicit permission to test. Discord bot tokens
> are credentials — treat them like passwords, don't commit them to git, and
> revoke/rotate them when you're done.

---

## What it does

Given a bot token and guild ID, the script:

1. **Verifies the token** — `GET /users/@me`
2. **Confirms guild access** — `GET /guilds/{guild_id}`
3. **Lists all channels** — text, announcement, forum, voice, categories
4. **Dumps message history** for every readable text-type channel, including
   pinned messages
5. **Downloads attachments** from every message and greps text-based ones
6. **Checks emoji names and role names** for hidden strings
7. **Regex-scans everything** (messages, embeds, topics, filenames, emoji
   names, role names) for a flag pattern (default: `something{...}`)

All raw output is saved to `./dump/` as JSON (one file per channel) plus
downloaded attachments, so you can re-grep or inspect manually afterward.

---

## Requirements

- Python 3.8+
- [`requests`](https://pypi.org/project/requests/)

```bash
pip install requests --break-system-packages
# or, in a virtualenv:
python3 -m venv venv && source venv/bin/activate && pip install requests
```

> **Note:** don't name your own copy of this script `enum.py` — it will
> shadow Python's built-in `enum` module and crash with a confusing
> `circular import` error. Keep it as `discord_enum.py` or similar.

---

## Usage

```bash
python3 discord_c2_dump.py
```

Example output:

```
01:00:56 [INFO] Authenticated as bot bot1#2925 (id=163712987987288921)
01:00:56 [INFO] Guild: hello (id=1525918842843435290, members=2)
01:00:57 [INFO] Found 3 readable channels
01:00:57 [INFO] Scanning #general (1525918844496121888)
01:00:57 [INFO] Scanning #session-example-4bac67b8 (12345678909876543210)
01:00:57 [INFO] Scanning #session-example2-5316cacf (0987654321234567890)
01:01:04 [INFO] Done. 93 new messages across 3 channels.
01:01:04 [INFO] Digest written to dump/digest.txt
01:01:04 [INFO] IOC summary written to dump/iocs.json
```

Channel dumps land in `./dump/<channel_name>_<channel_id>.json`, and any
downloaded attachments sit alongside them in the same folder.

---

## Joining the server as a human (optional)

The bot can only see what its role permits. If you suspect there's a
channel or content hidden from the bot but visible to a human member, you
can generate an invite using the bot's token (requires the bot to hold the
**Create Instant Invite** permission in at least one channel):

```bash
curl -X POST \
  -H "Authorization: Bot YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_age": 3600, "max_uses": 1}' \
  "https://discord.com/api/v10/channels/CHANNEL_ID/invites"
```

The response includes a `"code"` field — turn it into a real invite link:

```
https://discord.gg/CODE
```

Open that link in your own Discord account to join normally.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401 Unauthorized` on token check | Token is invalid/expired, or missing the `Bot ` prefix — the script handles the prefix, so double-check the raw token was copied correctly |
| `403 Missing Access` on guild/channels | The bot isn't actually a member of that guild |
| Empty member list from `/guilds/{id}/members` | Requires the **`GUILD_MEMBERS` privileged intent** to be enabled for the bot application; without it, Discord returns limited or no data |
| `circular import` / `AttributeError` on `re`/`json` | You renamed the script to `enum.py`, which shadows Python's stdlib `enum` module — rename it |
| `429 Too Many Requests` | Handled automatically — the script sleeps and retries based on Discord's `retry_after` value |
| Invite creation returns `403` | The bot's role lacks `CREATE_INSTANT_INVITE` in that channel — try a different channel, or check for a `vanity_url_code` on the guild object instead |

---

## Disclaimer

This tool talks directly to the live Discord API using real credentials.
It is provided for legitimate security research, malware analysis, and CTF
use. You are responsible for ensuring you have authorization to access the
target bot/guild. The author/assistant is not responsible for misuse.
