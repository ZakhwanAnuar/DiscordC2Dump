#!/usr/bin/env python3
"""
discord_c2_dump.py

Incident-response / threat-intel tool for dumping message history from a
Discord guild that a malware sample uses as its C2 channel, using a bot
token recovered during analysis.

Design goals:
  - Fast: channels are fetched concurrently instead of one at a time.
  - Incremental: remembers the last message ID seen per channel in a state
    file, so re-running only pulls NEW messages instead of re-downloading
    everything.
  - IOC-friendly output: one JSON file per channel, a flat greppable text
    digest, and a summary of IOCs (author IDs, attachment URLs + hashes).
  - Read-only: no destructive or offensive actions against the guild.

Usage:
    pip install requests --break-system-packages

    export DISCORD_BOT_TOKEN="...."
    export DISCORD_GUILD_ID="...."
    python3 discord_c2_dump.py

    # or pass explicitly
    python3 discord_c2_dump.py --token TOKEN --guild GUILD_ID

    # force a full re-dump, ignoring saved state
    python3 discord_c2_dump.py --full

    # raise concurrency (mind Discord's rate limits)
    python3 discord_c2_dump.py --workers 8

See README.md for full documentation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests

API_BASE = "https://discord.com/api/v10"

# Channel types worth reading: text, announcement, forum.
# (skips categories=4, voice=2, stage=13, etc.)
READABLE_CHANNEL_TYPES = {0, 5, 15}

# Quick triage pattern for anything that looks like a flag/token/secret in
# dumped content, e.g. flag{...}, CTF{...}, API keys with a similar shape.
DEFAULT_INTERESTING_PATTERN = re.compile(r"[A-Za-z0-9_]{2,20}\{[^{}]{3,200}\}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("discord_c2_dump")


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------

class DiscordClient:
    """Thin wrapper around the Discord REST API with rate-limit handling."""

    def __init__(self, token: str, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bot {token}"})

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = path if path.startswith("http") else f"{API_BASE}{path}"
        while True:
            resp = self.session.request(method, url, timeout=30, **kwargs)
            if resp.status_code == 429:
                try:
                    retry_after = float(resp.json().get("retry_after", 1))
                except Exception:
                    retry_after = 1.0
                log.warning("Rate limited on %s, sleeping %.2fs", url, retry_after)
                time.sleep(retry_after + 0.25)
                continue
            return resp

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.request("POST", path, **kwargs)


# --------------------------------------------------------------------------
# State management (enables incremental / delta dumps)
# --------------------------------------------------------------------------

@dataclass
class State:
    """Tracks the last-seen message ID per channel across runs."""

    path: Path
    data: dict[str, Any] = field(default_factory=lambda: {"channels": {}})

    @classmethod
    def load(cls, path: Path) -> "State":
        if path.exists():
            try:
                return cls(path=path, data=json.loads(path.read_text()))
            except Exception:
                log.warning("State file %s unreadable, starting fresh", path)
        return cls(path=path, data={"channels": {}})

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2))

    def last_seen(self, channel_id: str) -> Optional[str]:
        return self.data.get("channels", {}).get(channel_id, {}).get("last_message_id")

    def update(self, channel_id: str, last_message_id: str, total_count: int) -> None:
        self.data.setdefault("channels", {})[channel_id] = {
            "last_message_id": last_message_id,
            "total_message_count": total_count,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }


# --------------------------------------------------------------------------
# Core dump logic
# --------------------------------------------------------------------------

class C2Dumper:
    def __init__(
        self,
        client: DiscordClient,
        guild_id: str,
        out_dir: Path,
        state: State,
        pattern: re.Pattern,
        workers: int = 4,
        full: bool = False,
    ):
        self.client = client
        self.guild_id = guild_id
        self.out_dir = out_dir
        self.state = state
        self.pattern = pattern
        self.workers = workers
        self.full = full
        self.iocs: dict[str, Any] = {
            "author_ids": set(),
            "attachments": [],
            "interesting_matches": [],
        }
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "channels").mkdir(exist_ok=True)
        (self.out_dir / "attachments").mkdir(exist_ok=True)

    # ---- discovery -------------------------------------------------

    def whoami(self) -> Optional[dict]:
        r = self.client.get("/users/@me")
        if r.status_code != 200:
            log.error("Token check failed: %s %s", r.status_code, r.text)
            return None
        me = r.json()
        log.info("Authenticated as bot %s#%s (id=%s)",
                  me.get("username"), me.get("discriminator"), me.get("id"))
        return me

    def guild_info(self) -> Optional[dict]:
        r = self.client.get(f"/guilds/{self.guild_id}", params={"with_counts": "true"})
        if r.status_code != 200:
            log.error("Could not fetch guild: %s %s", r.status_code, r.text)
            return None
        g = r.json()
        log.info("Guild: %s (id=%s, members=%s)",
                  g.get("name"), g.get("id"), g.get("approximate_member_count"))
        return g

    def list_channels(self) -> list[dict]:
        r = self.client.get(f"/guilds/{self.guild_id}/channels")
        if r.status_code != 200:
            log.error("Could not list channels: %s %s", r.status_code, r.text)
            return []
        channels = [c for c in r.json() if c.get("type") in READABLE_CHANNEL_TYPES]
        log.info("Found %d readable channels", len(channels))
        return channels

    # ---- per-channel dump -------------------------------------------

    def _fetch_all_messages(self, channel_id: str, stop_at: Optional[str]) -> list[dict]:
        """Page backwards from newest to oldest, stopping early if we hit
        a message ID we've already recorded (incremental mode)."""
        collected: list[dict] = []
        before: Optional[str] = None
        while True:
            params = {"limit": 100}
            if before:
                params["before"] = before
            r = self.client.get(f"/channels/{channel_id}/messages", params=params)
            if r.status_code != 200:
                log.error("Read failed for channel %s: %s %s", channel_id, r.status_code, r.text)
                break
            batch = r.json()
            if not batch:
                break

            if stop_at and not self.full:
                trimmed = []
                hit_boundary = False
                for m in batch:
                    if m["id"] == stop_at:
                        hit_boundary = True
                        break
                    trimmed.append(m)
                collected.extend(trimmed)
                if hit_boundary:
                    break
            else:
                collected.extend(batch)

            before = batch[-1]["id"]
            if len(batch) < 100:
                break
        return collected

    def _download_attachment(self, url: str, filename: str) -> Optional[str]:
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            log.warning("Failed to download attachment %s: %s", filename, e)
            return None
        digest = hashlib.sha256(resp.content).hexdigest()
        safe_name = f"{digest[:12]}_{filename}"
        path = self.out_dir / "attachments" / safe_name
        path.write_bytes(resp.content)
        self.iocs["attachments"].append({
            "filename": filename,
            "url": url,
            "sha256": digest,
            "saved_as": str(path),
        })
        return digest

    def dump_channel(self, channel: dict) -> dict:
        cid, cname = channel["id"], channel.get("name", channel["id"])
        stop_at = self.state.last_seen(cid)
        log.info("Scanning #%s (%s)%s", cname, cid, "" if self.full else " [incremental]" if stop_at else "")

        new_messages = self._fetch_all_messages(cid, stop_at)

        # Merge with anything already saved on disk (incremental append)
        out_path = self.out_dir / "channels" / f"{cname}_{cid}.json"
        existing: list[dict] = []
        if out_path.exists() and not self.full:
            try:
                existing = json.loads(out_path.read_text())
            except Exception:
                existing = []

        combined = new_messages + existing  # newest-first ordering preserved
        if combined:
            out_path.write_text(json.dumps(combined, indent=2))
            self.state.update(cid, combined[0]["id"], len(combined))

        for m in new_messages:
            self.iocs["author_ids"].add(m.get("author", {}).get("id"))
            blob = json.dumps(m)
            for hit in self.pattern.findall(blob):
                self.iocs["interesting_matches"].append(
                    {"channel": cname, "message_id": m.get("id"), "match": hit}
                )
            for att in m.get("attachments", []):
                self._download_attachment(att["url"], att["filename"])

        return {"channel": cname, "id": cid, "new_messages": len(new_messages)}

    # ---- run ---------------------------------------------------------

    def run(self) -> None:
        if not self.whoami():
            sys.exit(1)
        if not self.guild_info():
            sys.exit(1)
        channels = self.list_channels()
        if not channels:
            log.warning("No readable channels found.")
            return

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.dump_channel, c): c for c in channels}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    c = futures[fut]
                    log.error("Channel %s failed: %s", c.get("name"), e)

        self.state.save()
        self._write_digest(results)

    def _write_digest(self, results: list[dict]) -> None:
        total_new = sum(r["new_messages"] for r in results)
        log.info("Done. %d new messages across %d channels.", total_new, len(results))

        # Flat, greppable text digest of every channel dump on disk.
        digest_path = self.out_dir / "digest.txt"
        with digest_path.open("w", encoding="utf-8") as f:
            for jf in sorted((self.out_dir / "channels").glob("*.json")):
                try:
                    msgs = json.loads(jf.read_text())
                except Exception:
                    continue
                f.write(f"\n===== {jf.stem} ({len(msgs)} messages) =====\n")
                for m in reversed(msgs):  # oldest -> newest for readability
                    ts = m.get("timestamp", "?")
                    author = m.get("author", {}).get("username", "?")
                    content = m.get("content", "")
                    f.write(f"[{ts}] {author}: {content}\n")
                    for att in m.get("attachments", []):
                        f.write(f"    [attachment] {att.get('filename')} -> {att.get('url')}\n")

        # IOC summary (author IDs, attachment hashes, any flag-like matches).
        ioc_path = self.out_dir / "iocs.json"
        ioc_out = {
            "author_ids": sorted(a for a in self.iocs["author_ids"] if a),
            "attachments": self.iocs["attachments"],
            "interesting_matches": self.iocs["interesting_matches"],
        }
        ioc_path.write_text(json.dumps(ioc_out, indent=2))

        log.info("Digest written to %s", digest_path)
        log.info("IOC summary written to %s", ioc_path)
        if self.iocs["interesting_matches"]:
            log.info("Interesting matches found:")
            for hit in self.iocs["interesting_matches"]:
                log.info("  [%s] msg %s -> %s", hit["channel"], hit["message_id"], hit["match"])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--token", default=os.environ.get("DISCORD_BOT_TOKEN"),
                   help="Bot token (or set DISCORD_BOT_TOKEN env var)")
    p.add_argument("--guild", default=os.environ.get("DISCORD_GUILD_ID"),
                   help="Guild/server ID (or set DISCORD_GUILD_ID env var)")
    p.add_argument("--out", default="dump", help="Output directory (default: ./dump)")
    p.add_argument("--state-file", default=None,
                   help="Path to state file for incremental runs (default: <out>/state.json)")
    p.add_argument("--workers", type=int, default=4, help="Concurrent channel fetches (default: 4)")
    p.add_argument("--full", action="store_true", help="Ignore saved state, re-dump everything")
    p.add_argument("--pattern", default=None,
                   help="Custom regex for triage matches (default: flag{...}-style pattern)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if not args.token or not args.guild:
        log.error("Missing --token/--guild (or DISCORD_BOT_TOKEN/DISCORD_GUILD_ID env vars).")
        sys.exit(2)

    out_dir = Path(args.out)
    state_path = Path(args.state_file) if args.state_file else out_dir / "state.json"
    state = State.load(state_path)
    pattern = re.compile(args.pattern) if args.pattern else DEFAULT_INTERESTING_PATTERN

    client = DiscordClient(args.token)
    dumper = C2Dumper(
        client=client,
        guild_id=args.guild,
        out_dir=out_dir,
        state=state,
        pattern=pattern,
        workers=args.workers,
        full=args.full,
    )
    dumper.run()


if __name__ == "__main__":
    main()