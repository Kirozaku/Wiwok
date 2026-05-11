#!/usr/bin/env python3
# wiwok.py v5.0 - osint tool for username / email / phone investigation
# no api keys needed

import os
import re
import sys
import json
import time
import shutil
import signal
import hashlib
import argparse
import threading
import subprocess
import shlex
import html as _html
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "5.0"
CFG_FILE = os.path.expanduser("~/.wiwok.json")
OUT_DIR  = os.path.expanduser("~/wiwok_results")
PLUG_DIR = os.path.expanduser("~/.wiwok_plugins")

DEFAULTS = {
    "workers": 4,
    "timeout": 30,
    "retries": 2,
    "retry_delay": 1.5
}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        if os.path.exists(CFG_FILE):
            with open(CFG_FILE) as f:
                cfg.update(json.load(f))
    except Exception:
        pass
    return cfg

CFG = load_config()

W = 68

_R    = "\033[0m"
_B    = "\033[1m"
_D    = "\033[2m"
_GRN  = "\033[38;5;82m"
_RED  = "\033[38;5;196m"
_YLW  = "\033[38;5;226m"
_CYN  = "\033[38;5;51m"
_GRY  = "\033[38;5;237m"
_GRY2 = "\033[38;5;245m"
_PRP  = "\033[38;5;141m"

_NO_COLOR = False


def c(code, text):
    if _NO_COLOR:
        return text
    return code + text + _R


def p(msg=""):
    print(msg, flush=True)


def hr(ch="─", col=_GRY):
    p(c(col, "  " + ch * (W - 2)))


def tag(sym, msg):
    clr = {"+": _GRN, "-": _RED, "!": _RED, ">": _CYN, "*": _YLW, "~": _PRP}
    p(f"  {c(clr.get(sym, _GRY2), '[' + sym + ']')} {msg}")


def kv(key, val):
    pad = key + " "
    p(f"  {c(_GRY2, pad + '·' * max(1, 18 - len(pad)))} {c(_B, val)}")


BANNER = r"""
  __      __.___ __      __________   ____  __.
/  \    /  \   /  \    /  \_____  \ |    |/ _|
\   \/\/   /   \   \/\/   //   |   \|      <
 \        /|   |\        //    |    \    |  \
  \__/\  / |___| \__/\  / \_______  /____|__ \
       \/             \/          \/        \/"""


def banner():
    p(c(_GRN + _B, BANNER))
    p()
    p(f"  {c(_GRY2, 'WiwoK DetoK OSINT TOOL')}  {c(_GRY, '//')}  "
      f"{c(_GRN + _B, 'v' + VERSION)}  {c(_GRY, '//')}  {c(_GRY2, 'zero api key edition')}")
    hr()


class RateLimiter:
    def __init__(self, delay=0.5):
        self._last = {}
        self._lock = threading.Lock()
        self.delay = delay

    def wait(self, domain):
        with self._lock:
            gap = time.time() - self._last.get(domain, 0)
            if gap < self.delay:
                time.sleep(self.delay - gap)
            self._last[domain] = time.time()

_RL = RateLimiter()


class Cache:
    def __init__(self):
        self.store = {}
        self._lock = threading.Lock()

    def get(self, k):
        with self._lock:
            return self.store.get(k)

    def has(self, k):
        with self._lock:
            return k in self.store

    def put(self, k, v):
        with self._lock:
            self.store[k] = v

_CACHE = Cache()


def http_get(url, headers=None, timeout=15):
    domain = urllib.parse.urlparse(url).netloc
    key = hashlib.md5(url.encode()).hexdigest()

    if _CACHE.has(key):
        return _CACHE.get(key)

    _RL.wait(domain)

    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
    if headers:
        hdrs.update(headers)

    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read().decode("utf-8", errors="replace")
        _CACHE.put(key, data)
        return data
    except urllib.error.HTTPError:
        _CACHE.put(key, None)
        return None
    except Exception:
        return None


def _mod_github_profile(target):
    raw = http_get("https://api.github.com/users/" + urllib.parse.quote(target))
    if not raw:
        return "  user not found"
    try:
        d = json.loads(raw)
        if "message" in d:
            return "  " + d["message"]
        want = ("name", "bio", "location", "company", "email",
                "public_repos", "followers", "created_at", "html_url", "twitter_username")
        lines = []
        for k, v in d.items():
            if k in want and v:
                lines.append(f"  {k:<18}: {v}")
        return "\n".join(lines) if lines else "  no public info"
    except Exception:
        return "  parse error"


def _mod_github_emails(target):
    url = f"https://api.github.com/users/{urllib.parse.quote(target)}/events/public?per_page=20"
    raw = http_get(url)
    if not raw:
        return "  no public emails found"
    try:
        found = set()
        for ev in json.loads(raw):
            for commit in ev.get("payload", {}).get("commits", []):
                em = commit.get("author", {}).get("email", "")
                if em and "noreply" not in em:
                    found.add(em)
        if not found:
            return "  no public emails found"
        return "\n".join("  " + e for e in sorted(found))
    except Exception:
        return "  no public emails found"


def _mod_github_by_email(target):
    raw = http_get(f"https://api.github.com/search/users?q={urllib.parse.quote(target)}+in:email")
    if not raw:
        return "  0 accounts found"
    try:
        data = json.loads(raw)
        items = data.get("items", [])
        out = [f"  {len(items)} accounts found"]
        for u in items[:5]:
            out.append(f"  {u.get('login', ''):<20} {u.get('html_url', '')}")
        return "\n".join(out)
    except Exception:
        return "  0 accounts found"


def _mod_keybase(target):
    raw = http_get(f"https://keybase.io/_/api/1.0/user/lookup.json?username={urllib.parse.quote(target)}")
    if not raw:
        return "  user not found"
    try:
        data = json.loads(raw)
        them = data.get("them")
        if isinstance(them, list) and them:
            pd = them[0]
        elif isinstance(them, dict):
            pd = them
        else:
            return "  user not found"

        out = [
            f"  username : {pd.get('basics', {}).get('username', '-')}",
            f"  name     : {pd.get('profile', {}).get('full_name', '-')}",
        ]
        for proof in pd.get("proofs_summary", {}).get("all", [])[:8]:
            out.append(f"  proof    : {proof.get('proof_type')} -- {proof.get('service_url', '')}")
        return "\n".join(out)
    except Exception:
        return "  parse error"


def _mod_reddit_profile(target):
    raw = http_get(
        f"https://www.reddit.com/user/{urllib.parse.quote(target)}/about.json",
        headers={"User-Agent": "wiwok/5.0"}
    )
    if not raw:
        return "  user not found"
    try:
        d = json.loads(raw).get("data", {})
        ts = d.get("created_utc", 0)
        joined = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else "-"
        return "\n".join([
            f"  karma         : {d.get('total_karma', 0)}",
            f"  created       : {joined}",
            f"  email_verified: {d.get('has_verified_email', False)}",
            f"  moderator     : {d.get('is_mod', False)}",
        ])
    except Exception:
        return "  user not found"


def _mod_gravatar(target):
    h = hashlib.md5(target.strip().lower().encode()).hexdigest()
    return (
        f"  md5 hash : {h}\n"
        f"  avatar   : https://www.gravatar.com/avatar/{h}?d=404\n"
        f"  profile  : https://en.gravatar.com/{h}"
    )


def _mod_pastebin_search(target):
    raw = http_get("https://psbdmp.ws/api/search/" + urllib.parse.quote(target))
    if not raw:
        return "  no results found"
    try:
        data = json.loads(raw)
        items = data.get("data", [])
        if not items:
            return "  no results found"
        out = [f"  {len(items)} results"]
        for paste in items[:5]:
            out.append(f"  https://pastebin.com/{paste.get('id', '')}  |  {paste.get('text', '')[:60]}")
        return "\n".join(out)
    except Exception:
        return "  no results found"


def _mod_google_dorks(target):
    q = target
    dorks = [
        f'site:linkedin.com "{q}"',
        f'site:instagram.com "{q}"',
        f'site:twitter.com "{q}"',
        f'site:facebook.com "{q}"',
        f'site:tiktok.com "{q}"',
        f'site:github.com "{q}"',
        f'"{q}" site:pastebin.com',
        f'"{q}" filetype:pdf',
        f'"{q}" password OR email OR phone OR address',
        f'intitle:"{q}"',
    ]
    return "\n".join("  " + d for d in dorks)


def _mod_username_variants(target):
    s = target.lower().replace(" ", ".")
    parts = [x for x in re.split(r"[_.\-]", s) if x]

    variants = set()
    if len(parts) >= 2:
        f, l = parts[0], parts[-1]
        variants.update([
            f+l, l+f, f+"."+l, f+"_"+l,
            f[0]+l, f+"."+l[0], l+"."+f,
            f+"-"+l, s, s.replace(".","_"),
            s.replace(".",""), s.replace(".","-")
        ])
    else:
        variants.update([
            s+"_"+s[:3], s[:3]+"_"+s,
            s+"."+s[:4], s[:4]+"."+s
        ])

    return "\n".join("  " + x for x in sorted(variants) if x and x != target)


_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _mod_instagram_check(target):
    raw = http_get(
        f"https://www.instagram.com/{urllib.parse.quote(target)}/",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"

    if any(x in raw for x in ["Page Not Found", "Sorry, this page", '"loginRequired":true']):
        return "  not found"

    name_m   = re.search(r'"full_name"\s*:\s*"([^"]+)"', raw)
    bio_m    = re.search(r'"biography"\s*:\s*"([^"]+)"', raw)
    follow_m = re.search(r'"edge_followed_by"\s*:\s*\{"count"\s*:\s*(\d+)', raw)
    post_m   = re.search(r'"edge_owner_to_timeline_media"\s*:\s*\{"count"\s*:\s*(\d+)', raw)

    hit = name_m or (target.lower() in raw[:5000].lower() and "instagram" in raw.lower())
    if not hit:
        return "  uncertain (Instagram may block scraping)"

    out = [
        f"  [+] account found on Instagram",
        f"  url       : https://www.instagram.com/{target}/",
    ]
    if name_m:   out.append(f"  name      : {name_m.group(1)}")
    if bio_m:    out.append(f"  bio       : {bio_m.group(1)[:80]}")
    if follow_m: out.append(f"  followers : {follow_m.group(1)}")
    if post_m:   out.append(f"  posts     : {post_m.group(1)}")
    return "\n".join(out)


def _mod_facebook_check(target):
    raw = http_get(
        f"https://www.facebook.com/{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"

    if "content is not available" in raw.lower() or "This content isn" in raw:
        return "  not found or private"

    title_m = re.search(r"<title>([^<]+)</title>", raw)
    if title_m:
        title = title_m.group(1)
        title = title.replace(" | Facebook", "").replace(" - Facebook", "").strip()
        if title and title.lower() not in ("facebook", "log in or sign up"):
            return "\n".join([
                "  [+] possible account found on Facebook",
                f"  url  : https://www.facebook.com/{target}",
                f"  name : {title}",
            ])

    if target.lower() in raw[:5000].lower():
        return f"  [+] possible account found on Facebook\n  url  : https://www.facebook.com/{target}"

    return "  not found or private"


def _mod_wayback_check(target):
    results = []

    if "@" in target:
        checks = [target]
    elif target.startswith("+"):
        checks = [target.replace("+", ""), target.replace("+62", "0")]
    else:
        checks = [
            f"instagram.com/{target}",
            f"twitter.com/{target}",
            f"facebook.com/{target}",
        ]

    for chk in checks[:3]:
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={urllib.parse.quote(chk)}"
            "&output=json&limit=3&fl=timestamp,original&filter=statuscode:200"
        )
        raw = http_get(url, timeout=20)
        if not raw:
            continue
        try:
            rows = json.loads(raw)
            if not rows or len(rows) < 2:
                continue
            for row in rows[1:4]:
                ts, orig = row[0], row[1]
                d = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                results.append(f"  [+] {orig}")
                results.append(f"       archived : https://web.archive.org/web/{ts}/{orig}  ({d})")
        except Exception:
            pass

    return "\n".join(results) if results else "  no snapshots found in Wayback Machine"


def _mod_linkedin_dorks(target):
    return "\n".join([
        f'  site:linkedin.com/in "{target}"',
        f'  site:linkedin.com/pub "{target}"',
        f'  site:linkedin.com "{target}" Indonesia',
        f'  site:linkedin.com "{target}" -jobs -hiring',
        f'  "{target}" linkedin.com',
    ])


def _mod_name_dorks(target):
    q = target
    lines = [
        f'  "{q}" site:linkedin.com',
        f'  "{q}" site:facebook.com',
        f'  "{q}" site:instagram.com',
        f'  "{q}" site:twitter.com',
        f'  "{q}" site:kaskus.co.id',
        f'  "{q}" site:tokopedia.com OR site:shopee.co.id',
        f'  "{q}" phone OR email OR address',
        f'  "{q}" filetype:pdf OR filetype:doc',
        f'  "{q}" password OR username',
        f'  intitle:"{q}"',
    ]
    return "\n".join(lines)


def _mod_steam_check(target):
    raw = http_get(
        f"https://steamcommunity.com/id/{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"
    if "The specified profile could not be found" in raw or "error_ctn" in raw:
        return "  not found"

    name_m  = re.search(r'class="actual_persona_name">([^<]+)<', raw)
    level_m = re.search(r'<span class="friendPlayerLevelNum">(\d+)<', raw)

    if not name_m:
        return "  uncertain (profile may be private)"

    out = [
        "  [+] account found on Steam",
        f"  url         : https://steamcommunity.com/id/{target}",
        f"  display name: {name_m.group(1).strip()}",
    ]
    if level_m:
        out.append(f"  steam level : {level_m.group(1)}")
    return "\n".join(out)


def _mod_snapchat_check(target):
    raw = http_get(
        f"https://www.snapchat.com/add/{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"
    if any(x in raw for x in ["Sorry! Couldn", "pageNotFound", '"statusCode":40']):
        return "  not found"
    if "snapchat.com" in raw and target.lower() in raw.lower():
        nm = re.search(r'"displayName"\s*:\s*"([^"]+)"', raw)
        out = [
            "  [+] account found on Snapchat",
            f"  url : https://www.snapchat.com/add/{target}",
        ]
        if nm:
            out.append(f"  name: {nm.group(1)}")
        return "\n".join(out)
    return "  uncertain"


def _mod_tiktok_check(target):
    raw = http_get(
        f"https://www.tiktok.com/@{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"
    if '"statusCode":10202' in raw or "Couldn't find this account" in raw:
        return "  not found"

    nick = re.search(r'"nickname"\s*:\s*"([^"]+)"', raw)
    fans = re.search(r'"followerCount"\s*:\s*(\d+)', raw)
    bio  = re.search(r'"signature"\s*:\s*"([^"]+)"', raw)

    if not nick and f"@{target}".lower() not in raw.lower():
        return "  uncertain (may require JS rendering)"

    out = [
        "  [+] account found on TikTok",
        f"  url       : https://www.tiktok.com/@{target}",
    ]
    if nick: out.append(f"  nickname  : {nick.group(1)}")
    if fans: out.append(f"  followers : {fans.group(1)}")
    if bio:  out.append(f"  bio       : {bio.group(1)[:80]}")
    return "\n".join(out)


def _mod_youtube_check(target):
    raw = http_get(
        f"https://www.youtube.com/@{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"
    if '"error"' in raw and '"code": 404' in raw:
        return "  not found"

    name = re.search(r'"channelMetadataRenderer"\s*:\s*\{[^}]*"title"\s*:\s*"([^"]+)"', raw)
    subs = re.search(r'"subscriberCountText"[^}]*?"simpleText"\s*:\s*"([^"]+)"', raw)
    vids = re.search(r'"videosCountText"[^}]*?"runs"[^]]*?"text"\s*:\s*"([^"]+)"', raw)

    if not name:
        return "  uncertain (YouTube may require JS)"

    out = [
        "  [+] channel found on YouTube",
        f"  url         : https://www.youtube.com/@{target}",
        f"  name        : {name.group(1) if name else target}",
    ]
    if subs: out.append(f"  subscribers : {subs.group(1)}")
    if vids: out.append(f"  videos      : {vids.group(1)}")
    return "\n".join(out)


def _mod_twitch_check(target):
    raw = http_get(
        f"https://www.twitch.tv/{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"

    if '"isLiveBroadcast"' in raw or ('"' + target + '"').lower() in raw.lower():
        live = re.search(r'"isLiveBroadcast"\s*:\s*(true|false)', raw)
        out = [
            "  [+] channel found on Twitch",
            f"  url  : https://www.twitch.tv/{target}",
        ]
        if live:
            out.append(f"  live : {live.group(1)}")
        return "\n".join(out)

    if target.lower() in raw[:8000].lower():
        return f"  [+] possible match on Twitch\n  url  : https://www.twitch.tv/{target}"

    return "  not found"


def _mod_pinterest_check(target):
    raw = http_get(
        f"https://www.pinterest.com/{urllib.parse.quote(target)}/",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"
    if "This page isn" in raw or '"statusCode":404' in raw:
        return "  not found"

    name    = re.search(r'"full_name"\s*:\s*"([^"]+)"', raw)
    follows = re.search(r'"follower_count"\s*:\s*(\d+)', raw)
    pins    = re.search(r'"pin_count"\s*:\s*(\d+)', raw)

    if not name and target.lower() not in raw[:4000].lower():
        return "  not found"

    out = [
        "  [+] account found on Pinterest",
        f"  url       : https://www.pinterest.com/{target}/",
    ]
    if name:    out.append(f"  name      : {name.group(1)}")
    if follows: out.append(f"  followers : {follows.group(1)}")
    if pins:    out.append(f"  pins      : {pins.group(1)}")
    return "\n".join(out)


def _mod_phone_format(target):
    clean = re.sub(r"[\s\-()]", "", target)
    lines = [f"  input     : {target}"]
    variants = set()

    if clean.startswith("0"):
        variants.update([f"+62{clean[1:]}", f"62{clean[1:]}", clean])
        lines.append("  country   : Indonesia (assumed)")
    elif clean.startswith("+"):
        variants.add(clean)
        variants.add(clean[1:])
        if clean.startswith("+62"):
            variants.add("0" + clean[3:])
    elif clean.startswith("62"):
        variants.update([f"+{clean}", "0" + clean[2:]])
    else:
        variants.add(clean)

    lines.append("  variants  :")
    for v in sorted(variants):
        lines.append(f"    {v}")

    digits = re.sub(r"\D", "", clean)
    valid  = 8 <= len(digits) <= 15
    lines.append(f"  length    : {len(digits)} digits ({'valid range' if valid else 'check format'})")
    return "\n".join(lines)


_NATIVE = {
    "github_profile":    _mod_github_profile,
    "github_emails":     _mod_github_emails,
    "github_by_email":   _mod_github_by_email,
    "keybase":           _mod_keybase,
    "reddit_profile":    _mod_reddit_profile,
    "gravatar":          _mod_gravatar,
    "pastebin_search":   _mod_pastebin_search,
    "google_dorks":      _mod_google_dorks,
    "username_variants": _mod_username_variants,
    "steam_check":       _mod_steam_check,
    "snapchat_check":    _mod_snapchat_check,
    "tiktok_check":      _mod_tiktok_check,
    "youtube_check":     _mod_youtube_check,
    "twitch_check":      _mod_twitch_check,
    "pinterest_check":   _mod_pinterest_check,
    "phone_format":      _mod_phone_format,
    "instagram_check":   _mod_instagram_check,
    "facebook_check":    _mod_facebook_check,
    "wayback_check":     _mod_wayback_check,
    "linkedin_dorks":    _mod_linkedin_dorks,
    "name_dorks":        _mod_name_dorks,
}


MODULES = {
    "sherlock": {
        "type": "username",
        "weight": 10,
        "desc": "track username across 300+ social platforms",
        "check": "sherlock",
        "cmd": "sherlock --timeout 10 --print-found --no-color {s}",
        "timeout": 90,
        "install": "sudo apt install -y sherlock",
        "pivot": {"email": r"[\w.+\-]+@[\w.\-]+\.\w+"},
    },

    "maigret": {
        "type": "username",
        "weight": 9,
        "desc": "deep profile from 2000+ sites",
        "check": "maigret",
        "cmd": "maigret --timeout 10 --no-progressbar --no-color {s}",
        "timeout": 120,
        "install": "pip install maigret --user --break-system-packages",
        "pivot": {
            "username": r"'([a-zA-Z0-9_.\-]+)'\s*:\s*'username'",
            "name":     r"├─fullname:\s+([A-Za-z][A-Za-z\s]{3,40})",
        },
    },

    "socialscan": {
        "type": "username", "weight": 7,
        "desc": "check username availability on major platforms",
        "check": "socialscan",
        "cmd": "socialscan {s}",
        "timeout": 30,
        "install": "pip install socialscan --break-system-packages",
    },

    "github_profile": {
        "type": "username", "weight": 8,
        "desc": "github profile, repos, and followers",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r'"email"\s*:\s*"([\w.+\-]+@[\w.\-]+\.\w+)"'},
    },

    "github_emails": {
        "type": "username", "weight": 8,
        "desc": "emails extracted from github commit history",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r"([\w.+\-]+@[\w.\-]+\.\w+)"},
    },

    "keybase": {
        "type": "username", "weight": 6,
        "desc": "identity proofs on keybase",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "reddit_profile": {
        "type": "username", "weight": 6,
        "desc": "public reddit profile and statistics",
        "check": "#native", "timeout": 20, "install": "#builtin",
    },

    "username_variants": {
        "type": "username", "weight": 4,
        "desc": "generate common username variations",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "instagram_check": {
        "type": "username", "weight": 8,
        "desc": "check account on Instagram",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "facebook_check": {
        "type": "username", "weight": 7,
        "desc": "check account on Facebook",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "tiktok_check": {
        "type": "username", "weight": 7,
        "desc": "check account on TikTok",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "snapchat_check": {
        "type": "username", "weight": 7,
        "desc": "check account on Snapchat",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "youtube_check": {
        "type": "username", "weight": 7,
        "desc": "check channel on YouTube",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "twitch_check": {
        "type": "username", "weight": 6,
        "desc": "check channel on Twitch",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "steam_check": {
        "type": "username", "weight": 6,
        "desc": "check profile on Steam",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "pinterest_check": {
        "type": "username", "weight": 6,
        "desc": "check account on Pinterest",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "linkedin_dorks": {
        "type": "username", "weight": 6,
        "desc": "generate LinkedIn-specific dorks",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "holehe": {
        "type": "email", "weight": 0,
        "desc": "holehe quick scan (use holehe_full instead)",
        "check": "holehe",
        "cmd": "holehe --only-used --no-color {s}",
        "timeout": 90,
        "install": "pip install holehe --break-system-packages",
    },

    "holehe_full": {
        "type": "email", "weight": 8,
        "desc": "email registered check on 121 platforms",
        "check": "holehe",
        "cmd": "holehe --only-used --no-color {s}",
        "timeout": 120,
        "install": "pip install holehe --break-system-packages",
    },

    "gravatar": {
        "type": "email", "weight": 7,
        "desc": "gravatar profile from email hash",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "github_by_email": {
        "type": "email", "weight": 7,
        "desc": "github accounts linked to this email",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"username": r'"login"\s*:\s*"([^"]+)"'},
    },

    "email_sherlock": {
        "type": "email", "weight": 0,
        "desc": "sherlock from email local-part",
        "check": "sherlock",
        "cmd": (
            "LOCAL=$(python3 -c \"print('{s}'.split('@')[0])\") && "
            "sherlock --timeout 10 --print-found --no-color \"$LOCAL\""
        ),
        "timeout": 90,
        "install": "sudo apt install -y sherlock",
    },

    "email_maigret": {
        "type": "email", "weight": 0,
        "desc": "maigret from email local-part",
        "check": "maigret",
        "cmd": (
            "LOCAL=$(python3 -c \"print('{s}'.split('@')[0])\") && "
            "maigret --timeout 10 --no-progressbar --no-color \"$LOCAL\""
        ),
        "timeout": 120,
        "install": "pip install maigret --user --break-system-packages",
    },

    "ignorant": {
        "type": "phone", "weight": 10,
        "desc": "check phone number on WhatsApp, Instagram, Snapchat",
        "check": "ignorant",
        "cmd": "ignorant {s}",
        "timeout": 60,
        "install": "pip install ignorant --break-system-packages",
    },

    "phoneinfoga": {
        "type": "phone", "weight": 9,
        "desc": "carrier, location, and online profile of phone number",
        "check": "phoneinfoga",
        "cmd": "phoneinfoga scan -n {s}",
        "timeout": 60,
        "install": (
            "curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga"
            "/master/support/scripts/install | bash"
            " && sudo mv ./phoneinfoga /usr/bin/phoneinfoga"
        ),
    },

    "phone_meta": {
        "type": "phone", "weight": 7,
        "desc": "carrier, location, timezone, number type",
        "check": "python3",
        "cmd": (
            "python3 -c \""
            "import sys;"
            "\ntry:"
            "\n  import phonenumbers"
            "\n  from phonenumbers import carrier, geocoder, timezone as tz"
            "\nexcept ImportError:"
            "\n  print('  install: pip install phonenumbers --break-system-packages'); sys.exit(0)"
            "\ntry:"
            "\n  n=phonenumbers.parse('{s}','ID');"
            "\n  ntype=phonenumbers.number_type(n);"
            "\n  tstr='mobile' if ntype==phonenumbers.PhoneNumberType.MOBILE else 'fixed-line' if ntype==phonenumbers.PhoneNumberType.FIXED_LINE else 'other';"
            "\n  print(f'  location         : {{geocoder.description_for_number(n,\\\"en\\\")}}');"
            "\n  print(f'  region_code      : {{phonenumbers.region_code_for_number(n)}}');"
            "\n  print(f'  timezone         : {{\\\", \\\".join(tz.time_zones_for_number(n))}}');"
            "\n  print(f'  operator         : {{carrier.name_for_number(n,\\\"en\\\") or \\\"-\\\"}}');"
            "\n  print(f'  valid            : {{phonenumbers.is_valid_number(n)}}');"
            "\n  print(f'  E.164            : {{phonenumbers.format_number(n,phonenumbers.PhoneNumberFormat.E164)}}');"
            "\n  print(f'  type             : {{tstr}}');"
            "\nexcept Exception as e: print(f'  error: {{e}}')"
            "\""
        ),
        "timeout": 10,
        "install": "pip install phonenumbers --break-system-packages",
    },

    "phone_format": {
        "type": "phone", "weight": 8,
        "desc": "auto-format number variants (E.164, local, etc)",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "wayback_check": {
        "type": "any", "weight": 6,
        "desc": "search target snapshots in Wayback Machine",
        "check": "#native", "timeout": 30, "install": "#builtin",
    },

    "pastebin_search": {
        "type": "any", "weight": 6,
        "desc": "search target in public pastebin dumps",
        "check": "#native", "timeout": 20, "install": "#builtin",
    },

    "google_dorks": {
        "type": "any", "weight": 5,
        "desc": "generate ready-to-use google dorks",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "name_dorks": {
        "type": "name", "weight": 8,
        "desc": "generate targeted dorks for a full name",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },
}


def load_plugins():
    plugins = {}
    if not os.path.isdir(PLUG_DIR):
        return plugins
    for fn in sorted(os.listdir(PLUG_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(PLUG_DIR, fn)) as f:
                data = json.load(f)
            if isinstance(data, dict):
                plugins.update(data)
        except Exception:
            pass
    return plugins

MODULES.update(load_plugins())


TYPE_MAP = {
    "username": [
        "sherlock", "maigret", "socialscan",
        "instagram_check", "facebook_check",
        "tiktok_check", "snapchat_check",
        "youtube_check", "twitch_check",
        "steam_check", "pinterest_check",
        "linkedin_dorks",
        "github_profile", "github_emails",
        "keybase", "reddit_profile",
        "username_variants", "wayback_check",
        "pastebin_search", "google_dorks",
    ],
    "email": [
        "holehe_full", "gravatar", "github_by_email",
        "email_sherlock", "email_maigret",
        "wayback_check", "pastebin_search", "google_dorks",
    ],
    "phone": [
        "phone_format", "ignorant", "phoneinfoga", "phone_meta",
        "wayback_check", "pastebin_search", "google_dorks",
    ],
    "name": [
        "name_dorks", "pastebin_search", "google_dorks", "username_variants",
    ],
}


_bin_cache = {}

def which_bin(binary):
    if binary in _bin_cache:
        return _bin_cache[binary]
    found = shutil.which(binary)
    if not found:
        for d in (os.path.expanduser("~/.local/bin"), "/usr/local/bin"):
            cand = os.path.join(d, binary)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                found = cand
                break
    _bin_cache[binary] = found
    return found


def is_installed(name):
    chk = MODULES[name].get("check", "")
    if chk in ("#builtin", "#native"):
        return True
    if chk.startswith("/"):
        return os.path.isfile(chk)
    return which_bin(chk) is not None


def build_cmd(name, target):
    tpl = MODULES[name].get("cmd", "")
    if not tpl:
        return ""
    safe = target.replace("'", "'\\''")
    return tpl.replace("{s}", "'" + safe + "'") if "python3 -c" not in tpl else tpl.replace("{s}", safe)


_PAT_EMAIL    = re.compile(r"^[\w.+\-]+@[\w.\-]+\.[a-zA-Z]{2,}$")
_PAT_PHONE    = re.compile(r"^\+[\d\s\-()]{7,20}$")
_PAT_USERNAME = re.compile(r"^[a-zA-Z0-9_.\-]{2,50}$")


def detect_type(s):
    if _PAT_EMAIL.match(s):    return "email"
    if _PAT_PHONE.match(s):    return "phone"
    if " " in s:               return "name"
    if _PAT_USERNAME.match(s): return "username"
    return "username"


def sanitize(s):
    s = s.strip()
    if not s:
        raise ValueError("target is empty")
    if len(s) > 200:
        raise ValueError("target is too long")
    bad = re.search(r'[;&|`$\n\r<>()\[\]{}\\\'\"#^~*!]', s)
    if bad:
        raise ValueError("invalid characters in target")
    return s


def _run_once(name, target):
    mod = MODULES.get(name, {})

    if mod.get("check") == "#native":
        fn = _NATIVE.get(name)
        if not fn:
            return "  native function not found", "", False
        try:
            out = fn(target)
            return out or "", f"[native:{name}]", bool(out)
        except Exception as e:
            return f"  error: {e}", f"[native:{name}]", False

    if not is_installed(name):
        hint = mod.get("install", "")
        return f"  not installed\n  install: {hint}", "", False

    timeout = mod.get("timeout") or CFG.get("timeout", 30)
    cmd = build_cmd(name, target)

    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"),
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            return stdout or "", cmd, proc.returncode == 0
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            return f"  timed out after {timeout}s\n{stdout or ''}", cmd, False
    except Exception as e:
        return f"  error: {e}", cmd, False


def run_module(name, target):
    retries = CFG.get("retries", 2)
    delay   = CFG.get("retry_delay", 1.5)
    last    = ("", "", False)

    for attempt in range(retries + 1):
        out, cmd, ok = _run_once(name, target)
        if ok:
            return out, cmd, ok
        last = (out, cmd, ok)
        if "not installed" in out or "native function not found" in out:
            break
        if attempt < retries:
            time.sleep(delay)

    return last


class Progress:
    def __init__(self, total):
        self.total  = total
        self.done   = 0
        self.ok     = 0
        self._lock  = threading.Lock()
        self._start = time.time()

    def tick(self, ok):
        with self._lock:
            self.done += 1
            if ok:
                self.ok += 1

    def elapsed(self):
        return time.time() - self._start

    def bar(self):
        w      = 24
        filled = int(w * self.done / max(self.total, 1))
        pct    = int(100 * self.done / max(self.total, 1))
        bar    = "█" * filled + "░" * (w - filled)
        return f"[{bar}] {pct:3d}%  {self.done}/{self.total}  ok:{self.ok}  {self.elapsed():.0f}s"


_ANSI = re.compile(r"\033[\[\(][\?]?[0-9;]*[a-zA-Z]|\033[a-zA-Z]|\r")

_NOISE_PATTERNS = [
    r"\d+%\|", r"\s*\[[-]\]\s", r"Update available", r"github\.com/sherlock-project",
    r"You can run search", r"Too many errors", r"You can see detailed",
    r"Available, Taken", r"Completed \d+ queries", r"QueryError", r"ClientConnector",
    r"ConnectionTimeout", r"SSLCertVerif", r"Using sites database",
    r"Starting a search on top", r"\[\*\] Checking username",
    r"image:\s*https?://", r"it/s\]", r"Some characters could not",
    r"Target factory started", r"scylla\.so is down", r"\[~\]",
    r"websites checked in", r"\*{6,}", r"\[x\]\s", r"\[\?\]\s",
    r"\[\*\] scanning username", r"scanner\(s\) succeeded",
    r"Running scan for phone", r"Results for googlesearch",
    r"Results for local", r"^\s*Raw local:", r"BTC Donations",
    r"Heartfelt", r"Official h8mail", r"Removing duplicates",
    r"Short text report", r"Email used", r"Search completed",
    r"phonenumbers\.parse", r"ignorant v", r"Checking phone",
    r"Phone number used", r"Phone number not used", r"Rate limit",
    r"\+\d{2}\s+\d+$",
]
_NOISE = re.compile("|".join(f"({p})" for p in _NOISE_PATTERNS))


def _filter_lines(text, tgt=""):
    from urllib.parse import unquote_plus
    out     = []
    section = None

    for ln in text.splitlines():
        ln = _ANSI.sub("", ln).rstrip()
        s  = ln.strip()

        if not s or _NOISE.search(ln):
            continue
        if tgt and s == tgt:
            continue

        if s in ("Social media:", "Disposable providers:", "Reputation:", "Individuals:", "General:"):
            section = s.rstrip(":")
            continue

        url_m = re.match(r"^\s*URL:\s*(https\S+)", ln)
        if url_m:
            decoded = unquote_plus(url_m.group(1))
            qm = re.search(r"[?&]q=([^&]+)", decoded)
            if qm and section:
                out.append(f"  [{section}] {qm.group(1).replace('+', ' ')}")
            continue

        out.append(ln)

    return out


_lock = threading.Lock()


def mod_open(idx, total, name, desc):
    pad = "─" * max(0, W - len(name) - 18)
    p()
    p(f"  {c(_GRY, '┌──')}[ {c(_CYN, f'{idx:02d}/{total:02d}')} {c(_GRY, '::')} {c(_B, name)} ]{c(_GRY, pad)}")
    p(f"  {c(_GRY, '│')}  {c(_D, desc)}")
    p(f"  {c(_GRY, '│')}")


def mod_cmd(cmd):
    short = cmd if cmd.startswith("[native") else cmd[:W - 10]
    p(f"  {c(_GRY, '│')}  {c(_D + _GRY2, '$ ' + short)}")
    p(f"  {c(_GRY, '│')}")


def mod_line(ln):
    if ln.rstrip():
        p(f"  {c(_GRY, '│')}  {ln.rstrip()}")


def mod_close(ok, elapsed, bar):
    p(f"  {c(_GRY, '│')}")
    p(f"  {c(_GRY, '│')}  {c(_GRN, 'done') if ok else c(_RED, 'fail')}  {c(_D, f'// {elapsed:.1f}s')}")
    p(f"  {c(_GRY, '└──')}  {c(_D, bar)}")


def investigate(target, ttype="", mode="standard", only=None, quiet=False):
    t0     = time.time()
    target = sanitize(target)
    ttype  = ttype or detect_type(target)

    weight_floor = {"quick": 8, "standard": 5, "deep": 0}.get(mode, 5)

    if only:
        pool    = [n for n in only if n in MODULES]
        missing = []
    else:
        candidates = TYPE_MAP.get(ttype, list(MODULES.keys()))
        pool, missing = [], []
        for n in candidates:
            if MODULES[n].get("weight", 5) < weight_floor:
                continue
            (pool if is_installed(n) else missing).append(n)

    if not quiet:
        tag("*", f"{len(pool)} modules  //  {len(missing)} not installed")
        p()

    results  = []
    progress = Progress(len(pool))
    counter  = [0]

    def worker(name):
        t_start     = time.time()
        out, cmd, ok = run_module(name, target)
        elapsed      = time.time() - t_start
        progress.tick(ok)

        with _lock:
            counter[0] += 1
            if not quiet:
                mod_open(counter[0], len(pool), name, MODULES[name].get("desc", ""))
                if cmd:
                    mod_cmd(cmd)
                for ln in _filter_lines(out or "", target):
                    mod_line(ln)
                mod_close(ok, elapsed, progress.bar())

        pivots = {}
        if ok and out:
            for ptype, pat in MODULES[name].get("pivot", {}).items():
                for m in re.findall(pat, out):
                    m = m.strip().rstrip(".")
                    if m and len(m) > 3 and m != target:
                        pivots.setdefault(ptype, set()).add(m)

        return {
            "module": name,
            "ok": ok,
            "output": out,
            "cmd": cmd,
            "pivots": {k: sorted(v) for k, v in pivots.items()},
        }

    nw = min(CFG.get("workers", 4), len(pool)) if pool else 1
    with ThreadPoolExecutor(max_workers=nw) as ex:
        futs = {ex.submit(worker, n): n for n in pool}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({
                    "module": futs[f], "ok": False,
                    "output": str(e), "cmd": "", "pivots": {}
                })

    all_pivots = {}
    for r in results:
        for pt, vals in r.get("pivots", {}).items():
            all_pivots.setdefault(pt, set()).update(vals)

    return {
        "target":  target,
        "type":    ttype,
        "mode":    mode,
        "ts":      datetime.now().isoformat(),
        "elapsed": round(time.time() - t0, 1),
        "results": results,
        "pivots":  {k: sorted(v) for k, v in all_pivots.items()},
        "missing": missing,
        "summary": {
            "ok":    sum(1 for r in results if r["ok"]),
            "fail":  sum(1 for r in results if not r["ok"]),
            "total": len(results),
        },
    }


def _outpath(name, ext):
    os.makedirs(OUT_DIR, exist_ok=True)
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean = re.sub(r"[^\w\-.]", "_", name)
    return os.path.join(OUT_DIR, f"{clean}_{ts}.{ext}")


def save_json(inv):
    path = _outpath(inv["target"], "json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=2, ensure_ascii=False)
    return path


_ANSI_STRIP = re.compile(r"\033[\[\(][\?]?[0-9;]*[a-zA-Z]|\033[a-zA-Z]|\r")

_SKIP_REPORT = re.compile(
    r"(\d+%\|)|(\[[-]\])|(Update available)|(sherlock-project)|(You can run search)"
    r"|(Too many errors)|(QueryError|ClientConnector|ConnectionTimeout|SSLCertVerif)"
    r"|(Using sites database)|(Starting a search on top)|(\[\*\] Checking username)"
    r"|(image:\s*https?://)|(it/s\])|(Some characters could not)"
    r"|(Target factory started|scylla\.so)|(\[~\])|(websites checked in)"
    r"|(\*{6,})|(REPLACEMENT CHARACTER)|(\[x\]\s)|(\[\?\]\s)"
    r"|(\[\*\] scanning username)|(^\s*URL:\s*https)"
    r"|(scanner\(s\) succeeded)|(Running scan for phone)"
    r"|(Results for googlesearch)|(Results for local)|(^\s*Raw local:)"
    r"|(BTC Donations)|(Heartfelt)|(Official h8mail)"
    r"|(ignorant v)|(Checking phone)"
    r"|(Phone number used)|(Phone number not used)|(Rate limit)"
    r"|(\+\d{2}\s+\d+$)"
)

_EMPTY_VALS = frozenset([
    "user not found", "no public emails found", "no results found",
    "username: -", "name     : -", "0 accounts found", "parse error",
])


def _clean_lines(text, tgt):
    from urllib.parse import unquote_plus
    out     = []
    section = None

    for ln in text.splitlines():
        ln = _ANSI_STRIP.sub("", ln).rstrip()
        if not ln.strip() or _SKIP_REPORT.search(ln):
            continue
        if ln.strip() == tgt:
            continue
        s = ln.strip()
        if s in ("Social media:", "Disposable providers:", "Reputation:", "Individuals:", "General:"):
            section = s.rstrip(":")
            continue
        um = re.match(r"^\s*URL:\s*(https\S+)", ln)
        if um:
            dec = unquote_plus(um.group(1))
            qm  = re.search(r"[?&]q=([^&]+)", dec)
            if qm and section:
                out.append(f"  [{section}] {qm.group(1).replace('+', ' ')}")
            continue
        out.append(ln)

    while out and re.match(r"^[-=*]{6,}$", out[0].strip()):
        out.pop(0)

    return out


def _is_empty(lines):
    return not any(l.strip() not in _EMPTY_VALS for l in lines)


def save_txt(inv):
    path = _outpath(inv["target"], "txt")
    s    = inv["summary"]
    L1   = "=" * 66
    L2   = "-" * 40

    hits = []
    for r in inv["results"]:
        if not r.get("ok"):
            continue
        raw = (r.get("output") or "").strip()
        if not raw:
            continue
        cl = _clean_lines(raw, inv["target"])
        if cl and not _is_empty(cl):
            n_hits = sum(1 for l in cl if l.strip().startswith("[+]"))
            hits.append((r["module"], n_hits, cl))

    lines = [
        f"WiwoK DetoK OSINT TOOL v{VERSION}  --  Investigation Report",
        L1,
        f"target   : {inv['target']}",
        f"type     : {inv['type']}",
        f"mode     : {inv['mode']}",
        f"date     : {inv['ts'][:19].replace('T', '  ')}",
        f"elapsed  : {inv['elapsed']}s",
        f"result   : {s['ok']} ok  /  {s['fail']} failed  /  {s['total']} total",
        L1, "",
        "[ summary ]",
        L2,
    ]

    for mod, n, _ in hits:
        label = f"{n} findings" if n else "data"
        lines.append(f"  {mod:<26} {label}")
    lines.append("")

    if inv.get("pivots"):
        lines += ["[ pivots ]", L2]
        for pt, vals in inv["pivots"].items():
            lines.append(f"  {pt} : {', '.join(vals[:10])}")
        lines.append("")
        lines.append("  investigate:")
        for pt, vals in inv["pivots"].items():
            for v in vals[:6]:
                q = f'"{v}"' if " " in v else v
                lines.append(f"    python3 wiwok.py {q}")
        lines += ["", L1, ""]

    lines += ["[ detail ]", L1, ""]
    for mod, _, cl in hits:
        lines += [f"[ {mod} ]", L2]
        lines += cl
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return path


def save_html(inv):
    path = _outpath(inv["target"], "html")
    s    = inv["summary"]

    fhtml = ""
    for r in inv["results"]:
        if not r.get("ok"):
            continue
        raw = (r.get("output") or "").strip()
        if not raw:
            continue
        cl = _clean_lines(raw, inv["target"])
        if not cl or _is_empty(cl):
            continue

        name    = r["module"]
        desc    = MODULES.get(name, {}).get("desc", "")
        content = "\n".join(_html.escape(ln) for ln in cl)
        content = re.sub(r"(\[+\])", r'<span class="hit">\1</span>', content)

        fhtml += (
            f'<div class="mod">'
            f'<div class="mhd" onclick="tog(this)">'
            f'<span class="ok">[+]</span>'
            f'<span class="mn">{_html.escape(name)}</span>'
            f'<span class="md">{_html.escape(desc)}</span>'
            f'<span class="chv">▾</span>'
            f'</div>'
            f'<pre class="mb">{content}</pre>'
            f'</div>\n'
        )

    pvhtml = ""
    for pt, vals in (inv.get("pivots") or {}).items():
        pvhtml += f'<div class="pt">[{_html.escape(pt)}]</div>'
        for v in vals[:10]:
            q   = f'"{v}"' if " " in v else v
            cmd = f"python3 wiwok.py {_html.escape(q)}"
            pvhtml += (
                f'<div class="pv">  {_html.escape(v)} '
                f'<span class="pcmd">↳ {cmd}</span></div>'
            )

    css = """
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d0d0d;color:#c0c0c0;font-family:'Courier New',monospace;font-size:12.5px;padding:28px;line-height:1.6}
a{color:#52fa7c;text-decoration:none}a:hover{text-decoration:underline}
.hdr{border-left:3px solid #52fa7c;padding:8px 0 8px 14px;margin-bottom:22px}
.hdr h1{color:#52fa7c;font-size:15px;letter-spacing:3px;text-transform:uppercase}
.hdr .meta{color:#555;font-size:11px;margin-top:5px}
.badge{display:inline-block;background:#1a2a1a;color:#52fa7c;font-size:9px;letter-spacing:2px;padding:2px 8px;border:1px solid #2a4a2a;margin-left:10px;vertical-align:middle}
.stats{display:flex;gap:20px;margin:0 0 20px;padding:10px 16px;background:#111;border:1px solid #222}
.stat .val{font-size:22px;font-weight:700}
.stat .lbl{color:#555;font-size:10px;letter-spacing:1px}
.ok-v{color:#52fa7c}.fail-v{color:#ff4444}
.sec{color:#555;font-size:10px;letter-spacing:3px;text-transform:uppercase;margin:22px 0 8px;border-bottom:1px solid #1a1a1a;padding-bottom:4px}
.mod{border:1px solid #1e1e1e;margin-bottom:6px;background:#0f0f0f}
.mhd{padding:8px 14px;cursor:pointer;display:flex;align-items:center;gap:12px;background:#141414;user-select:none}
.mhd:hover{background:#1a1a1a}
.ok{color:#52fa7c;font-weight:700;min-width:28px}.fail{color:#ff4444;font-weight:700}
.mn{color:#e0e0e0;font-weight:700;min-width:170px}
.md{color:#444;font-size:11px;flex:1}
.chv{color:#333;margin-left:auto;font-size:14px;transition:transform .2s}
.mhd.col .chv{transform:rotate(-90deg)}
.mb{padding:10px 16px;font-size:11.5px;border-top:1px solid #1a1a1a;white-space:pre-wrap;word-break:break-all;color:#909090;display:block}
.mb.hide{display:none}
.hit{color:#52fa7c;font-weight:700}
.pt{color:#bd93f9;margin-top:10px;font-weight:700}
.pv{color:#8be9fd;padding-left:16px;font-size:11.5px}
.pcmd{color:#444;font-size:10.5px;margin-left:8px}
.ftr{margin-top:28px;color:#2a2a2a;font-size:10.5px;border-top:1px solid #181818;padding-top:10px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:#0d0d0d}
::-webkit-scrollbar-thumb{background:#2a2a2a;border-radius:3px}
"""

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiwoK :: {_html.escape(inv['target'])}</title>
<style>{css}</style>
</head>
<body>
<div class="hdr">
  <h1>WiwoK DetoK OSINT TOOL v{VERSION} <span class="badge">ZERO API KEY</span></h1>
  <div class="meta">
    target: {_html.escape(inv['target'])} &nbsp;·&nbsp;
    type: {_html.escape(inv['type'])} &nbsp;·&nbsp;
    mode: {_html.escape(inv['mode'])} &nbsp;·&nbsp;
    {_html.escape(inv['ts'][:19].replace('T', ' '))} &nbsp;·&nbsp;
    {inv['elapsed']}s
  </div>
</div>
<div class="stats">
  <div class="stat"><div class="val ok-v">{s['ok']}</div><div class="lbl">OK</div></div>
  <div class="stat"><div class="val fail-v">{s['fail']}</div><div class="lbl">FAILED</div></div>
  <div class="stat"><div class="val">{s['total']}</div><div class="lbl">TOTAL</div></div>
  <div class="stat"><div class="val">{inv['elapsed']}s</div><div class="lbl">ELAPSED</div></div>
</div>
{('<div class="sec">pivots</div>' + pvhtml) if pvhtml else ''}
<div class="sec">findings</div>
{fhtml or '<div style="color:#2a2a2a;padding:12px">no findings</div>'}
<div class="ftr">WiwoK DetoK v{VERSION} &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<script>
function tog(h){{h.classList.toggle('col');h.nextElementSibling.classList.toggle('hide');}}
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


def _run_silent(cmd, timeout=300):
    try:
        r = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        return r.returncode == 0
    except Exception:
        return False


def _inst(label, cmd, t=300):
    print(f"  {c(_GRY2, '[>]')} {label:<28} ", end="", flush=True)
    ok = _run_silent(cmd, t)
    print(c(_GRN, "ok") if ok else c(_RED, "FAILED"))
    return ok


def cmd_setup():
    banner()
    p()
    hr()
    p(f"  {c(_B, '1/2  pip tools')}")
    hr()
    pip_tools = [
        ("phonenumbers", "pip install phonenumbers --break-system-packages", 60),
        ("holehe",       "pip install holehe --break-system-packages", 180),
        ("maigret",      "pip install maigret --user --break-system-packages", 300),
        ("socialscan",   "pip install socialscan --break-system-packages", 180),
        ("ignorant",     "pip install ignorant --break-system-packages", 180),
        ("phoneinfoga",
         "curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash"
         " && sudo mv ./phoneinfoga /usr/bin/phoneinfoga 2>/dev/null || true",
         120),
    ]
    for lbl, cmd, t in pip_tools:
        _inst(lbl, cmd, t)
    p()
    hr()
    p(f"  {c(_B, '2/2  verify')}")
    hr()
    tools = {
        "holehe":      "holehe",
        "maigret":     "maigret",
        "socialscan":  "socialscan",
        "ignorant":    "ignorant",
        "phoneinfoga": "phoneinfoga",
        "curl":        "curl",
    }
    ok_n = 0
    for name, bin_ in tools.items():
        found = bool(which_bin(bin_))
        p(f"  {c(_GRY2, '[*]')} {name:<22} {c(_GRN, 'ok') if found else c(_RED, 'missing')}")
        if found:
            ok_n += 1
    p()
    hr("═")
    tag("+" if ok_n == len(tools) else "-", f"{ok_n}/{len(tools)} tools ready")
    hr("═")


def cmd_update():
    banner()
    p()
    hr()
    p(f"  {c(_B, 'updating tools')}")
    hr()
    updates = [
        ("holehe",       "pip install --upgrade holehe --break-system-packages", 180),
        ("maigret",      "pip install --upgrade maigret --user --break-system-packages", 300),
        ("socialscan",   "pip install --upgrade socialscan --break-system-packages", 180),
        ("ignorant",     "pip install --upgrade ignorant --break-system-packages", 180),
        ("phonenumbers", "pip install --upgrade phonenumbers --break-system-packages", 60),
    ]
    for lbl, cmd, t in updates:
        _inst(lbl, cmd, t)
    p()
    hr("═")
    tag("+", "update complete")
    hr("═")


def cmd_check():
    banner()
    p()

    by_type = {}
    for name, info in MODULES.items():
        by_type.setdefault(info["type"], []).append(name)

    total_ok = 0
    for ttype in ["username", "email", "phone", "name", "any"]:
        if ttype not in by_type:
            continue
        hr()
        p(f"  {c(_B + _CYN, ttype)}")
        hr()
        for name in sorted(by_type[ttype]):
            ok   = is_installed(name)
            sym  = c(_GRN, "[+]") if ok else c(_RED, "[-]")
            desc = c(_D, MODULES[name].get("desc", ""))
            p(f"  {sym} {name:<26} {desc}")
            if not ok:
                hint = MODULES[name].get("install", "")
                if hint and not hint.startswith("#"):
                    p(f"       {c(_GRY2, '→ ' + hint[:60])}")
            else:
                total_ok += 1
        p()

    hr("═")
    tag("+" if total_ok == len(MODULES) else "-", f"{total_ok}/{len(MODULES)} modules ready")
    if total_ok < len(MODULES):
        tag(">", "python3 wiwok.py --setup")
    hr("═")


def cmd_help():
    banner()
    p()
    p(f"  {c(_B, 'USAGE')}")
    p(f"    python3 wiwok.py <target>")
    p(f"    python3 wiwok.py [options] <target>")
    p()
    hr()
    p(f"  {c(_B, 'COMMANDS')}")
    hr()
    for k, v in [
        ("--setup",  "install all dependencies"),
        ("--update", "update tools to latest version"),
        ("--check",  "check status of all modules"),
        ("--help",   "display this help page"),
    ]:
        p(f"  {c(_GRY2, k):<28} {v}")
    p()
    hr()
    p(f"  {c(_B, 'OPTIONS')}")
    hr()
    for k, v in [
        ("-t <type>",    "force target type  [username|email|phone|name]"),
        ("-m <mode>",    "scan depth  [quick|standard|deep]"),
        ("-r <modules>", "run specific modules (comma-separated)"),
        ("-P / --pivot", "auto-investigate all discovered pivots"),
        ("-q",           "quiet mode"),
        ("--no-color",   "output without color"),
    ]:
        p(f"  {c(_GRY2, k):<28} {v}")
    p()
    hr()
    p(f"  {c(_B, 'EXAMPLES')}")
    hr()
    for lbl, cmd in [
        ("username",         "python3 wiwok.py johndoe"),
        ("email",            "python3 wiwok.py john@example.com"),
        ("phone",            "python3 wiwok.py +6281234567890"),
        ("name",             'python3 wiwok.py -t name "John Doe"'),
        ("deep scan",        "python3 wiwok.py -m deep johndoe"),
        ("quick scan",       "python3 wiwok.py -m quick johndoe"),
        ("auto pivot",       "python3 wiwok.py -m deep -P johndoe"),
        ("username modules", "python3 wiwok.py -r sherlock,maigret johndoe"),
        ("email modules",    "python3 wiwok.py -r holehe_full,gravatar john@example.com"),
        ("phone modules",    "python3 wiwok.py -r ignorant,phone_meta +6281234567890"),
        ("check instagram",  "python3 wiwok.py -r instagram_check johndoe"),
        ("check youtube",    "python3 wiwok.py -r youtube_check johndoe"),
        ("quiet mode",       "python3 wiwok.py -q -m deep johndoe"),
    ]:
        p(f"  {c(_D, lbl + ':'): <22}  {cmd}")
    p()
    hr()
    p(f"  {c(_B, 'MODULES BY TYPE')}")
    hr()
    by_type2 = {}
    for name, info in MODULES.items():
        by_type2.setdefault(info["type"], []).append(name)
    for ttype in ["username", "email", "phone", "name", "any"]:
        if ttype not in by_type2:
            continue
        p(f"  {c(_GRY2, '[' + ttype + ']')}")
        for name in sorted(by_type2[ttype]):
            ok   = is_installed(name)
            dot  = c(_GRN, "●") if ok else c(_RED, "○")
            chk  = MODULES[name].get("check", "")
            ntag = c(_D + _CYN, " native") if chk == "#native" else ""
            p(f"    {dot} {name:<26} {c(_D, MODULES[name].get('desc', ''))}{ntag}")
        p()
    hr("═")


def cmd_pivot(inv, mode, quiet):
    if not inv.get("pivots"):
        return
    p()
    hr("═")
    p(f"  {c(_B + _CYN, 'AUTO-PIVOT')}")
    hr("═")

    for ptype, vals in inv["pivots"].items():
        for val in vals[:3]:
            p()
            tag(">", f"{c(_GRY2, ptype)}  →  {c(_B, val)}")
            p()
            try:
                sub = investigate(val, ptype, mode, quiet=quiet)
                _print_summary(sub, mode)
                jp = save_json(sub)
                tp = save_txt(sub)
                hp = save_html(sub)
                p()
                tag("+", f"json  : {jp}")
                tag("+", f"txt   : {tp}")
                tag("+", f"html  : {hp}")
            except Exception as e:
                tag("!", str(e))


def _print_summary(inv, mode="standard"):
    s = inv["summary"]

    _fake = re.compile(
        r"(Email used)|(Using sites database)|(Search completed)"
        r"|(Short text report)|(Phone number used)|(Phone number not used)|(Rate limit)"
    )

    findings = []
    seen = set()

    for r in inv["results"]:
        if not r.get("ok"):
            continue
        hits = []
        for ln in (r.get("output") or "").splitlines():
            clean = _ANSI_STRIP.sub("", ln).strip()
            if not clean.startswith("[+]"):
                continue
            if _fake.search(clean):
                continue
            content = clean[4:].strip()
            if content and content not in seen:
                seen.add(content)
                hits.append(content)
        if hits:
            findings.append((r["module"], hits))

    p()
    hr("═")
    p(f"  {c(_B, 'RESULT')}")
    p(f"  ok:{c(_GRN, str(s['ok']))}  failed:{c(_RED, str(s['fail']))}  "
      f"total:{s['total']}  {c(_D, str(inv['elapsed']) + 's')}")

    if findings:
        p()
        p(f"  {c(_B, 'FINDINGS')}")
        hr()
        for mod, hits in findings:
            p(f"  {c(_GRY2, '[' + mod + ']')}")
            for h in hits:
                p(f"  {c(_GRN, '[+]')} {h}")
            p()

    if inv.get("pivots"):
        p()
        p(f"  {c(_B, 'PIVOTS')}")
        for pt, vals in inv["pivots"].items():
            p(f"  {c(_GRY2, '[' + pt + ']')}  {', '.join(vals[:6])}")
        p()
        p(f"  {c(_D, 'investigate:')}")
        for pt, vals in inv["pivots"].items():
            for v in vals[:6]:
                q = f'"{v}"' if " " in v else v
                p(f"  {c(_GRY, '$')} python3 wiwok.py -m {mode} {c(_B, q)}")


def main():
    import warnings
    warnings.filterwarnings("ignore")

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    for d in (os.path.expanduser("~/.local/bin"), "/usr/local/bin"):
        if os.path.isdir(d) and d not in os.environ.get("PATH", ""):
            os.environ["PATH"] = d + ":" + os.environ["PATH"]

    ap = argparse.ArgumentParser(prog="wiwok", add_help=False)
    ap.add_argument("target", nargs="?")
    ap.add_argument("-t", "--type", dest="ttype", default="",
                    choices=["username", "email", "phone", "name"])
    ap.add_argument("-m", "--mode", default="standard",
                    choices=["quick", "standard", "deep"])
    ap.add_argument("-r", "--run",   default="")
    ap.add_argument("-P", "--pivot", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--setup",     action="store_true")
    ap.add_argument("--update",    action="store_true")
    ap.add_argument("--check",     action="store_true")
    ap.add_argument("--no-color",  action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    args = ap.parse_args()

    global _NO_COLOR
    if args.no_color:
        _NO_COLOR = True

    if args.help or len(sys.argv) == 1:
        cmd_help()
    elif args.setup:
        cmd_setup()
    elif args.update:
        cmd_update()
    elif args.check:
        cmd_check()
    elif args.target:
        try:
            target = sanitize(args.target)
        except ValueError as e:
            tag("!", str(e))
            sys.exit(1)

        ttype = args.ttype or detect_type(target)
        only  = [x.strip() for x in args.run.split(",")] if args.run else None

        if not args.quiet:
            banner()
            p()
            hr()
            kv("target",  target)
            kv("type",    ttype)
            kv("mode",    args.mode)
            kv("time",    datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
            kv("workers", str(CFG.get("workers", 4)))
            if only:
                kv("modules", ", ".join(only))
            hr()
            p()

        inv = investigate(target, ttype, args.mode, only, quiet=args.quiet)
        _print_summary(inv, args.mode)

        if inv.get("missing") and not args.quiet:
            p()
            p(f"  {c(_D, 'not installed: ' + ', '.join(inv['missing']))}")

        p()
        hr()
        try:
            jp = save_json(inv)
            tp = save_txt(inv)
            hp = save_html(inv)
            tag("+", f"json  : {jp}")
            tag("+", f"txt   : {tp}")
            tag("+", f"html  : {hp}")
        except Exception as e:
            tag("!", f"save error: {e}")
        hr("═")

        if args.pivot:
            cmd_pivot(inv, args.mode, args.quiet)
    else:
        cmd_help()


if __name__ == "__main__":
    main()
