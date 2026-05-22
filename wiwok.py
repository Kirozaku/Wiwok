#!/usr/bin/env python3

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

VERSION = "6.0.0-db2"
CFG_FILE = os.path.expanduser("~/.wiwok.json")
OUT_DIR  = os.path.expanduser("~/wiwok_results")
PLUG_DIR = os.path.expanduser("~/.wiwok_plugins")

DEFAULTS = {
    "workers": 6,
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
    except json.JSONDecodeError as e:
        print(f"  [!] {CFG_FILE} tidak valid (JSON error: {e}), pakai defaults.", file=sys.stderr)
    except Exception as e:
        print(f"  [!] gagal baca config: {e}", file=sys.stderr)
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
    def __init__(self, delay=0.35):
        self._last = {}
        self._lock = threading.Lock()
        self.delay = delay

    def wait(self, domain):
        with self._lock:
            gap = time.time() - self._last.get(domain, 0)
            sleep_time = max(0.0, self.delay - gap)
            self._last[domain] = time.time() + sleep_time
        if sleep_time > 0:
            time.sleep(sleep_time)

_RL = RateLimiter()

_CACHE_SENTINEL = object()

class Cache:
    """In-memory request cache, thread-safe, dengan TTL untuk cegah memory leak."""
    def __init__(self, ttl=300):
        self.store = {}
        self.timestamps = {}
        self._lock = threading.Lock()
        self.ttl = ttl

    def _expired(self, k):
        ts = self.timestamps.get(k)
        return ts is None or (time.time() - ts) > self.ttl

    def get(self, k):
        with self._lock:
            if k in self.store and not self._expired(k):
                return self.store[k]
            self.store.pop(k, None)
            self.timestamps.pop(k, None)
            return _CACHE_SENTINEL

    def has(self, k):
        with self._lock:
            return k in self.store and not self._expired(k)

    def put(self, k, v):
        with self._lock:
            self.store[k] = v
            self.timestamps[k] = time.time()
            if len(self.store) > 2000:
                now = time.time()
                expired = [ek for ek, ts in self.timestamps.items()
                           if now - ts > self.ttl]
                for ek in expired:
                    self.store.pop(ek, None)
                    self.timestamps.pop(ek, None)

_CACHE = Cache()

def http_get(url, headers=None, timeout=15, data=None, method=None):
    """
    HTTP GET (atau POST jika data diisi). Semua modul harus pakai fungsi ini.

    Perbaikan v6.1:
    - FIX: Tidak cache error transient (429, 503, 504, timeout, DNS fail).
      Hanya cache error permanen (404, 410, 451) dan sukses.
      Sebelumnya semua error di-cache → retry logic jadi tidak berguna.
    - FIX: Validasi scheme & host pada redirect untuk cegah SSRF.
      Server bisa redirect ke file://, http://127.0.0.1, atau IP metadata cloud.
    - FIX: Support POST body (parameter `data`) sehingga modul GraphQL
      (AniList, Hashnode) bisa pakai cache, RateLimiter, dan redirect limit
      yang sama — tidak bypass lagi.
    """
    import ipaddress

    _PERMANENT_ERRORS = frozenset([404, 410, 451])

    domain = urllib.parse.urlparse(url).netloc
    method_str = "POST" if data else "GET"
    cache_raw = method_str + ":" + url + "||" + (data.decode("utf-8", errors="replace") if data else "")
    key = hashlib.md5(cache_raw.encode()).hexdigest()

    cached = _CACHE.get(key)
    if cached is not _CACHE_SENTINEL:
        return cached

    _RL.wait(domain)

    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
    if headers:
        hdrs.update(headers)

    def _is_safe_host(hostname):
        if not hostname:
            return False
        blocked_names = {"localhost", "ip6-localhost", "ip6-loopback"}
        if hostname.lower() in blocked_names:
            return False
        try:
            if re.match(r'^(0x[0-9a-fA-F]+|0[0-7]+|\d+)$', hostname):
                ip = ipaddress.ip_address(int(hostname, 0))
            else:
                ip = ipaddress.ip_address(hostname)
            return not (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast)
        except (ValueError, TypeError):
            pass
        return True

    class _SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs_r, newurl):
            count = getattr(req, "_redirect_count", 0)
            if count >= 5:
                return None
            parsed = urllib.parse.urlparse(newurl)
            if parsed.scheme not in ("http", "https"):
                return None
            if not _is_safe_host(parsed.hostname):
                return None
            req._redirect_count = count + 1
            return super().redirect_request(req, fp, code, msg, hdrs_r, newurl)

    opener = urllib.request.build_opener(_SafeRedirect())

    try:
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        with opener.open(req, timeout=timeout) as r:
            result = r.read().decode("utf-8", errors="replace")
        _CACHE.put(key, result)
        return result
    except urllib.error.HTTPError as e:
        if e.code in _PERMANENT_ERRORS:
            _CACHE.put(key, None)
        return None
    except urllib.error.URLError:
        return None
    except Exception:
        return None

def http_post(url, body, headers=None, timeout=15):
    """Wrapper POST untuk modul yang butuh POST body (GraphQL, dll)."""
    post_headers = {"Content-Type": "application/json"}
    if headers:
        post_headers.update(headers)
    data = body if isinstance(body, bytes) else body.encode("utf-8")
    return http_get(url, headers=post_headers, timeout=timeout, data=data, method="POST")

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
    uname_m  = re.search(
        r'"username"\s*:\s*"' + re.escape(target.lower()) + r'"',
        raw.lower()
    )

    if not (name_m or follow_m or post_m or uname_m):
        return "  not found or blocked by Instagram"

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

    _LOGIN_SIGNALS = ('"loginPage"', 'id="email"', '"loginForm"', 'name="login"',
                      '"requireLogin"', 'action="/login"', '"login_form"')
    if any(sig in raw for sig in _LOGIN_SIGNALS):
        return "  not found or private (login wall)"

    uid_m = re.search(r'"userID"\s*:\s*"(\d+)"', raw)
    canonical_m = re.search(
        r'og:url[^>]*content="https://(?:www\.)?facebook\.com/' + re.escape(target) + r'["/]',
        raw, re.I
    )
    if not uid_m or not canonical_m:
        return "  not found or private"

    title_m = re.search(r"<title>([^<]+)</title>", raw)
    title = ""
    if title_m:
        title = title_m.group(1)
        title = title.replace(" | Facebook", "").replace(" - Facebook", "").strip()

    out = [
        "  [+] possible account found on Facebook",
        f"  url  : https://www.facebook.com/{target}",
        f"  uid  : {uid_m.group(1)}",
    ]
    if title and title.lower() not in ("facebook",):
        out.insert(2, f"  name : {title}")
    return "\n".join(out)

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

def _mod_emailrep(target):
    raw = http_get(f"https://emailrep.io/{urllib.parse.quote(target)}")
    if not raw:
        return "  no data"
    try:
        d = json.loads(raw)
        det = d.get("details", {})
        lines = [
            f"  reputation    : {d.get('reputation', '-')}",
            f"  suspicious    : {d.get('suspicious', '-')}",
            f"  malicious     : {det.get('malicious_activity', '-')}",
            f"  data_breach   : {det.get('data_breach', '-')}",
            f"  credentials   : {det.get('credentials_leaked', '-')}",
            f"  deliverable   : {det.get('deliverable', '-')}",
            f"  disposable    : {det.get('disposable', '-')}",
        ]
        profiles = det.get("profiles", [])
        if profiles:
            lines.append(f"  platforms     : {', '.join(profiles)}")
        return "\n".join(lines)
    except Exception:
        return "  parse error"

def _mod_xposedornot(target):
    raw = http_get(f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(target)}")
    if not raw:
        return "  no data / not found in breaches"
    try:
        d = json.loads(raw)
        if "Error" in d or not d.get("breaches"):
            return "  no breaches found"
        breaches = d.get("breaches", [])
        out = [f"  {len(breaches)} breach(es) found"]
        for b in breaches[:10]:
            if isinstance(b, list):
                out.append(f"  · {b[0]}" if b else "")
            else:
                out.append(f"  · {b}")
        return "\n".join(out)
    except Exception:
        return "  no breaches found"

def _mod_hibp(target):
    raw = http_get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(target)}?truncateResponse=true",
        headers={"User-Agent": "wiwok/5.0-osint"}
    )
    if not raw:
        return "  not found in any breaches (or rate limited)"
    try:
        items = json.loads(raw)
        out = [f"  {len(items)} breach(es) found"]
        for it in items[:15]:
            out.append(f"  · {it.get('Name', '?')}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_gitlab_profile(target):
    raw = http_get(f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(target)}")
    if not raw:
        return "  not found"
    try:
        items = json.loads(raw)
        if not items:
            return "  not found"
        u = items[0]
        lines = [
            f"  [+] account found on GitLab",
            f"  url       : {u.get('web_url', '-')}",
            f"  name      : {u.get('name', '-')}",
            f"  username  : {u.get('username', '-')}",
            f"  bio       : {(u.get('bio') or '')[:80]}",
            f"  location  : {u.get('location') or '-'}",
            f"  state     : {u.get('state', '-')}",
            f"  created   : {(u.get('created_at') or '')[:10]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_codeberg_profile(target):
    raw = http_get(f"https://codeberg.org/api/v1/users/{urllib.parse.quote(target)}")
    if not raw:
        return "  not found"
    try:
        u = json.loads(raw)
        if u.get("message"):
            return "  not found"
        lines = [
            f"  [+] account found on Codeberg",
            f"  url       : {u.get('html_url', '-')}",
            f"  name      : {u.get('full_name') or u.get('login', '-')}",
            f"  location  : {u.get('location') or '-'}",
            f"  website   : {u.get('website') or '-'}",
            f"  email     : {u.get('email') or '-'}",
            f"  repos     : {u.get('public_repos', 0)}",
            f"  followers : {u.get('followers', 0)}",
            f"  created   : {(u.get('created') or '')[:10]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_bluesky_profile(target):
    handle = target if "." in target else f"{target}.bsky.social"
    raw = http_get(
        f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={urllib.parse.quote(handle)}"
    )
    if not raw:
        raw2 = http_get(
            f"https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q={urllib.parse.quote(target)}&limit=3"
        )
        if raw2:
            try:
                actors = json.loads(raw2).get("actors", [])
                if actors:
                    a = actors[0]
                    return (
                        f"  [~] possible match on Bluesky (search)\n"
                        f"  handle    : {a.get('handle', '-')}\n"
                        f"  name      : {a.get('displayName', '-')}\n"
                        f"  bio       : {(a.get('description') or '')[:80]}\n"
                        f"  url       : https://bsky.app/profile/{a.get('handle', '')}"
                    )
            except Exception:
                pass
        return "  not found on Bluesky"
    try:
        p = json.loads(raw)
        lines = [
            f"  [+] account found on Bluesky",
            f"  handle    : {p.get('handle', '-')}",
            f"  name      : {p.get('displayName', '-')}",
            f"  bio       : {(p.get('description') or '')[:80]}",
            f"  followers : {p.get('followersCount', 0)}",
            f"  following : {p.get('followsCount', 0)}",
            f"  posts     : {p.get('postsCount', 0)}",
            f"  url       : https://bsky.app/profile/{p.get('handle', '')}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_mastodon_search(target):
    instances = ["mastodon.social", "infosec.exchange", "fosstodon.org", "hachyderm.io"]
    results = []
    for inst in instances:
        raw = http_get(
            f"https://{inst}/api/v1/accounts/lookup?acct={urllib.parse.quote(target)}"
        )
        if not raw:
            continue
        try:
            a = json.loads(raw)
            if a.get("id"):
                results.append(
                    f"  [+] @{target}@{inst}\n"
                    f"       name      : {a.get('display_name', '-')}\n"
                    f"       url       : {a.get('url', '-')}\n"
                    f"       followers : {a.get('followers_count', 0)}\n"
                    f"       posts     : {a.get('statuses_count', 0)}"
                )
        except Exception:
            continue
    return "\n".join(results) if results else "  not found on checked Mastodon instances"

def _mod_hackernews_profile(target):
    raw = http_get(
        f"https://hacker-news.firebaseio.com/v0/user/{urllib.parse.quote(target)}.json"
    )
    if not raw or raw.strip() == "null":
        return "  not found"
    try:
        u = json.loads(raw)
        created = datetime.utcfromtimestamp(u.get("created", 0)).strftime("%Y-%m-%d") if u.get("created") else "-"
        about = re.sub(r"<[^>]+>", "", u.get("about", "") or "")[:100]
        lines = [
            f"  [+] account found on HackerNews",
            f"  url       : https://news.ycombinator.com/user?id={target}",
            f"  karma     : {u.get('karma', 0)}",
            f"  created   : {created}",
            f"  about     : {about}",
            f"  submitted : {len(u.get('submitted', []))} items",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_stackexchange_profile(target):
    url = f"https://api.stackexchange.com/2.3/users?inname={urllib.parse.quote(target)}&site=stackoverflow&pagesize=5"
    raw = http_get(url, timeout=15)
    if not raw:
        return "  no data"
    try:
        data = json.loads(raw)
        items = data.get("items", [])
        if not items:
            return "  not found on StackOverflow"
        out = [f"  {len(items)} result(s) on StackExchange"]
        for u in items[:3]:
            loc  = u.get("location", "")
            web  = u.get("website_url", "")
            line = f"  [+] {u.get('display_name','')}  rep:{u.get('reputation',0)}"
            if loc: line += f"  loc:{loc}"
            out.append(line)
            out.append(f"       url : {u.get('link', '-')}")
            if web: out.append(f"       web : {web}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_lobsters_profile(target):
    raw = http_get(f"https://lobste.rs/u/{urllib.parse.quote(target)}.json")
    if not raw:
        return "  not found"
    try:
        u = json.loads(raw)
        if not u.get("username"):
            return "  not found"
        lines = [
            f"  [+] account found on Lobsters",
            f"  url         : https://lobste.rs/u/{target}",
            f"  karma       : {u.get('karma', 0)}",
            f"  created     : {(u.get('created_at') or '')[:10]}",
            f"  about       : {(u.get('about') or '')[:80]}",
            f"  invited_by  : {u.get('invited_by_user', '-')}",
            f"  github      : {u.get('github_username', '-')}",
        ]
        if u.get("github_username"):
            lines.append(f"  [+] github username: {u['github_username']}")
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_npm_profile(target):
    raw = http_get(
        f"https://registry.npmjs.org/-/v1/search?text=author:{urllib.parse.quote(target)}&size=10"
    )
    out = []
    if raw:
        try:
            objs = json.loads(raw).get("objects", [])
            emails = set()
            for o in objs:
                pkg = o.get("package", {})
                em  = (pkg.get("author") or {}).get("email", "")
                if em: emails.add(em)
            if emails:
                out.append(f"  [+] emails found via npm packages:")
                for e in sorted(emails):
                    out.append(f"  · {e}")
            out.append(f"  packages  : {len(objs)} found (author:{target})")
            for o in objs[:5]:
                pkg = o.get("package", {})
                out.append(f"  · {pkg.get('name','-')}  v{pkg.get('version','-')}")
        except Exception:
            pass
    raw2 = http_get(f"https://www.npmjs.com/~{urllib.parse.quote(target)}")
    if raw2 and f'"name":"{target}"' in raw2.lower():
        out.insert(0, f"  [+] npm profile: https://www.npmjs.com/~{target}")
    return "\n".join(out) if out else "  not found on npm"

def _mod_pypi_profile(target):
    raw = http_get(f"https://pypi.org/pypi/{urllib.parse.quote(target)}/json")
    if not raw:
        return "  package not found on PyPI"
    try:
        info = json.loads(raw).get("info", {})
        lines = [
            f"  [+] package found on PyPI",
            f"  name      : {info.get('name', '-')}",
            f"  version   : {info.get('version', '-')}",
            f"  author    : {info.get('author', '-')}",
            f"  email     : {info.get('author_email', '-')}",
            f"  home_page : {info.get('home_page', '-')}",
            f"  summary   : {(info.get('summary') or '')[:80]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_cratesio_profile(target):
    raw = http_get(
        f"https://crates.io/api/v1/users/{urllib.parse.quote(target)}",
        headers={"User-Agent": "wiwok/5.0 (osint-research)"}
    )
    if not raw:
        return "  not found on crates.io"
    try:
        u = json.loads(raw).get("user", {})
        if not u:
            return "  not found on crates.io"
        lines = [
            f"  [+] account found on crates.io",
            f"  url       : {u.get('url', '-')}",
            f"  name      : {u.get('name') or '-'}",
            f"  login     : {u.get('login', '-')}",
            f"  github_id : {u.get('id', '-')}",
            f"  avatar    : {u.get('avatar', '-')}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_rubygems_profile(target):
    raw = http_get(f"https://rubygems.org/api/v1/owners/{urllib.parse.quote(target)}/gems.json")
    if not raw:
        return "  not found on RubyGems"
    try:
        gems = json.loads(raw)
        if not isinstance(gems, list) or not gems:
            return "  no gems found for this user"
        out = [f"  [+] {len(gems)} gem(s) on RubyGems for {target}"]
        github_links = set()
        for g in gems[:8]:
            out.append(f"  · {g.get('name','-')}  v{g.get('version','-')}")
            src = g.get("source_code_uri", "") or ""
            if "github.com" in src:
                github_links.add(src)
        if github_links:
            out.append("  github links:")
            for l in github_links:
                out.append(f"  · {l}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_dockerhub_profile(target):
    raw = http_get(f"https://hub.docker.com/v2/users/{urllib.parse.quote(target)}/")
    if not raw:
        return "  not found on Docker Hub"
    try:
        u = json.loads(raw)
        if u.get("detail"):
            return "  not found on Docker Hub"
        lines = [
            f"  [+] account found on Docker Hub",
            f"  url       : https://hub.docker.com/u/{target}",
            f"  name      : {u.get('full_name') or '-'}",
            f"  company   : {u.get('company') or '-'}",
            f"  location  : {u.get('location') or '-'}",
            f"  joined    : {(u.get('date_joined') or '')[:10]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_devto_profile(target):
    raw = http_get(f"https://dev.to/api/users/by_username?url={urllib.parse.quote(target)}")
    if not raw:
        return "  not found on dev.to"
    try:
        u = json.loads(raw)
        if u.get("error"):
            return "  not found on dev.to"
        lines = [
            f"  [+] account found on dev.to",
            f"  url       : https://dev.to/{target}",
            f"  name      : {u.get('name', '-')}",
            f"  summary   : {(u.get('summary') or '')[:80]}",
            f"  location  : {u.get('location') or '-'}",
            f"  twitter   : {u.get('twitter_username') or '-'}",
            f"  github    : {u.get('github_username') or '-'}",
            f"  website   : {u.get('website_url') or '-'}",
            f"  followers : {u.get('followers_count', 0)}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_chesscom_profile(target):
    raw = http_get(f"https://api.chess.com/pub/player/{urllib.parse.quote(target.lower())}")
    if not raw:
        return "  not found on Chess.com"
    try:
        p = json.loads(raw)
        if p.get("code") == 0:
            return "  not found on Chess.com"
        country_raw = p.get("country", "")
        country = country_raw.split("/")[-1] if country_raw else "-"
        ts = p.get("last_online", 0)
        last_on = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else "-"
        joined_ts = p.get("joined", 0)
        joined = datetime.utcfromtimestamp(joined_ts).strftime("%Y-%m-%d") if joined_ts else "-"
        lines = [
            f"  [+] account found on Chess.com",
            f"  url       : {p.get('url', '-')}",
            f"  name      : {p.get('name') or '-'}",
            f"  title     : {p.get('title') or '-'}",
            f"  followers : {p.get('followers', 0)}",
            f"  country   : {country}",
            f"  location  : {p.get('location') or '-'}",
            f"  joined    : {joined}",
            f"  last_on   : {last_on}",
            f"  twitch    : {p.get('twitch_url') or '-'}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_lichess_profile(target):
    raw = http_get(f"https://lichess.org/api/user/{urllib.parse.quote(target)}")
    if not raw:
        return "  not found on Lichess"
    try:
        u = json.loads(raw)
        if not u.get("id"):
            return "  not found on Lichess"
        prof = u.get("profile", {})
        ts = u.get("createdAt", 0)
        created = datetime.utcfromtimestamp(ts // 1000).strftime("%Y-%m-%d") if ts else "-"
        links = (prof.get("links") or "")[:120]
        lines = [
            f"  [+] account found on Lichess",
            f"  url       : https://lichess.org/@/{target}",
            f"  name      : {prof.get('realName') or '-'}",
            f"  country   : {prof.get('country') or '-'}",
            f"  location  : {prof.get('location') or '-'}",
            f"  bio       : {(prof.get('bio') or '')[:80]}",
            f"  links     : {links}",
            f"  followers : {u.get('nbFollowers', 0)}",
            f"  created   : {created}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_discogs_profile(target):
    raw = http_get(
        f"https://api.discogs.com/users/{urllib.parse.quote(target)}",
        headers={"User-Agent": "wiwok/5.0 +osint-research"}
    )
    if not raw:
        return "  not found on Discogs"
    try:
        u = json.loads(raw)
        if u.get("message"):
            return "  not found on Discogs"
        lines = [
            f"  [+] account found on Discogs",
            f"  url       : {u.get('uri', '-')}",
            f"  name      : {u.get('name') or '-'}",
            f"  location  : {u.get('location') or '-'}",
            f"  profile   : {(u.get('profile') or '')[:80]}",
            f"  collection: {u.get('num_collection', 0)}",
            f"  registered: {(u.get('registered') or '')[:10]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_myanimelist_profile(target):
    raw = http_get(f"https://api.jikan.moe/v4/users/{urllib.parse.quote(target)}")
    if not raw:
        return "  not found on MyAnimeList"
    try:
        d = json.loads(raw).get("data", {})
        if not d:
            return "  not found on MyAnimeList"
        bday = (d.get("birthday") or "")[:10]
        joined = (d.get("joined") or "")[:10]
        lines = [
            f"  [+] account found on MyAnimeList",
            f"  url       : {d.get('url', '-')}",
            f"  username  : {d.get('username', '-')}",
            f"  gender    : {d.get('gender') or '-'}",
            f"  birthday  : {bday or '-'}",
            f"  location  : {d.get('location') or '-'}",
            f"  joined    : {joined or '-'}",
            f"  about     : {(d.get('about') or '')[:80]}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  parse error"

def _mod_anilist_profile(target):
    body = json.dumps({
        "query": "query($n:String!){User(name:$n){id name about siteUrl createdAt}}",
        "variables": {"n": target}
    })
    raw = http_post("https://graphql.anilist.co", body)
    if not raw:
        return "  not found on AniList"
    try:
        u = (json.loads(raw).get("data") or {}).get("User") or {}
        if not u.get("id"):
            return "  not found on AniList"
        created = datetime.utcfromtimestamp(u.get("createdAt", 0)).strftime("%Y-%m-%d") if u.get("createdAt") else "-"
        about = re.sub(r"<[^>]+>", "", u.get("about", "") or "")[:80]
        lines = [
            f"  [+] account found on AniList",
            f"  url       : {u.get('siteUrl', '-')}",
            f"  name      : {u.get('name', '-')}",
            f"  about     : {about}",
            f"  created   : {created}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  not found or error"

def _mod_pinboard_profile(target):
    raw = http_get(f"https://feeds.pinboard.in/json/u:{urllib.parse.quote(target)}/")
    if not raw:
        return "  not found or no public bookmarks"
    try:
        items = json.loads(raw)
        if not items:
            return "  no public bookmarks"
        tags = {}
        for item in items:
            for t in (item.get("t") or []):
                tags[t] = tags.get(t, 0) + 1
        top_tags = sorted(tags, key=lambda x: -tags[x])[:10]
        out = [
            f"  [+] public bookmarks found on Pinboard",
            f"  url       : https://pinboard.in/u:{target}",
            f"  bookmarks : {len(items)} (showing sample)",
            f"  top tags  : {', '.join(top_tags)}",
        ]
        for item in items[:5]:
            out.append(f"  · {item.get('u', '-')[:80]}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_orcid_search(target):
    target_words = [w for w in target.lower().split() if len(w) > 1]

    parts = target.strip().split()
    if len(parts) >= 2:
        given  = urllib.parse.quote(parts[0])
        family = urllib.parse.quote(parts[-1])
        q = f"given-names:{given}+AND+family-name:{family}"
    else:
        q = urllib.parse.quote(target)

    raw = http_get(
        f"https://pub.orcid.org/v3.0/search/?q={q}&rows=5",
        headers={"Accept": "application/json"}
    )
    if not raw:
        return "  no results from ORCID"
    try:
        d = json.loads(raw)
        results = d.get("result", [])
        if not results:
            return "  no ORCID records found"

        validated = []
        for r in results[:5]:
            oid = r.get("orcid-identifier", {}).get("path", "")
            if not oid:
                continue
            person = r.get("person") or {}
            name_block = person.get("name") or {}
            given_val  = (name_block.get("given-names") or {}).get("value", "")
            family_val = (name_block.get("family-name") or {}).get("value", "")
            full_name  = f"{given_val} {family_val}".lower().strip()

            if full_name and full_name != " ":
                matched = sum(1 for tw in target_words if tw in full_name)
                threshold = len(target_words) if len(target_words) <= 2 else len(target_words) - 1
                if matched < threshold:
                    continue

            validated.append(oid)

        if not validated:
            validated = [
                r.get("orcid-identifier", {}).get("path", "")
                for r in results[:5]
                if r.get("orcid-identifier", {}).get("path")
            ]

        if not validated:
            return "  no ORCID records found"

        out = [f"  {len(validated)} ORCID record(s) found"]
        for oid in validated:
            out.append(f"  · https://orcid.org/{oid}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_openalex_search(target):
    raw = http_get(
        f"https://api.openalex.org/authors?search={urllib.parse.quote(target)}&per_page=5&mailto=osint@research.io"
    )
    if not raw:
        return "  no results from OpenAlex"
    try:
        results = json.loads(raw).get("results", [])
        if not results:
            return "  not found on OpenAlex"
        out = [f"  {len(results)} author(s) found on OpenAlex"]
        for a in results[:3]:
            inst = (a.get("last_known_institution") or {}).get("display_name", "-")
            orcid = (a.get("ids") or {}).get("orcid", "-")
            out.append(
                f"  [+] {a.get('display_name','-')}\n"
                f"       institution : {inst}\n"
                f"       works       : {a.get('works_count',0)}\n"
                f"       citations   : {a.get('cited_by_count',0)}\n"
                f"       orcid       : {orcid}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_semanticscholar_search(target):
    raw = http_get(
        f"https://api.semanticscholar.org/graph/v1/author/search?"
        f"query={urllib.parse.quote(target)}&fields=name,paperCount,citationCount,affiliations"
    )
    if not raw:
        return "  no results from Semantic Scholar"
    try:
        items = json.loads(raw).get("data", [])
        if not items:
            return "  not found on Semantic Scholar"
        out = [f"  {len(items)} author(s) on Semantic Scholar"]
        for a in items[:3]:
            aff = ", ".join(x.get("name","") for x in (a.get("affiliations") or []))
            out.append(
                f"  [+] {a.get('name','-')}\n"
                f"       papers    : {a.get('paperCount',0)}\n"
                f"       citations : {a.get('citationCount',0)}\n"
                f"       affil     : {aff or '-'}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_crossref_search(target):
    raw = http_get(
        f"https://api.crossref.org/works?query.author={urllib.parse.quote(target)}&rows=10&mailto=osint@research.io"
    )
    if not raw:
        return "  no results from CrossRef"
    try:
        items = json.loads(raw).get("message", {}).get("items", [])
        if not items:
            return "  no works found on CrossRef"

        target_words = [w for w in target.lower().split() if len(w) > 1]

        def _author_matches(work):
            authors = work.get("author") or []
            for a in authors:
                full_name = f"{a.get('given', '')} {a.get('family', '')}".lower()
                matched = sum(1 for tw in target_words if tw in full_name)
                threshold = len(target_words) if len(target_words) <= 2 else len(target_words) - 1
                if matched >= threshold:
                    return True
            return False

        matched_items = [w for w in items if _author_matches(w)]
        if not matched_items:
            return f"  no confirmed works for '{target}' as author on CrossRef"

        out = [f"  {len(matched_items)} work(s) found on CrossRef"]
        for w in matched_items[:5]:
            title = (w.get("title") or ["-"])[0]
            authors = ", ".join(
                f"{a.get('given','')} {a.get('family','')}" for a in (w.get("author") or [])[:3]
            )
            doi = w.get("DOI", "-")
            out.append(f"  · {title[:70]}")
            out.append(f"    authors : {authors[:80]}")
            out.append(f"    doi     : https://doi.org/{doi}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_openlibrary_search(target):
    raw = http_get(
        f"https://openlibrary.org/search/authors.json?q={urllib.parse.quote(target)}"
    )
    if not raw:
        return "  no results from Open Library"
    try:
        docs = json.loads(raw).get("docs", [])
        if not docs:
            return "  not found on Open Library"
        out = [f"  {len(docs)} author(s) on Open Library"]
        for a in docs[:3]:
            out.append(
                f"  [+] {a.get('name', '-')}\n"
                f"       birth_date : {a.get('birth_date', '-')}\n"
                f"       work_count : {a.get('work_count', 0)}\n"
                f"       top_work   : {(a.get('top_work') or '-')[:60]}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_opencorporates_search(target):
    raw = http_get(
        f"https://api.opencorporates.com/v0.4/officers/search?q={urllib.parse.quote(target)}&per_page=5"
    )
    if not raw:
        return "  no results from OpenCorporates"
    try:
        officers = json.loads(raw).get("results", {}).get("officers", [])
        if not officers:
            return "  no corporate records found"
        out = [f"  {len(officers)} officer record(s) found"]
        for item in officers[:5]:
            o = item.get("officer", {})
            co = o.get("company", {})
            out.append(
                f"  [+] {o.get('name','-')}  —  {o.get('position','-')}\n"
                f"       company    : {co.get('name','-')}\n"
                f"       juris.     : {co.get('jurisdiction_code','-')}\n"
                f"       inactive   : {o.get('inactive', False)}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_opensanctions_search(target):
    raw = http_get(
        f"https://api.opensanctions.org/search/?q={urllib.parse.quote(target)}&limit=5"
    )
    if not raw:
        return "  no results from OpenSanctions"
    try:
        results = json.loads(raw).get("results", [])
        if not results:
            return "  not found in sanctions/watchlists"
        out = [f"  {len(results)} result(s) in OpenSanctions"]
        for e in results[:5]:
            props = e.get("properties", {})
            nationality = ", ".join(props.get("nationality", ["-"]))
            dob = ", ".join(props.get("birthDate", ["-"]))
            datasets = ", ".join(e.get("datasets", [])[:3])
            out.append(
                f"  [+] {e.get('caption', '-')}  schema:{e.get('schema','-')}\n"
                f"       nationality : {nationality}\n"
                f"       DOB         : {dob}\n"
                f"       datasets    : {datasets}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_fec_search(target):
    raw = http_get(
        f"https://api.open.fec.gov/v1/schedules/schedule_a/"
        f"?contributor_name={urllib.parse.quote(target)}&api_key=DEMO_KEY&per_page=5&sort=-contribution_receipt_date"
    )
    if not raw:
        return "  no results from FEC (US donors only)"
    try:
        items = json.loads(raw).get("results", [])
        if not items:
            return "  not found in FEC donor records"
        out = [f"  {len(items)} FEC donation record(s) found (US only)"]
        for d in items[:5]:
            out.append(
                f"  [+] {d.get('contributor_name','-')}\n"
                f"       city       : {d.get('contributor_city','-')}, {d.get('contributor_state','-')}\n"
                f"       employer   : {d.get('contributor_employer','-')}\n"
                f"       occupation : {d.get('contributor_occupation','-')}\n"
                f"       amount     : ${d.get('contribution_receipt_amount',0)}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_gdelt_news(target):
    q = urllib.parse.quote(f'"{target}"')
    raw = http_get(
        f"https://api.gdeltproject.org/api/v2/doc/doc?query={q}&mode=artlist&format=json&maxrecords=10"
    )
    if not raw:
        return "  no results from GDELT"
    try:
        articles = json.loads(raw).get("articles", [])
        if not articles:
            return "  no news coverage found in GDELT"
        out = [f"  {len(articles)} article(s) found in GDELT news database"]
        for a in articles[:5]:
            out.append(f"  · [{a.get('seendate','')[:8]}] {a.get('title','')[:70]}")
            out.append(f"    {a.get('domain','-')}  lang:{a.get('language','-')}")
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_wikidata_search(target):
    raw = http_get(
        f"https://www.wikidata.org/w/api.php?action=wbsearchentities"
        f"&search={urllib.parse.quote(target)}&format=json&language=en&limit=5"
    )
    if not raw:
        return "  no results from Wikidata"
    try:
        results = json.loads(raw).get("search", [])
        if not results:
            return "  not found on Wikidata"

        target_lower = target.lower()
        target_words = set(target_lower.split())

        def _is_relevant(e):
            label = (e.get("label") or "").lower()
            desc  = (e.get("description") or "").lower()
            if target_lower in label or label in target_lower:
                return True
            if target_words and all(w in label for w in target_words):
                return True
            _PERSON_SIGNALS = ("human", "person", "researcher", "politician",
                               "scientist", "author", "actor", "musician",
                               "akademisi", "peneliti", "politisi")
            if any(sig in desc for sig in _PERSON_SIGNALS):
                if any(w in label for w in target_words if len(w) > 2):
                    return True
            return False

        relevant = [e for e in results if _is_relevant(e)]
        if not relevant:
            return "  not found on Wikidata"

        out = [f"  {len(relevant)} entity(ies) found on Wikidata"]
        for e in relevant[:5]:
            out.append(
                f"  [+] {e.get('label','-')}  [{e.get('id','-')}]\n"
                f"       description : {e.get('description', '-')[:80]}\n"
                f"       url         : https://www.wikidata.org/wiki/{e.get('id','')}"
            )
        return "\n".join(out)
    except Exception:
        return "  parse error"

def _mod_unavatar(target):
    providers = ["github", "twitter", "gravatar", "instagram"]
    lines = [f"  unavatar.io profile image URLs for '{target}':"]
    for prov in providers:
        lines.append(f"  · https://unavatar.io/{prov}/{target}")
    lines.append(f"  (open URL to see image, then reverse-search via TinEye/Yandex)")
    return "\n".join(lines)

def _mod_duckduckgo_search(target):
    raw = http_get(
        f"https://api.duckduckgo.com/?q={urllib.parse.quote(target)}&format=json&no_html=1&skip_disambig=1"
    )
    if not raw:
        return "  no results from DuckDuckGo"
    try:
        d = json.loads(raw)
        abstract = d.get("Abstract", "")
        abstract_src = d.get("AbstractSource", "")
        abstract_url = d.get("AbstractURL", "")
        image = d.get("Image", "")
        related = [r.get("Text", "")[:60] for r in d.get("RelatedTopics", [])[:5] if r.get("Text")]
        lines = []
        if abstract:
            lines.append(f"  [+] {abstract_src}: {abstract[:200]}")
            if abstract_url:
                lines.append(f"  url     : {abstract_url}")
            if image:
                lines.append(f"  image   : https://duckduckgo.com{image}")
        if related:
            lines.append("  related topics:")
            for r in related:
                lines.append(f"  · {r}")
        return "\n".join(lines) if lines else "  no instant answer found"
    except Exception:
        return "  parse error"

def _mod_hashnode_profile(target):
    body = json.dumps({
        "query": (
            "query($u:String!){"
            "  user(username:$u){"
            "    id username name tagline followersCount"
            "    posts(page:0,pageSize:1){totalDocuments}"
            "    publicationDomain"
            "  }"
            "}"
        ),
        "variables": {"u": target}
    })
    raw = http_post("https://gql.hashnode.com/", body)
    if not raw:
        return "  not found on Hashnode"
    try:
        u = (json.loads(raw).get("data") or {}).get("user") or {}
        if not u.get("id"):
            return "  not found on Hashnode"
        num_posts = (u.get("posts") or {}).get("totalDocuments", 0)
        lines = [
            f"  [+] account found on Hashnode",
            f"  url       : https://hashnode.com/@{target}",
            f"  name      : {u.get('name', '-')}",
            f"  tagline   : {(u.get('tagline') or '')[:80]}",
            f"  posts     : {num_posts}",
            f"  followers : {u.get('followersCount', 0)}",
            f"  blog      : {u.get('publicationDomain') or '-'}",
        ]
        return "\n".join(l for l in lines if l.split(':',1)[-1].strip() not in ('-',''))
    except Exception:
        return "  not found or error"

def _mod_telegram_check(target):
    """
    Cek akun/channel/bot Telegram via t.me preview page.

    Mengapa dedicated module dibutuhkan:
    t.me/{username} SELALU return HTTP 200 untuk username apa pun —
    baik yang ada maupun tidak ada. Cek HTTP status saja = 99% false positive.

    Strategi deteksi berlapis:
    1. Cek error signal eksplisit dulu (language-independent).
    2. Cek action button / resolve link yang HANYA muncul untuk akun valid.
    3. Extract metadata profil jika tersedia.
    """
    raw = http_get(
        f"https://t.me/{urllib.parse.quote(target)}",
        headers={"User-Agent": _UA}
    )
    if not raw:
        return "  not found or blocked"

    _ERROR_SIGNALS = (
        "Sorry, this link is broken",
        "tgme_page_ph_head",
        "link is broken",
        "Sorry, this username is invalid",
    )
    if any(sig in raw for sig in _ERROR_SIGNALS):
        return "  not found"

    has_action = "tgme_page_action_button" in raw
    has_resolve = f'tg://resolve?domain={target.lower()}' in raw.lower()
    has_private = any(s in raw for s in (
        "This channel is private", "Join Group", "Request to Join"
    ))

    if not (has_action or has_resolve or has_private):
        return "  not found or uncertain"

    name_m  = re.search(r'class="tgme_page_title"[^>]*>([^<]+)<', raw)
    desc_m  = re.search(r'class="tgme_page_description"[^>]*>(.*?)</div>', raw, re.S)
    subs_m  = re.search(r'([\d\s,\.]+)\s*(subscribers|members|online)', raw, re.I)
    if "tgme_channel_info" in raw or "subscribers" in raw.lower():
        acct_type = "channel/group"
    elif "bot" in target.lower() or "/start" in raw:
        acct_type = "bot"
    else:
        acct_type = "user"

    out = [
        f"  [+] Telegram {acct_type} found",
        f"  url  : https://t.me/{target}",
    ]
    if name_m:
        out.append(f"  name : {name_m.group(1).strip()}")
    if desc_m:
        desc = re.sub(r"<[^>]+>", "", desc_m.group(1)).strip()[:100]
        if desc:
            out.append(f"  desc : {desc}")
    if subs_m:
        out.append(f"  subs : {subs_m.group(1).strip()} {subs_m.group(2)}")
    if has_private:
        out.append("  note : account exists but is private")

    return "\n".join(out)

def _mod_whatsmyname(target):
    """Check username across key platforms using WMN-style HTTP status check."""
    platforms = [
        ("GitHub",    f"https://github.com/{target}"),
        ("GitLab",    f"https://gitlab.com/{target}"),
        ("Reddit",    f"https://www.reddit.com/user/{target}"),
        ("Medium",    f"https://medium.com/@{target}"),
        ("Substack",  f"https://{target}.substack.com"),
        ("Kaggle",    f"https://www.kaggle.com/{target}"),
        ("Replit",    f"https://replit.com/@{target}"),
        ("CodePen",   f"https://codepen.io/{target}"),
        ("Behance",   f"https://www.behance.net/{target}"),
        ("Dribbble",  f"https://dribbble.com/{target}"),
        ("Fiverr",    f"https://www.fiverr.com/{target}"),
        ("Tumblr",    f"https://{target}.tumblr.com"),
        ("Lichess",   f"https://lichess.org/@/{target}"),
        ("Chess.com", f"https://www.chess.com/member/{target}"),
        ("Lobsters",  f"https://lobste.rs/u/{target}"),
        ("Dev.to",    f"https://dev.to/{target}"),
        ("Hashnode",  f"https://hashnode.com/@{target}"),
    ]

    _REQUIRE = {
        "Medium":   [f'content="https://medium.com/@{target}"',
                     f'"@{target}"'],
        "Substack": ["<article", "post-preview", "subscriber-count",
                     f'"{target}.substack.com/p/'],
        "Tumblr":   ["tumblr-post", "post_micro", "post_id",
                     "tumblr-feed"],
        "Behance":  ["ProfileStats", "profile-stats", "appreciations",
                     f'"username":"{target}"'],
        "Dribbble": ["shots-grid", "profile-shots", "followers-count",
                     f'data-username="{target}"'],
        "Fiverr":   ["seller-profile", "gig-wrapper", "seller_card",
                     f'"username":"{target}"'],
        "Hashnode": [f'"username":"{target}"', "publication-title",
                     "follower-count", "article-card"],
        "Replit":   ["profile-header", "repl-tile", "UserProfile",
                     f'"username":"{target}"'],
        "Kaggle":   ["tier-badge", "competition-entry", "notebook-list",
                     f'"userName":"{target}"'],
    }

    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)"

    def _check_platform(name, url):
        body = http_get(url, timeout=8)
        if body is None:
            return False, name, url

        required = _REQUIRE.get(name)
        if required:
            if not any(s.lower() in body.lower() for s in required):
                return False, name, url
        _UNIVERSAL_ERRORS = (
            "page not found", "404 not found", "user not found",
            "this account doesn", "doesn't exist", "no longer available",
        )
        if any(e in body.lower() for e in _UNIVERSAL_ERRORS):
            return False, name, url
        return True, name, url

    found, notfound = [], []
    executor = ThreadPoolExecutor(max_workers=6)
    try:
        futs = {executor.submit(_check_platform, name, url): name for name, url in platforms}
        try:
            for f in as_completed(futs, timeout=60):
                try:
                    ok, name, url = f.result()
                    if ok:
                        found.append(f"  [+] {name:<14} {url}")
                    else:
                        notfound.append(name)
                except Exception:
                    notfound.append(futs[f])
        except TimeoutError:
            for fut, pname in futs.items():
                if not fut.done():
                    notfound.append(pname)
    finally:
        executor.shutdown(wait=False)

    out = [f"  checked {len(platforms)} platforms"]
    out += sorted(found)
    if notfound:
        out.append(f"  not found: {', '.join(sorted(notfound))}")
    return "\n".join(out)

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
    nm = re.search(r'"displayName"\s*:\s*"([^"]+)"', raw)
    if not nm:
        return "  not found"
    out = [
        "  [+] account found on Snapchat",
        f"  url : https://www.snapchat.com/add/{target}",
        f"  name: {nm.group(1)}",
    ]
    return "\n".join(out)

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

    if not nick and not fans:
        return "  not found or uncertain (may require JS rendering)"

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

    name = re.search(r'"channelMetadataRenderer"\s*:\s*\{"title"\s*:\s*"([^"]+)"', raw)
    subs = re.search(r'"subscriberCountText"[^}]*?"simpleText"\s*:\s*"([^"]+)"', raw)
    vids = re.search(r'"videosCountText"[^}]*?"runs"[^]]*?"text"\s*:\s*"([^"]+)"', raw)

    if not name:
        return "  uncertain (YouTube may require JS)"

    out = [
        "  [+] channel found on YouTube",
        f"  url         : https://www.youtube.com/@{target}",
        f"  name        : {name.group(1)}",
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

    login_m = re.search(r'"login"\s*:\s*"' + re.escape(target.lower()) + r'"', raw.lower())
    alt_m   = re.search(r'"alternateName"\s*:\s*"' + re.escape(target.lower()) + r'"', raw.lower())
    disp_m  = re.search(r'"displayName"\s*:\s*"([^"]+)"', raw)

    if not (login_m or alt_m):
        return "  not found"

    live = re.search(r'"isLiveBroadcast"\s*:\s*(true|false)', raw)
    out = [
        "  [+] channel found on Twitch",
        f"  url  : https://www.twitch.tv/{target}",
    ]
    if disp_m:
        out.append(f"  name : {disp_m.group(1)}")
    if live:
        out.append(f"  live : {live.group(1)}")
    return "\n".join(out)

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

    if not name and not follows and not pins:
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
    "emailrep":             _mod_emailrep,
    "xposedornot":          _mod_xposedornot,
    "hibp":                 _mod_hibp,
    "telegram_check":       _mod_telegram_check,
    "whatsmyname":          _mod_whatsmyname,
    "gitlab_profile":       _mod_gitlab_profile,
    "codeberg_profile":     _mod_codeberg_profile,
    "bluesky_profile":      _mod_bluesky_profile,
    "mastodon_search":      _mod_mastodon_search,
    "hackernews_profile":   _mod_hackernews_profile,
    "stackexchange_profile":_mod_stackexchange_profile,
    "lobsters_profile":     _mod_lobsters_profile,
    "npm_profile":          _mod_npm_profile,
    "pypi_profile":         _mod_pypi_profile,
    "cratesio_profile":     _mod_cratesio_profile,
    "rubygems_profile":     _mod_rubygems_profile,
    "dockerhub_profile":    _mod_dockerhub_profile,
    "devto_profile":        _mod_devto_profile,
    "chesscom_profile":     _mod_chesscom_profile,
    "lichess_profile":      _mod_lichess_profile,
    "discogs_profile":      _mod_discogs_profile,
    "myanimelist_profile":  _mod_myanimelist_profile,
    "anilist_profile":      _mod_anilist_profile,
    "pinboard_profile":     _mod_pinboard_profile,
    "orcid_search":         _mod_orcid_search,
    "openalex_search":      _mod_openalex_search,
    "semanticscholar_search": _mod_semanticscholar_search,
    "crossref_search":      _mod_crossref_search,
    "openlibrary_search":   _mod_openlibrary_search,
    "opencorporates_search": _mod_opencorporates_search,
    "opensanctions_search":  _mod_opensanctions_search,
    "fec_search":            _mod_fec_search,
    "gdelt_news":           _mod_gdelt_news,
    "wikidata_search":      _mod_wikidata_search,
    "unavatar":             _mod_unavatar,
    "duckduckgo_search":    _mod_duckduckgo_search,
    "hashnode_profile":     _mod_hashnode_profile,
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
        "cmd": (
            "python3 -c \""
            "import phonenumbers,os;"
            "n=phonenumbers.parse('{s}',None);"
            "os.system('ignorant '+str(n.country_code)+' '+str(n.national_number))"
            "\""
        ),
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

    "emailrep": {
        "type": "email", "weight": 8,
        "desc": "email reputation, breach status & social presence (emailrep.io)",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "xposedornot": {
        "type": "email", "weight": 7,
        "desc": "email data breach check via XposedOrNot",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "hibp": {
        "type": "email", "weight": 9,
        "desc": "Have I Been Pwned — breach & paste check",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "telegram_check": {
        "type": "username", "weight": 8,
        "desc": "check Telegram user/channel/bot (dedicated, anti-FP)",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "whatsmyname": {
        "type": "username", "weight": 9,
        "desc": "username presence check on 17 platforms (content-validated)",
        "check": "#native", "timeout": 90, "install": "#builtin",
    },
    "gitlab_profile": {
        "type": "username", "weight": 7,
        "desc": "GitLab public profile and projects",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r'"email"\s*:\s*"([\w.+\-]+@[\w.\-]+\.\w+)"'},
    },
    "codeberg_profile": {
        "type": "username", "weight": 6,
        "desc": "Codeberg (Gitea) public profile",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r'"email"\s*:\s*"([\w.+\-]+@[\w.\-]+\.\w+)"'},
    },
    "bluesky_profile": {
        "type": "username", "weight": 7,
        "desc": "Bluesky / AT Protocol profile (public, no auth)",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "mastodon_search": {
        "type": "username", "weight": 6,
        "desc": "Mastodon account lookup across key instances",
        "check": "#native", "timeout": 30, "install": "#builtin",
    },
    "hackernews_profile": {
        "type": "username", "weight": 6,
        "desc": "HackerNews profile — karma, about, submission count",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "stackexchange_profile": {
        "type": "username", "weight": 6,
        "desc": "StackOverflow / StackExchange profile lookup",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "lobsters_profile": {
        "type": "username", "weight": 6,
        "desc": "Lobsters tech community — trust chain & github link",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"username": r'"github_username"\s*:\s*"([^"]+)"'},
    },

    "npm_profile": {
        "type": "username", "weight": 6,
        "desc": "NPM packages & email extraction for developer",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r"([\w.+\-]+@[\w.\-]+\.\w+)"},
    },
    "pypi_profile": {
        "type": "username", "weight": 6,
        "desc": "PyPI package — author, email, homepage",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"email": r"([\w.+\-]+@[\w.\-]+\.\w+)"},
    },
    "cratesio_profile": {
        "type": "username", "weight": 5,
        "desc": "Crates.io Rust developer profile",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "rubygems_profile": {
        "type": "username", "weight": 5,
        "desc": "RubyGems owned gems & GitHub links",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "dockerhub_profile": {
        "type": "username", "weight": 5,
        "desc": "Docker Hub profile — join date, company, location",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "devto_profile": {
        "type": "username", "weight": 6,
        "desc": "Dev.to profile — twitter/github links, location",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {
            "username": r'"twitter_username"\s*:\s*"([^"]+)"',
        },
    },

    "chesscom_profile": {
        "type": "username", "weight": 6,
        "desc": "Chess.com profile — real name, country, Twitch",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"name": r'"name"\s*:\s*"([A-Za-z][A-Za-z\s]{3,40})"'},
    },
    "lichess_profile": {
        "type": "username", "weight": 6,
        "desc": "Lichess profile — bio, links, location",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "discogs_profile": {
        "type": "username", "weight": 5,
        "desc": "Discogs music collector — real name, location",
        "check": "#native", "timeout": 15, "install": "#builtin",
        "pivot": {"name": r'"name"\s*:\s*"([A-Za-z][A-Za-z\s]{3,40})"'},
    },
    "myanimelist_profile": {
        "type": "username", "weight": 5,
        "desc": "MyAnimeList profile via Jikan — gender, birthday, location",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "anilist_profile": {
        "type": "username", "weight": 5,
        "desc": "AniList profile via GraphQL",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "pinboard_profile": {
        "type": "username", "weight": 4,
        "desc": "Pinboard public bookmarks — interests & patterns",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "orcid_search": {
        "type": "name", "weight": 8,
        "desc": "ORCID researcher ID — career, publications",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "openalex_search": {
        "type": "name", "weight": 7,
        "desc": "OpenAlex author — works, citations, h-index, institution",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "semanticscholar_search": {
        "type": "name", "weight": 7,
        "desc": "Semantic Scholar author — papers, citations, affiliations",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "crossref_search": {
        "type": "name", "weight": 6,
        "desc": "CrossRef — publications, co-authors, affiliation emails",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "openlibrary_search": {
        "type": "name", "weight": 5,
        "desc": "Open Library — book author profile, works, birth date",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "opencorporates_search": {
        "type": "name", "weight": 7,
        "desc": "OpenCorporates — corporate officer records in 180+ countries",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "opensanctions_search": {
        "type": "name", "weight": 8,
        "desc": "OpenSanctions — sanctions, PEP, Interpol/OFAC watchlists",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
    "fec_search": {
        "type": "name", "weight": 6,
        "desc": "FEC — US political donation records (address, employer)",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "gdelt_news": {
        "type": "name", "weight": 7,
        "desc": "GDELT — global news coverage in 100+ languages",
        "check": "#native", "timeout": 20, "install": "#builtin",
    },
    "wikidata_search": {
        "type": "name", "weight": 7,
        "desc": "Wikidata structured data — birth, positions, external IDs",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },

    "unavatar": {
        "type": "username", "weight": 5,
        "desc": "unavatar.io — profile image URLs for reverse-image search",
        "check": "#native", "timeout": 5, "install": "#builtin",
    },

    "duckduckgo_search": {
        "type": "any", "weight": 5,
        "desc": "DuckDuckGo instant answer — quick public figure summary",
        "check": "#native", "timeout": 10, "install": "#builtin",
    },
    "hashnode_profile": {
        "type": "username", "weight": 5,
        "desc": "Hashnode developer blog profile",
        "check": "#native", "timeout": 15, "install": "#builtin",
    },
}

def load_plugins():
    plugins = {}
    if not os.path.isdir(PLUG_DIR):
        return plugins

    _ALLOWED_KEYS = {"type", "weight", "desc", "check", "cmd", "timeout", "install", "pivot"}
    _CMD_DANGER = re.compile(
        r'[;&|`$<>]|>>?|\$\('
        r'|curl\s.*\|\s*bash|wget\s.*\|\s*sh'
        r'|curl\s+.*\s-o\s|rm\s+-rf?'
    )

    for fn in sorted(os.listdir(PLUG_DIR)):
        if not fn.endswith(".json"):
            continue
        fpath = os.path.join(PLUG_DIR, fn)
        try:
            with open(fpath) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                print(f"  [!] plugin {fn}: bukan dict, dilewati", file=sys.stderr)
                continue
            for mod_name, spec in data.items():
                if not isinstance(spec, dict):
                    continue
                bad_keys = set(spec) - _ALLOWED_KEYS
                if bad_keys:
                    print(f"  [!] plugin {fn}/{mod_name}: key tidak dikenal dibuang: {bad_keys}",
                          file=sys.stderr)
                    for k in bad_keys:
                        del spec[k]
                cmd_val = spec.get("cmd", "")
                if cmd_val and _CMD_DANGER.search(cmd_val):
                    print(f"  [!] plugin {fn}/{mod_name}: cmd mencurigakan, dilewati: {cmd_val[:60]}",
                          file=sys.stderr)
                    continue
                plugins[mod_name] = spec
        except json.JSONDecodeError as e:
            print(f"  [!] plugin {fn}: JSON tidak valid — {e}", file=sys.stderr)
        except Exception as e:
            print(f"  [!] plugin {fn}: gagal dimuat — {e}", file=sys.stderr)
    return plugins

MODULES.update(load_plugins())

_ANY_MODULES = ["wayback_check", "pastebin_search", "google_dorks", "duckduckgo_search"]

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
        "username_variants",
        "telegram_check",
        "whatsmyname",
        "gitlab_profile", "codeberg_profile",
        "bluesky_profile", "mastodon_search",
        "hackernews_profile", "stackexchange_profile",
        "lobsters_profile",
        "npm_profile", "pypi_profile", "cratesio_profile",
        "rubygems_profile", "dockerhub_profile", "devto_profile",
        "hashnode_profile",
        "chesscom_profile", "lichess_profile", "discogs_profile",
        "myanimelist_profile", "anilist_profile", "pinboard_profile",
        "unavatar",
        *_ANY_MODULES,
    ],
    "email": [
        "holehe_full", "gravatar", "github_by_email",
        "email_sherlock", "email_maigret",
        "emailrep", "xposedornot", "hibp",
        *_ANY_MODULES,
    ],
    "phone": [
        "phone_format", "ignorant", "phoneinfoga", "phone_meta",
        *_ANY_MODULES,
    ],
    "name": [
        "name_dorks", "username_variants",
        "orcid_search", "openalex_search", "semanticscholar_search",
        "crossref_search", "openlibrary_search",
        "opencorporates_search", "opensanctions_search", "fec_search",
        "gdelt_news", "wikidata_search",
        *_ANY_MODULES,
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
    if "{s}" in tpl and "python3 -c" not in tpl:
        return tpl.replace("{s}", shlex.quote(target))
    safe = target.replace("{", "{{").replace("}", "}}")
    try:
        return tpl.format(s=safe)
    except Exception:
        return f"{name} {target}"

_PAT_EMAIL    = re.compile(r"^[\w.+\-]+@[\w.\-]+\.[a-zA-Z]{2,}$")
_PAT_PHONE    = re.compile(r"^(?:\+[\d\s\-()]{7,20}|(?:0|62)\d{7,13})$")
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
            out = out or ""
            is_definitive = any(m in out.lower() for m in _DEFINITIVE_EMPTY)
            is_error = (not is_definitive) and any(
                m in out.lower() for m in _TRANSIENT_ERROR
            )
            ok = bool(out) and ("[+]" in out or "[~]" in out or not (is_error or is_definitive))
            return out, f"[native:{name}]", ok
        except Exception as e:
            return f"  error: {e}", f"[native:{name}]", False

    if not is_installed(name):
        hint = mod.get("install", "")
        return f"  not installed\n  install: {hint}", "", False

    timeout = mod.get("timeout") or CFG.get("timeout", 30)
    cmd = build_cmd(name, target)

    _SHELL_META = re.compile(r"&&|\|\||[|;&`]|\$\(")
    use_shell = bool(_SHELL_META.search(cmd))
    cmd_arg   = cmd if use_shell else shlex.split(cmd)

    try:
        proc = subprocess.Popen(
            cmd_arg,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"),
            start_new_session=True,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            return stdout or "", cmd, proc.returncode == 0
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(0.4)
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
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
        if any(m in out.lower() for m in _DEFINITIVE_EMPTY):
            break
        if attempt < retries:
            time.sleep(delay * (2 ** attempt))

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
        with self._lock:
            done = self.done
            ok   = self.ok
        w      = 24
        filled = int(w * done / max(self.total, 1))
        pct    = int(100 * done / max(self.total, 1))
        bar    = "█" * filled + "░" * (w - filled)
        return f"[{bar}] {pct:3d}%  {done}/{self.total}  ok:{ok}  {self.elapsed():.0f}s"

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
    r"x-expires=\d+",
    r"x-signature=",
    r"AWSAccessKeyId=",
    r"marketplace/api/v\d+/urls/",
    r"api-v\d+/bio/details/",
    r"api/users/0\.1/users\?usernames",
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

    nw = min(CFG.get("workers", 6), len(pool)) if pool else 1
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

_CONF_HIGH   = "HIGH"
_CONF_MEDIUM = "MEDIUM"
_CONF_LOW    = "LOW"
_CONF_NOISE  = "NOISE"

_ENT_EMAIL    = re.compile(r"\b[\w.+\-]{2,}@[\w.\-]+\.[a-zA-Z]{2,}\b")
_ENT_PHONE    = re.compile(r"\+\d[\d\s\-]{6,15}\d")
_ENT_URL      = re.compile(r"https?://[^\s\"'<>]{8,}")
_ENT_USERNAME = re.compile(r"username\s*[:\-]\s*([a-zA-Z0-9_.\-]{2,40})", re.I)
_ENT_NAME     = re.compile(r"(?:name|full_name|display_name)\s*[:\-]\s*(.{3,60})", re.I)
_ENT_LOCATION = re.compile(r"(?:location|loc|city|country)\s*[:\-]\s*(.{2,60})", re.I)

_CDN_HOSTS = (
    "tiktokcdn.com", "googleusercontent.com", "cdninstagram.com",
    "fbcdn.net", "twimg.com", "pbs.twimg.com", "avatars.githubusercontent.com",
    "i.imgur.com", "cloudfront.net", "akamaized.net", "fastly.net",
    "static.", "assets.", "media.", "images.", "img.",
)
_NON_PROFILE_PATTERNS = (
    "/releases/", "/releases", "/tag/", "/tags/",
    "raw.githubusercontent.com",
    "sherlock-project/sherlock",
    "/api/", "/api-v", "api.github.com",
    "/marketplace/api/",
    "api-v2/bio/details/",
    "api/v4/urls/",
    "api/users/0.1/users",
    "?username=", "?user=", "&q=", "?hl=",
    "scholar.google.com/scholar",
    "/cdn-cgi/", "ajax.googleapis.com",
    "x-expires=", "x-signature=", "refresh_token=",
    "AWSAccessKeyId=", "Signature=", "Expires=",
)
_HIGH_FP_DOMAINS = frozenset({
    "igromania.ru", "svidbook.ru", "php.ru", "opennet.ru",
    "velomania.ru",
    "mercadolivre.com.br", "mercadolibre.com",
    "nationstates.net",
    "discords.com",
    "rarible.com",
    "ttonlineviewer.com",
    "omg.lol",
})

_DEFINITIVE_EMPTY = (
    "not found on", "not found in",
    "not found or uncertain",
    "not found", "user not found",
    "no public emails", "no breaches found", "no snapshots found",
    "0 accounts found", "no public bookmarks",
    "no results found", "no orcid records",
)
_TRANSIENT_ERROR = (
    "parse error", "no data", "uncertain",
    "not found or blocked",
    "not found or private",
    "blocked", "error:", "timeout",
)

def _score_confidence(module_name, line, found_via_api=False):
    """
    Assign confidence score ke sebuah finding line.
    Prinsip: semakin langsung sumbernya, semakin tinggi scorenya.
    """
    ln = line.lower()

    _noise_modules = {"google_dorks", "name_dorks", "linkedin_dorks",
                      "wayback_check", "pastebin_search", "duckduckgo_search",
                      "gdelt_news", "unavatar", "username_variants"}
    if module_name in _noise_modules:
        return _CONF_NOISE

    _api_modules = {
        "github_profile", "github_emails", "github_by_email",
        "gitlab_profile", "codeberg_profile", "keybase",
        "reddit_profile", "bluesky_profile", "hackernews_profile",
        "npm_profile", "pypi_profile", "cratesio_profile",
        "rubygems_profile", "dockerhub_profile", "devto_profile",
        "chesscom_profile", "lichess_profile", "myanimelist_profile",
        "anilist_profile", "gravatar", "emailrep", "xposedornot", "hibp",
        "orcid_search", "openalex_search", "opencorporates_search",
        "opensanctions_search", "fec_search", "wikidata_search",
        "semanticscholar_search", "crossref_search", "openlibrary_search",
    }
    if module_name in _api_modules:
        return _CONF_HIGH

    if module_name == "telegram_check" and "[+]" in line:
        return _CONF_HIGH

    _scrape_modules = {
        "instagram_check", "facebook_check", "tiktok_check",
        "snapchat_check", "youtube_check", "twitch_check",
        "pinterest_check", "steam_check", "mastodon_search",
        "stackexchange_profile", "lobsters_profile",
        "discogs_profile", "pinboard_profile", "hashnode_profile",
    }
    if module_name in _scrape_modules:
        return _CONF_MEDIUM

    if module_name == "whatsmyname":
        return _CONF_MEDIUM

    _external_tools = {"sherlock", "maigret", "socialscan",
                       "email_sherlock", "email_maigret"}
    if module_name in _external_tools:
        return _CONF_LOW

    if module_name in {"phone_meta", "phone_format", "ignorant", "phoneinfoga"}:
        return _CONF_LOW

    return _CONF_MEDIUM

def _extract_entities(output, module_name):
    """
    Parse output modul → list of (category, value, confidence).
    """
    findings = []
    if not output:
        return findings

    _is_external = module_name in {
        "sherlock", "maigret", "socialscan", "email_sherlock", "email_maigret"
    }

    for line in output.splitlines():
        ln = line.strip()
        if not ln:
            continue

        conf = _score_confidence(module_name, ln)
        if conf == _CONF_NOISE:
            continue

        for m in _ENT_EMAIL.findall(ln):
            if "noreply" not in m and "example" not in m:
                findings.append(("email", m.lower(), conf))

        for m in _ENT_PHONE.findall(ln):
            findings.append(("phone", m.strip(), conf))

        for m in _ENT_URL.findall(ln):
            if any(ext in m.lower() for ext in (
                ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                ".css", ".js", ".woff", ".ico",
            )):
                continue
            if any(cdn in m.lower() for cdn in _CDN_HOSTS):
                continue
            if any(pat in m for pat in _NON_PROFILE_PATTERNS):
                continue
            if len(m) > 400:
                continue
            if len(m) > 200:
                _parsed_m = urllib.parse.urlparse(m)
                _PROFILE_DOMAINS = (
                    "linkedin.com", "twitter.com", "x.com", "github.com",
                    "facebook.com", "instagram.com", "researchgate.net",
                )
                if not any(d in _parsed_m.netloc for d in _PROFILE_DOMAINS):
                    continue
            if _is_external:
                url_domain = urllib.parse.urlparse(m).netloc.lower()
                if any(fp in url_domain for fp in _HIGH_FP_DOMAINS):
                    continue
            findings.append(("url", m, conf))

        um = _ENT_USERNAME.search(ln)
        if um:
            findings.append(("username", um.group(1).strip(), conf))

        nm = _ENT_NAME.search(ln)
        if nm:
            val = nm.group(1).strip().strip("'\"")
            if len(val) > 2 and val.lower() not in ("-", "none", "null"):
                findings.append(("name", val, conf))

        lm = _ENT_LOCATION.search(ln)
        if lm:
            val = lm.group(1).strip().strip("'\"")
            if len(val) > 1 and val.lower() not in ("-", "none"):
                findings.append(("location", val, conf))

    return findings

def _normalize_value(category, value):
    """Normalisasi nilai untuk deduplication — selalu konsisten case-insensitive."""
    v = value.strip()
    if category == "email":    return v.lower()
    if category == "phone":    return re.sub(r"[\s\-()]", "", v)
    if category == "username": return v.lower()
    if category == "name":     return v.lower()
    return v.lower()

def _merge_into_profile(profile, category, value, confidence, source_module, source_target):
    """
    Merge satu finding ke profile dict. Jika sudah ada, update confidence
    ke yang lebih tinggi dan tambahkan sumber baru.
    """
    key = f"{category}:{_normalize_value(category, value)}"
    conf_rank = {_CONF_HIGH: 3, _CONF_MEDIUM: 2, _CONF_LOW: 1, _CONF_NOISE: 0}

    if key not in profile:
        profile[key] = {
            "category":   category,
            "value":      value,
            "confidence": confidence,
            "sources":    [],
        }
    else:
        existing_rank = conf_rank.get(profile[key]["confidence"], 0)
        new_rank      = conf_rank.get(confidence, 0)
        if new_rank > existing_rank:
            profile[key]["confidence"] = confidence

    src = f"{source_module}@{source_target}"
    if src not in profile[key]["sources"]:
        profile[key]["sources"].append(src)

def _build_pivot_queue(inv_result, already_investigated, max_per_type=5):
    """
    Ekstrak pivot targets dari hasil investigate(), filter yang sudah diproses.
    Return list of (target, type) sorted by priority.
    """
    queue = []
    priority = {"email": 3, "username": 2, "phone": 1, "name": 0}

    _GENERIC_NAMES = {
        "admin", "user", "test", "guest", "anonymous", "unknown",
        "null", "none", "n/a", "-",
        "bocil", "bocil cilik", "hadroh", "hadroh indonesia",
        "gaming", "gamer", "oficial", "official", "channel", "studio",
        "music", "store", "shop", "team", "crew", "official channel",
        "admin channel", "bot", "support",
        "indonesia", "jakarta", "bandung", "surabaya",
    }

    _NAME_LOOKS_ALIAS = re.compile(r'[\d_]{2,}|[@#]|\bfc\b|\bofficial\b', re.I)

    for ptype, vals in inv_result.get("pivots", {}).items():
        for v in vals[:max_per_type]:
            norm = _normalize_value(ptype, v).lower()

            if norm in already_investigated:
                continue

            if len(v) < 4:
                continue

            if ptype == "name":
                words = v.strip().split()
                if not words:
                    continue
                if len(words) < 2:
                    continue
                if v.lower() in _GENERIC_NAMES or norm in _GENERIC_NAMES:
                    continue
                if all(w.lower() in _GENERIC_NAMES for w in words):
                    continue
                if _NAME_LOOKS_ALIAS.search(v):
                    continue

            queue.append((v, ptype, priority.get(ptype, 0)))

    queue.sort(key=lambda x: -x[2])
    return [(t, tp) for t, tp, _ in queue]

def _print_smos_header(seed, depth, phase):
    p()
    hr()
    p(f"  {c(_CYN, '◈')} {c(_B, 'SMART OSINT')}  {c(_GRY2, '///')}  "
      f"seed:{c(_YLW, seed)}  depth:{depth}  phase:{c(_CYN, phase)}")
    hr()
    p()

def _print_smos_profile(profile, graph, elapsed):
    """Render unified profile hasil smart OSINT."""
    p()
    hr("═")
    p(f"  {c(_B, '◈ SMART OSINT — UNIFIED PROFILE')}")
    p(f"  {c(_D, f'elapsed: {elapsed:.1f}s  |  unique findings: {len(profile)}')}")
    hr()

    by_cat = {}
    for entry in profile.values():
        cat = entry["category"]
        by_cat.setdefault(cat, []).append(entry)

    cat_order = ["name", "username", "email", "phone", "location", "url"]
    for cat in cat_order:
        entries = by_cat.get(cat, [])
        if not entries:
            continue
        conf_rank = {_CONF_HIGH: 3, _CONF_MEDIUM: 2, _CONF_LOW: 1}
        entries.sort(key=lambda e: -conf_rank.get(e["confidence"], 0))
        p(f"  {c(_GRY2, f'[{cat.upper()}]')}")
        for e in entries:
            conf = e["confidence"]
            conf_col = _GRN if conf == _CONF_HIGH else (_YLW if conf == _CONF_MEDIUM else _RED)
            src_str = ", ".join(e["sources"][:3])
            p(f"  {c(conf_col, f'[{conf[0]}]')} {e['value']:<45} {c(_D, src_str)}")
        p()

    if len(graph) > 1:
        p(f"  {c(_GRY2, '[IDENTITY GRAPH]')}")
        for src_node, dst_nodes in graph.items():
            if dst_nodes:
                p(f"  {c(_CYN, src_node)} → {', '.join(dst_nodes)}")
        p()

    hr("═")

def investigate_smart(seed_target, seed_type="", quiet=False,
                      max_depth=2, max_total_targets=12):
    """
    Smart OSINT mode: investigasi berlapis, adaptive pivot, confidence scoring,
    deduplication cross-target, dan unified profile builder.

    Parameter:
        max_depth           : kedalaman pivot maksimal (default 2)
                              depth=0 → seed saja
                              depth=1 → seed + pivot langsung dari seed
                              depth=2 → seed + pivot + pivot-dari-pivot
        max_total_targets   : batas total target yang diinvestigasi (anti-runaway)
    """
    t0 = time.time()

    seed_target = sanitize(seed_target)
    seed_type   = seed_type or detect_type(seed_target)

    investigated   = {}
    pivot_graph    = {}
    unified_profile = {}
    queue          = [(seed_target, seed_type, 0)]

    def _norm(t):
        return _normalize_value(detect_type(t), t)

    while queue and len(investigated) < max_total_targets:
        target, ttype, depth = queue.pop(0)
        norm = _norm(target)

        if norm in investigated:
            continue

        if not quiet:
            phase_label = f"depth {depth} — {'seed' if depth == 0 else 'pivot'}"
            _print_smos_header(seed_target, depth, phase_label)
            tag("*", f"investigating: {target}  [{ttype}]")
            p()

        inv = investigate(target, ttype, mode="deep", quiet=quiet)
        investigated[norm] = inv

        for r in inv.get("results", []):
            if not r.get("ok"):
                continue
            entities = _extract_entities(r.get("output", ""), r["module"])
            for cat, val, conf in entities:
                _merge_into_profile(
                    unified_profile, cat, val, conf,
                    source_module=r["module"],
                    source_target=target,
                )

        if depth < max_depth:
            new_pivots = _build_pivot_queue(inv, set(investigated.keys()))
            pivot_graph[target] = [t for t, _ in new_pivots]
            for pt, ptype in new_pivots:
                if _norm(pt) not in investigated:
                    queue.append((pt, ptype, depth + 1))
            if not quiet and new_pivots:
                tag("~", f"pivot queue: {', '.join(t for t,_ in new_pivots[:6])}")
        else:
            pivot_graph[target] = []

    elapsed = time.time() - t0

    if not quiet:
        _print_smos_profile(unified_profile, pivot_graph, elapsed)

    return {
        "mode":            "smos",
        "seed":            seed_target,
        "seed_type":       seed_type,
        "elapsed":         round(elapsed, 1),
        "targets_scanned": len(investigated),
        "profile":         unified_profile,
        "pivot_graph":     pivot_graph,
        "investigations":  investigated,
    }

def save_smos_json(smos_result):
    """Simpan hasil smart OSINT ke JSON."""
    path = _outpath(smos_result["seed"] + "_smos", "json")
    out = {k: v for k, v in smos_result.items() if k != "investigations"}
    out["investigations_summary"] = {
        t: {
            "ok":    r["summary"]["ok"],
            "total": r["summary"]["total"],
        }
        for t, r in smos_result["investigations"].items()
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return path

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

_ANSI_STRIP = _ANSI

_SKIP_REPORT = _NOISE

_EMPTY_VALS = frozenset([
    "user not found", "no public emails found", "no results found",
    "username: -", "name     : -", "0 accounts found", "parse error",
])

def _clean_lines(text, tgt):
    from urllib.parse import unquote_plus
    out     = []
    section = None

    for ln in text.splitlines():
        ln = _ANSI.sub("", ln).rstrip()
        if not ln.strip() or _NOISE.search(ln):
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
    p(f"  {c(_B, '1/3  apt packages')}")
    hr()
    _inst("apt update",  "sudo apt-get update -qq", 120)
    _inst("curl",        "sudo apt-get install -y curl", 120)
    _inst("sherlock",    "sudo apt install -y sherlock", 120)
    p()
    hr()
    p(f"  {c(_B, '2/3  pip tools')}")
    hr()
    pip_tools = [
        ("phonenumbers", "pip install phonenumbers --break-system-packages", 60),
        ("holehe",       "pip install holehe --break-system-packages", 180),
        ("maigret",      "pip install maigret --user --break-system-packages", 300),
        ("socialscan",   "pip install socialscan --break-system-packages", 180),
        ("ignorant",     "pip install ignorant --break-system-packages", 180),
        ("phoneinfoga",
         "curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master"
         "/support/scripts/install | bash"
         " && sudo mv ./phoneinfoga /usr/bin/phoneinfoga 2>/dev/null || true",
         120),
    ]
    for lbl, cmd, t in pip_tools:
        _inst(lbl, cmd, t)
    p()
    hr()
    p(f"  {c(_B, '3/3  verify')}")
    hr()
    tools = {
        "sherlock":    "sherlock",
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
        ("sherlock",     "sudo apt install -y --only-upgrade sherlock", 120),
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
        ("-t <type>",       "force target type  [username|email|phone|name]"),
        ("-m <mode>",       "scan mode  [quick|standard|deep|smos]"),
        ("-r <modules>",    "run specific modules (comma-separated)"),
        ("-P / --pivot",    "auto-investigate all discovered pivots (non-smos)"),
        ("-q",              "quiet mode — suppress per-module output"),
        ("--no-color",      "output without ANSI color"),
        ("--depth <n>",     "pivot depth for -m smos  (default: 2, max: 4)"),
        ("--max-targets <n>","max total targets for -m smos  (default: 12)"),
    ]:
        p(f"  {c(_GRY2, k):<28} {v}")
    p()
    hr()
    p(f"  {c(_B, 'MODES')}")
    hr()
    for mode, desc in [
        ("quick",       "high-priority modules only (weight ≥ 8) — fast, ~30s"),
        ("standard",    "balanced speed & coverage (weight ≥ 5) — default"),
        ("deep",        "all modules, no exclusions — full coverage, ~2–5 min"),
        ("smos",        "Smart OSINT: deep + automatic multi-level pivot + unified profile"),
    ]:
        col = _CYN if mode == "smos" else _GRY2
        p(f"  {c(col, mode):<20} {desc}")
    p()
    p(f"  {c(_D, 'smos vs deep:')}")
    p(f"  {c(_D, '  deep = 1 target, 1 pass, no confidence scoring')}")
    p(f"  {c(_D, '  smos = multi-target iterative, automatic pivot, confidence [H/M/L],')}")
    p(f"  {c(_D, '         cross-target dedup, identity graph, unified profile')}")
    p()
    hr()
    p(f"  {c(_B, 'EXAMPLES')}")
    hr()
    for lbl, cmd in [
        ("username",           "python3 wiwok.py johndoe"),
        ("email",              "python3 wiwok.py john@example.com"),
        ("phone",              "python3 wiwok.py +6281234567890"),
        ("name",               'python3 wiwok.py -t name "John Doe"'),
        ("deep scan",          "python3 wiwok.py -m deep johndoe"),
        ("quick scan",         "python3 wiwok.py -m quick johndoe"),
        ("smart osint",        "python3 wiwok.py -m smos johndoe"),
        ("smos + depth 3",     "python3 wiwok.py -m smos --depth 3 johndoe"),
        ("smos + max target",  "python3 wiwok.py -m smos --depth 2 --max-targets 20 johndoe"),
        ("smos quiet",         "python3 wiwok.py -m smos -q johndoe"),
        ("auto pivot",         "python3 wiwok.py -m deep -P johndoe"),
        ("specific modules",   "python3 wiwok.py -r telegram_check,github_profile johndoe"),
        ("check instagram",    "python3 wiwok.py -r instagram_check johndoe"),
        ("check telegram",     "python3 wiwok.py -r telegram_check johndoe"),
        ("email check",        "python3 wiwok.py -r holehe_full,hibp john@example.com"),
        ("phone check",        "python3 wiwok.py -r ignorant,phone_meta +6281234567890"),
        ("quiet deep",         "python3 wiwok.py -q -m deep johndoe"),
    ]:
        p(f"  {c(_D, lbl + ':'): <24}  {cmd}")
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
            if not clean:
                continue
            if _fake.search(clean):
                continue
            _EMPTY_LINE_MARKERS = (
                "not found", "parse error", "no data", "no results",
                "no public", "0 accounts", "no breaches", "not installed",
            )
            if any(m in clean.lower() for m in _EMPTY_LINE_MARKERS):
                continue
            if clean.startswith("[+]"):
                content = clean[4:].strip()
            elif clean.startswith("[~]"):
                content = "(~) " + clean[4:].strip()
            else:
                content = clean
            if content and content not in seen:
                seen.add(content)
                hits.append((clean.startswith("[+]") or clean.startswith("[~]"), content))
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
            for is_hit, h in hits:
                prefix = c(_GRN, '[+]') if is_hit else c(_GRY2, '   ')
                p(f"  {prefix} {h}")
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
                    choices=["quick", "standard", "deep", "smos", "smartosint"])
    ap.add_argument("-r", "--run",   default="")
    ap.add_argument("-P", "--pivot", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--depth",  type=int, default=2,
                    help="kedalaman pivot untuk -m smos (default: 2, max: 4)")
    ap.add_argument("--max-targets", type=int, default=12,
                    help="batas total target untuk -m smos (default: 12)")
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

        mode = args.mode
        if mode == "smartosint":
            mode = "smos"

        is_smos = (mode == "smos")

        if not args.quiet:
            banner()
            p()
            hr()
            kv("target",  target)
            kv("type",    ttype)
            kv("mode",    mode)
            kv("time",    datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
            kv("workers", str(CFG.get("workers", 6)))
            if is_smos:
                kv("smos depth",   str(min(args.depth, 4)))
                kv("smos targets", str(args.max_targets))
            if only:
                kv("modules", ", ".join(only))
            hr()
            p()

        if is_smos:
            smos = investigate_smart(
                target, ttype,
                quiet=args.quiet,
                max_depth=min(args.depth, 4),
                max_total_targets=args.max_targets,
            )
            try:
                jp = save_smos_json(smos)
                tag("+", f"json  : {jp}")
            except Exception as e:
                tag("!", f"save error: {e}")
            hr("═")
        else:
            inv = investigate(target, ttype, mode, only, quiet=args.quiet)
            _print_summary(inv, mode)

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
                cmd_pivot(inv, mode, args.quiet)
    else:
        cmd_help()

if __name__ == "__main__":
    main()
