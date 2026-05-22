<p align="center">
  <img src="https://l.top4top.io/p_3768jabk70.png" width="400">
</p>

# WiwoK DetoK — OSINT Tool

```
  __      __.___ __      __________   ____  __.
/  \    /  \   /  \    /  \_____  \ |    |/ _|
\   \/\/   /   \   \/\/   //   |   \|      <
 \        /|   |\        //    |    \    |  \
  \__/\  / |___| \__/\  / \_______  /____|__ \
       \/             \/          \/        \/
```

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-red?style=flat-square)
![License](https://img.shields.io/badge/License-GPLv3-blue?style=flat-square)
![API Key](https://img.shields.io/badge/API_Key-Not_Required-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-6.0.0--db2-orange?style=flat-square)

OSINT tool for investigating **usernames**, **emails**, **phone numbers**, and **full names** — no API keys, no login, no extra setup.

---

## Features

- **Zero API Key** — install and run, nothing to configure
- **Multi-target** — username, email, phone, full name
- **Smart OSINT Mode** — automatic multi-layer pivoting with confidence scoring and unified profile builder
- **Auto Pivot** — findings are automatically chained into new investigation targets
- **Parallel Scan** — all modules run concurrently via thread pool
- **4 Scan Modes** — `quick`, `standard`, `deep`, `smos`
- **Triple Output** — JSON, TXT, and interactive HTML report
- **68 Native Modules** — built-in checks covering social, academic, developer, and public record sources
- **Confidence Scoring** — findings tagged `HIGH`, `MEDIUM`, or `LOW` based on source reliability
- **False Positive Filtering** — CDN URLs, API endpoints, and signed tokens are automatically suppressed
- **Plugin System** — add custom modules via `.json` files
- **Kali Linux Ready**

---

## Installation

```bash
git clone https://github.com/kirozaku/wiwok
cd wiwok
python3 wiwok.py --setup
```

`--setup` handles everything automatically: apt packages, pip tools, and binary installs.

### Verify

```bash
python3 wiwok.py --check
```

---

## Usage

```bash
# username
python3 wiwok.py johndoe

# email
python3 wiwok.py john@example.com

# phone (E.164 format)
python3 wiwok.py +6281234567890

# full name
python3 wiwok.py -t name "John Doe"

# deep scan
python3 wiwok.py -m deep johndoe

# deep scan + auto pivot
python3 wiwok.py -m deep -P johndoe

# smart OSINT mode (multi-layer auto pivot)
python3 wiwok.py -m smos johndoe

# smart OSINT with custom depth and target limit
python3 wiwok.py -m smos --depth 3 --max-targets 20 johndoe

# run specific modules only
python3 wiwok.py -r sherlock,maigret johndoe

# quiet mode (no live output, results saved to file)
python3 wiwok.py -q johndoe
```

### Options

```
-t <type>          force target type [username|email|phone|name]
-m <mode>          scan depth [quick|standard|deep|smos]
-r <modules>       comma-separated module list
-P                 auto-investigate all discovered pivots
-q                 quiet mode (no live output)
--depth <n>        pivot depth for smos mode (default: 2, max: 4)
--max-targets <n>  total target cap for smos mode (default: 12)
--no-color         disable colors
--setup            install all dependencies
--update           update all tools
--check            check module status
```

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `quick` | High-weight modules only — fastest, less coverage |
| `standard` | Core modules — default balance of speed and coverage |
| `deep` | All modules including external tools |
| `smos` | Smart OSINT — automatic multi-layer pivot with unified profile and confidence scoring |

### Smart OSINT (`-m smos`)

smos investigates the seed target, extracts pivots (emails, usernames, names discovered in results), and automatically re-investigates each pivot — up to a configurable depth. All findings are deduplicated across targets and merged into a single **Unified Profile** with confidence levels:

- `[H]` **HIGH** — structured API data (GitHub, ORCID, HIBP, etc.)
- `[M]` **MEDIUM** — validated HTML scrape (Instagram, TikTok, Mastodon, etc.)
- `[L]` **LOW** — inferred from external tools (Sherlock, Maigret)

---

## Modules

### Username (40)

| Module | Description |
|--------|-------------|
| sherlock | Track username across 300+ social platforms |
| maigret | Deep profile from 2000+ sites |
| socialscan | Availability check on major platforms |
| whatsmyname | Content-validated check on 17 platforms |
| instagram_check | Instagram native check |
| facebook_check | Facebook native check |
| tiktok_check | TikTok native check |
| snapchat_check | Snapchat native check |
| youtube_check | YouTube channel check |
| twitch_check | Twitch channel check |
| steam_check | Steam profile check |
| pinterest_check | Pinterest native check |
| telegram_check | Telegram user / channel / bot (multi-layer anti-FP) |
| github_profile | GitHub profile, repos, and followers |
| github_emails | Emails extracted from public commit history |
| gitlab_profile | GitLab public profile and projects |
| codeberg_profile | Codeberg (Gitea) public profile |
| keybase | Identity proofs on Keybase |
| reddit_profile | Public Reddit profile and statistics |
| bluesky_profile | Bluesky / AT Protocol profile |
| mastodon_search | Mastodon account lookup across key instances |
| hackernews_profile | HackerNews — karma, about, submission count |
| stackexchange_profile | StackOverflow / StackExchange profile lookup |
| lobsters_profile | Lobsters tech community — trust chain & GitHub link |
| npm_profile | NPM packages & email extraction |
| pypi_profile | PyPI package — author, email, homepage |
| cratesio_profile | Crates.io Rust developer profile |
| rubygems_profile | RubyGems owned gems & GitHub links |
| dockerhub_profile | Docker Hub — join date, company, location |
| devto_profile | Dev.to profile — Twitter/GitHub links, location |
| hashnode_profile | Hashnode developer blog profile |
| chesscom_profile | Chess.com — real name, country, Twitch |
| lichess_profile | Lichess — bio, links, location |
| discogs_profile | Discogs music collector — real name, location |
| myanimelist_profile | MyAnimeList via Jikan — gender, birthday, location |
| anilist_profile | AniList profile via GraphQL |
| pinboard_profile | Pinboard public bookmarks — interests & patterns |
| unavatar | Profile image URLs for reverse-image search |
| linkedin_dorks | LinkedIn-specific Google dorks |
| username_variants | Generate common username variations |

### Email (9)

| Module | Description |
|--------|-------------|
| holehe_full | Registered check on 121 platforms |
| emailrep | Email reputation, breach status & social presence |
| hibp | Have I Been Pwned — breach & paste check |
| xposedornot | Breach check via XposedOrNot |
| gravatar | Gravatar profile from email hash |
| github_by_email | GitHub accounts linked to this email |
| email_sherlock | Sherlock from email local-part |
| email_maigret | Maigret from email local-part |
| wayback_check | Wayback Machine snapshots |

### Phone (4)

| Module | Description |
|--------|-------------|
| ignorant | WhatsApp, Instagram, Snapchat check |
| phoneinfoga | Carrier, location, and online profile |
| phone_meta | Carrier, timezone, number type |
| phone_format | Auto-format number variants (E.164, local, etc.) |

### Full Name (11)

| Module | Description |
|--------|-------------|
| orcid_search | ORCID researcher ID — structured author query |
| openalex_search | OpenAlex author — works, citations, h-index, institution |
| semanticscholar_search | Semantic Scholar — papers, citations, affiliations |
| crossref_search | CrossRef — publications with author-validated filtering |
| openlibrary_search | Open Library — book author profile, works, birth date |
| opencorporates_search | Corporate officer records in 180+ countries |
| opensanctions_search | Sanctions, PEP, Interpol/OFAC watchlists |
| fec_search | US political donation records (address, employer) |
| wikidata_search | Wikidata — birth, positions, external IDs |
| gdelt_news | GDELT — global news coverage in 100+ languages |
| name_dorks | Targeted Google dorks for full name |

### Universal (4 — run on all target types)

| Module | Description |
|--------|-------------|
| wayback_check | Wayback Machine snapshots |
| pastebin_search | Public pastebin dump search |
| google_dorks | Ready-to-use Google dorks |
| duckduckgo_search | DuckDuckGo instant answer |

---

## Output

Results are saved automatically to `~/wiwok_results/`:

```
~/wiwok_results/
├── target_20240101_120000.json
├── target_20240101_120000.txt
├── target_20240101_120000.html
└── target_smos_20240101_120000.json   ← Smart OSINT unified profile
```

The HTML report is interactive — each module result is collapsible.

---

## Plugin System

Drop a `.json` file into `~/.wiwok_plugins/` to add custom modules without touching the source:

```json
{
  "my_module": {
    "type": "username",
    "weight": 7,
    "desc": "my custom module",
    "check": "my_tool",
    "cmd": "my_tool -u {s}",
    "timeout": 30,
    "install": "pip install my_tool"
  }
}
```

Supported `type` values: `username`, `email`, `phone`, `name`, `any`

Weight range: `0` (disabled) to `10` (always run in quick mode)

---

## Requirements

- Python 3.8+
- Kali Linux (recommended) or any Debian-based distro

Tools installed via `--setup`:

```
sherlock      apt
holehe        pip
maigret       pip
socialscan    pip
ignorant      pip
phonenumbers  pip
phoneinfoga   curl (binary)
```

---

## Support

If this tool helped you, consider donating:

**BTC**: `1N1rMC95mwYqpQNCWC5TQmZJGdpwf2APsS`

**Trakteer** (QRIS / GoPay / OVO / Dana / Bank Transfer): [trakteer.id/Kirozaku/tip](https://trakteer.id/Kirozaku/tip)

---

## Disclaimer

This tool is intended for educational purposes and legitimate security research only. The author is not responsible for any misuse. Make sure you have proper authorization before investigating any individual or organization.

Some parts written with the help of AI tools.

---

## License

Copyright (C) 2026 Kirozaku

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for details.
