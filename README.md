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
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![API Key](https://img.shields.io/badge/API_Key-Not_Required-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-5.0-orange?style=flat-square)

OSINT tool for investigating **usernames**, **emails**, and **phone numbers** — no API keys, no login, no extra setup.

---

## Features

- **Zero API Key** — install and run, nothing to configure
- **Multi-target** — username, email, phone, full name
- **Auto Pivot** — findings are automatically chained into new targets
- **Parallel Scan** — all modules run concurrently
- **3 Scan Modes** — `quick`, `standard`, `deep`
- **Triple Output** — JSON, TXT, and interactive HTML report
- **20+ Native Modules** — built-in checks with no external dependencies
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

# run specific modules only
python3 wiwok.py -r sherlock,maigret johndoe
```

### Options

```
-t <type>     force target type [username|email|phone|name]
-m <mode>     scan depth [quick|standard|deep]
-r <modules>  comma-separated module list
-P            auto-investigate all discovered pivots
-q            quiet mode (no live output)
--no-color    disable colors
--setup       install all dependencies
--update      update all tools
--check       check module status
```

---

## Modules

### Username (20)
| Module | Description |
|--------|-------------|
| sherlock | 300+ social platforms |
| maigret | 2000+ sites, extracts profile info |
| socialscan | availability check on major platforms |
| instagram_check | Instagram native check |
| facebook_check | Facebook native check |
| youtube_check | YouTube channel check |
| tiktok_check | TikTok native check |
| snapchat_check | Snapchat native check |
| twitch_check | Twitch channel check |
| steam_check | Steam profile check |
| pinterest_check | Pinterest native check |
| github_profile | GitHub profile + repos |
| github_emails | Emails from commit history |
| keybase | Identity proofs |
| reddit_profile | Reddit public stats |
| linkedin_dorks | LinkedIn-specific search dorks |
| username_variants | Common username variations |
| wayback_check | Wayback Machine snapshots |
| pastebin_search | Public pastebin dumps |
| google_dorks | Ready-to-use Google dorks |

### Email (8)
| Module | Description |
|--------|-------------|
| holehe_full | 121 platform check |
| gravatar | Gravatar profile from email hash |
| github_by_email | GitHub accounts linked to email |
| email_sherlock | Sherlock from email local-part |
| email_maigret | Maigret from email local-part |
| wayback_check | Wayback Machine search |
| pastebin_search | Pastebin dump search |
| google_dorks | Google dorks for email |

### Phone (7)
| Module | Description |
|--------|-------------|
| ignorant | WhatsApp, Instagram, Snapchat check |
| phoneinfoga | Carrier, location, online profile |
| phone_meta | Carrier, timezone, number type |
| phone_format | Auto-format number variants |
| wayback_check | Wayback Machine search |
| pastebin_search | Pastebin dump search |
| google_dorks | Google dorks for phone |

---

## Output

Results are saved automatically to `~/wiwok_results/`:

```
~/wiwok_results/
├── target_20240101_120000.json
├── target_20240101_120000.txt
└── target_20240101_120000.html
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

---

## Disclaimer

This tool is intended for educational purposes and legitimate security research only. The author is not responsible for any misuse. Make sure you have proper authorization before investigating any individual or organization.

---

## License

MIT — see [LICENSE](LICENSE)
