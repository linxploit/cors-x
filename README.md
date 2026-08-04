<div align="center">

```
 _____ ___________  _____  __   __
/  __ \  _  | ___ \/  ___| \ \ / /
| /  \/ | | | |_/ /\ `--.   \ V /
| |   | | | |    /  `--. \  /   \
| \__/\ \_/ / |\ \ /\__/ / / /^\ \
 \____/\___/\_| \_|\____/  \/   \/
```

###  Cross-Origin Misconfiguration Analyzer 

**Synthetic origins only. Reserved TLDs. No exploitation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is CorsX?

**CorsX** tests how a server's CORS policy actually behaves under a battery of well-documented origin-validation patterns — not just whether `Access-Control-Allow-Origin` is present, but whether it *reflects an attacker-controlled origin*, whether it trusts the literal `null` origin, and whether common validation shortcuts (substring checks, case handling, scheme/port blindness) can be tricked into allowing a domain the server never meant to trust.

Every test origin lives under `.test` — an IANA-reserved TLD that will never resolve on the real internet — so nothing is ever sent toward an actual third party. CorsX only reads the response headers your own server sends back; it never touches a response body cross-origin and never performs a browser action.

---

## ✨ Features

- 🎨 **A distinct visual identity** — bordered grid tables, a live status strip, and a stamped verdict box, built with its own violet→crimson palette.
- 🧪 **A 7-point origin test matrix**, covering the CORS misconfiguration classes most commonly found in the wild:
  - **Arbitrary reflection** — does the server echo back any attacker-controlled origin?
  - **`null` origin trust** — reachable from sandboxed iframes and `data:` URIs.
  - **Suffix trick** — `https://target.example.attacker.test` (weak "startswith" logic).
  - **Prefix trick** — `https://evil-target.example` (weak "endswith"/substring logic).
  - **Case-sensitivity bug** — uppercased origin bypassing a case-sensitive check.
  - **Scheme downgrade** — does `http://` get trusted the same as `https://`?
  - **Port variation** — is the origin matched with the port ignored?
- 🔍 **Credential-aware risk grading** — the same reflected origin is scored very differently depending on whether `Access-Control-Allow-Credentials: true` is also present (that's the difference between "readable" and "fully exploitable with a logged-in victim").
- 🤝 **Preflight inspection** — a real `OPTIONS` request with `Access-Control-Request-Method`/`-Headers` to see what the server actually permits.
- 📛 **A five-level verdict** — SAFE → LOW → MEDIUM → HIGH → CRITICAL, stamped clearly per target.
- ⚡ **Concurrent multi-target scanning**, custom headers/cookies for authenticated endpoints, configurable attacker domain.
- 📊 **Exportable reports** — full **JSON** (every test + note) or flat **CSV**.
- 🛡️ **Authorization gate** — confirms you're allowed to assess a target before sending a single request (skippable with `--yes`).

---

## 📸 Preview

```
✦ Cross-Origin Misconfiguration Analyzer ✦
v1.0.0 · Synthetic origins only. Reserved TLDs. No exploitation.

• TARGET: https://api.example.com/data
┌────────────────────────────────────┬─────────────────────────┬──────────────────────────┬───────┬──────────┐
│ TEST                                │ TEST ORIGIN              │ ALLOW-ORIGIN              │ CREDS │ RISK     │
├────────────────────────────────────┼─────────────────────────┼──────────────────────────┼───────┼──────────┤
│ Arbitrary attacker origin reflected?│ https://corsx-probe.test │ https://corsx-probe.test  │ true  │ CRITICAL │
│ 'null' Origin trusted?              │ null                     │ null                       │ true  │ HIGH     │
│ Weak suffix/startswith match bypass?│ https://api.example...   │ https://api.example...    │ true  │ HIGH     │
└────────────────────────────────────┴─────────────────────────┴──────────────────────────┴───────┴──────────┘

╔══════════════════════════════════════════════╗
║              ⚡ CRITICAL RISK ⚡               ║
╚══════════════════════════════════════════════╝
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/cors-x.git
cd cors-x
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## 🚀 Usage

### Analyze a single endpoint

```bash
python3 corsx.py -u "https://api.example.com/data"
```

### Analyze a list of targets

```bash
python3 corsx.py -l examples/targets.txt
```

### See the full reasoning behind every test

```bash
python3 corsx.py -u "https://api.example.com/data" -v
```

### Test an authenticated endpoint

```bash
python3 corsx.py -u "https://api.example.com/account" -b "session=abc123"
```

### Use a different synthetic attacker domain

```bash
python3 corsx.py -u "https://api.example.com" --attacker-domain my-probe.test
```

### Save a report

```bash
python3 corsx.py -l examples/targets.txt -o report.json
python3 corsx.py -l examples/targets.txt -o report.csv
```

### Skip the authorization prompt (for your own automated pipelines)

```bash
python3 corsx.py -u "https://api.example.com" --yes
```

### Full option reference

```bash
python3 corsx.py --help
```

| Flag | Description |
|---|---|
| `-u`, `--url` | Single target URL |
| `-l`, `--list` | File with one target URL per line |
| `-t`, `--timeout` | Request timeout in seconds (default: `10`) |
| `--threads` | Targets scanned concurrently (default: `3`) |
| `--attacker-domain` | Synthetic domain used in test origins (default: `corsx-probe.test`) |
| `-H`, `--header` | Custom header `"Key: Value"`, repeatable |
| `-b`, `--cookies` | Cookie string `"a=1; b=2"` |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show full notes for every test |
| `--yes` | Skip the authorization confirmation prompt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧭 Risk levels

| Risk | Meaning |
|---|---|
| **CRITICAL** | An attacker-controlled origin is trusted **and** credentials are allowed — full authenticated cross-origin access is possible for anyone. |
| **HIGH** | An attacker-controlled origin is trusted (no credentials), or a bypass technique succeeded with credentials allowed. |
| **MEDIUM** | Wildcard `*` without credentials, or a bypass technique succeeded without credentials. |
| **LOW** | A CORS header is present but correctly scoped to a real allow-list — it never reflects the test origins. |
| **SAFE** | No test origin was ever reflected back. |

> ⚠️ **A finding describes what the server's headers say a browser would be allowed to do — not a confirmed breach.** Always confirm manually what data the endpoint actually returns and whether it's sensitive before reporting or acting on results.

---

## ⚖️ Responsible use

Every test origin CorsX sends lives under `.test`, an IANA-reserved special-use TLD that can never resolve to a real server — so no traffic is ever directed at, or reflects back toward, an actual third party. Still:

- Only run CorsX against targets you **own** or have **explicit permission** to assess.
- CorsX will ask you to confirm authorization before scanning, every time, unless you pass `--yes`.
- You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
cors-x/
├── corsx.py               # Main executable — the tool itself
├── requirements.txt        # Python dependencies
├── examples/
│   └── targets.txt           # Example target list for -l/--list
├── tests/
│   └── test_corsx.py         # Unit tests for the classification engine
├── LICENSE                 # MIT License
└── README.md                # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — additional origin-bypass patterns and refined risk heuristics are great contributions. Please keep additions to synthetic, reserved-TLD test origins, in line with CorsX's design.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
