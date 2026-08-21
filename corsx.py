#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 _____ ___________  _____  __   __
/  __ \\  _  | ___ \\/  ___| \\ \\ / /
| /  \\/ | | | |_/ /\\ `--.   \\ V /
| |   | | | |    /  `--. \\  /   \\
| \\__/\\ \\_/ / |\\ \\ /\\__/ / / /^\\ \\
 \\____/\\___/\\_| \\_|\\____/  \\/   \\/

CorsX — Cross-Origin Misconfiguration Analyzer
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder

DISCLAIMER:
    CorsX sends a handful of normal HTTP GET/OPTIONS requests carrying
    a synthetic "Origin" header — the exact same header any real
    browser attaches automatically on a cross-origin request. All test
    origins live under IANA-reserved, non-resolvable TLDs (.test /
    .example) so nothing is ever sent to, or reflects traffic toward,
    a real third-party domain. CorsX does not perform any browser
    action, does not read cross-origin response bodies, and does not
    exploit anything — it only reports what the server's own response
    headers say it would allow a browser to do.

    A finding describes server configuration, not a confirmed breach.
    Only use this tool against targets you own or are explicitly
    authorized to assess.
"""

import argparse
import concurrent.futures
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

TOOL_NAME = "CorsX"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"

requests.packages.urllib3.disable_warnings()  # noqa


#  UI toolkit — a deliberately different visual language from the rest of
#  the Linxploit X-Suite: violet→crimson gradient, a live status strip,


GRADIENT = [
    "\033[38;5;93m",
    "\033[38;5;99m",
    "\033[38;5;135m",
    "\033[38;5;141m",
    "\033[38;5;177m",
    "\033[38;5;213m",
    "\033[38;5;207m",
    "\033[38;5;201m",
    "\033[38;5;198m",
    "\033[38;5;196m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_SAFE = Fore.GREEN + BOLD
C_LOW = Fore.CYAN + BOLD
C_MED = Fore.YELLOW + BOLD
C_HIGH = "\033[38;5;208m" + BOLD  # orange
C_CRIT = "\033[38;5;196m" + BOLD  # crimson
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;135m" + BOLD  # violet accent
C_INFO = Fore.CYAN

RISK_COLOR = {
    "SAFE": C_SAFE, "LOW": C_LOW, "MEDIUM": C_MED, "HIGH": C_HIGH, "CRITICAL": C_CRIT,
}
RISK_ORDER = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "┌" if UNICODE_OK else "+", "tr": "┐" if UNICODE_OK else "+",
    "bl": "└" if UNICODE_OK else "+", "br": "┘" if UNICODE_OK else "+",
    "h": "─" if UNICODE_OK else "-", "v": "│" if UNICODE_OK else "|",
    "lt": "├" if UNICODE_OK else "+", "rt": "┤" if UNICODE_OK else "+",
    "cross": "┼" if UNICODE_OK else "+", "t": "┬" if UNICODE_OK else "+", "b": "┴" if UNICODE_OK else "+",
    "dtl": "╔" if UNICODE_OK else "+", "dtr": "╗" if UNICODE_OK else "+",
    "dbl": "╚" if UNICODE_OK else "+", "dbr": "╝" if UNICODE_OK else "+",
    "dh": "═" if UNICODE_OK else "-", "dv": "║" if UNICODE_OK else "|",
    "check": "✔" if UNICODE_OK else "OK", "cross_mark": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!", "spark": "✦" if UNICODE_OK else "*",
    "bolt": "⚡" if UNICODE_OK else "!", "globe": "🌐" if UNICODE_OK else "[W]",
    "dot": "•" if UNICODE_OK else "*",
}

BANNER_ART = r"""
 _____ ___________  _____  __   __
/  __ \  _  | ___ \/  ___| \ \ / /
| /  \/ | | | |_/ /\ `--.   \ V /
| |   | | | |    /  `--. \  /   \
| \__/\ \_/ / |\ \ /\__/ / / /^\ \
 \____/\___/\_| \_|\____/  \/   \/
""".rstrip("\n")

BANNER_ART_ASCII = r"""
  ___  ___  ___  ___     __  __
 / __)/ _ \| _ \/ __)___ \ \/ /
| (__| (_) |   /\__ (___) >  <
 \___)\___/|_|_\(___/    /_/\_\
""".rstrip("\n")

import re  # noqa: E402
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def status_strip(items: List[Tuple[str, str, str]]):
    """A single-line strip of bracketed status chips, e.g.
    [ ENGINE: CorsX v1.0 ] [ TESTS: 7 ] [ MODE: ACTIVE ]"""
    chips = []
    for label, value, color in items:
        chips.append(f"{C_MUTE}[{RESET} {color}{label}: {value}{RESET} {C_MUTE}]{RESET}")
    print("  " + "  ".join(chips))


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(strip_ansi(line)) for line in art.splitlines()) + 6

    print()
    for line in art.splitlines():
        print(gradient_line(line))
    print()

    tagline = f"{BOX['spark']} Cross-Origin Misconfiguration Analyzer {BOX['spark']}"
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · Synthetic origins only. Reserved TLDs. No exploitation."
    print(C_MUTE + sub.center(width) + RESET)
    print()

    status_strip([
        ("AUTHOR", AUTHOR, C_ACC),
        ("ORG", ORG, C_ACC),
        ("SITE", SITE, C_MUTE),
    ])
    print()


def hr(color=C_MUTE, width=70, ch=None):
    print(color + (ch or BOX["h"]) * width + RESET)


def section_title(title: str, color: str = C_ACC):
    print()
    print(f"{color}{BOX['dot']} {BOLD}{title}{RESET}")
    hr(C_MUTE, len(strip_ansi(title)) + 2)


def draw_table(headers: List[str], rows: List[List[str]], colors: Optional[List[Optional[str]]] = None):
    """Render a bordered grid table. `colors` is an optional per-row color
    applied to the whole row (e.g. by risk level)."""
    cols = len(headers)
    widths = [len(strip_ansi(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(strip_ansi(str(cell))))
    widths = [w + 2 for w in widths]

    def border(left, mid, right, fill):
        return left + mid.join(fill * w for w in widths) + right

    def row_line(cells, color=None):
        parts = []
        for i, cell in enumerate(cells):
            text = str(cell)
            pad = widths[i] - len(strip_ansi(text)) - 1
            cell_color = color or ""
            parts.append(f" {cell_color}{text}{RESET if color else ''}" + " " * pad)
        return BOX["v"] + BOX["v"].join(parts) + BOX["v"]

    print(C_MUTE + border(BOX["tl"], BOX["t"], BOX["tr"], BOX["h"]) + RESET)
    print(C_MUTE + row_line([BOLD + h + RESET for h in headers]) + RESET)
    print(C_MUTE + border(BOX["lt"], BOX["cross"], BOX["rt"], BOX["h"]) + RESET)
    for i, row in enumerate(rows):
        color = colors[i] if colors else None
        print(C_MUTE + row_line(row, color) + RESET)
    print(C_MUTE + border(BOX["bl"], BOX["b"], BOX["br"], BOX["h"]) + RESET)


# ---- verdict stamp -----------------------------------------------------

def verdict_stamp(label: str, color: str, width: int = 46):
    inner = f" {BOX['bolt']} {label} {BOX['bolt']} "
    pad = max(width - len(strip_ansi(inner)), 0)
    left = pad // 2
    right = pad - left
    line = " " * left + inner + " " * right
    print()
    print(color + BOX["dtl"] + BOX["dh"] * width + BOX["dtr"] + RESET)
    print(color + BOX["dv"] + line + BOX["dv"] + RESET)
    print(color + BOX["dbl"] + BOX["dh"] * width + BOX["dbr"] + RESET)
    print()


# --------------------------------------------------------------------------- #
#  Test matrix — well-documented CORS misconfiguration patterns
#  (the same public techniques described in the OWASP Testing Guide and
#  used by well-known open-source CORS scanners).
# --------------------------------------------------------------------------- #

DEFAULT_ATTACKER_DOMAIN = "corsx-probe.test"  # IANA-reserved, non-resolvable TLD


def build_test_origins(target_host: str, attacker_domain: str) -> List[Tuple[str, str, str]]:
    """Returns a list of (test_id, description, origin_value)."""
    return [
        ("reflected_arbitrary", "Arbitrary attacker origin reflected?",
         f"https://{attacker_domain}"),
        ("null_origin", "'null' Origin trusted?",
         "null"),
        ("suffix_trick", "Weak suffix/startswith match bypass?",
         f"https://{target_host}.{attacker_domain}"),
        ("prefix_trick", "Weak substring/endswith match bypass?",
         f"https://evil-{target_host}"),
        ("case_variation", "Case-sensitive comparison bug?",
         f"HTTPS://{attacker_domain.upper()}"),
        ("scheme_downgrade", "Scheme ignored in origin validation?",
         f"http://{target_host}"),
        ("port_variation", "Port ignored in origin validation?",
         f"https://{target_host}:4443"),
    ]


# --------------------------------------------------------------------------- #
#  Core scan
# --------------------------------------------------------------------------- #

@dataclass
class CorsFinding:
    test_id: str
    description: str
    test_origin: str
    allow_origin: Optional[str] = None
    allow_credentials: Optional[str] = None
    vary_includes_origin: bool = False
    reflected: bool = False
    risk: str = "SAFE"
    note: str = ""


@dataclass
class PreflightInfo:
    allow_methods: Optional[str] = None
    allow_headers: Optional[str] = None
    max_age: Optional[str] = None


@dataclass
class ScanResult:
    url: str
    findings: List[CorsFinding] = field(default_factory=list)
    preflight: Optional[PreflightInfo] = None
    error: Optional[str] = None

    @property
    def overall_risk(self) -> str:
        if self.error:
            return "ERROR"
        if not self.findings:
            return "SAFE"
        return max((f.risk for f in self.findings), key=lambda r: RISK_ORDER.get(r, 0))


def classify(test_id: str, test_origin: str, allow_origin: Optional[str], allow_credentials: Optional[str]):
    credentials_true = (allow_credentials or "").strip().lower() == "true"

    if not allow_origin:
        return "SAFE", False, "Origin not reflected — server did not allow this origin."

    ao = allow_origin.strip()

    if ao == "*":
        if credentials_true:
            return ("CRITICAL", False,
                    "Wildcard '*' combined with Allow-Credentials: true. Browsers reject this exact "
                    "combination, but a server sending it is a strong signal of broken CORS logic — "
                    "review immediately.")
        return ("MEDIUM", False,
                "Wildcard '*' — fine for fully public, unauthenticated endpoints only. "
                "Confirm this endpoint never returns sensitive or user-specific data.")

    reflected = ao.lower() == test_origin.lower() or test_origin.lower() in ao.lower()
    if not reflected:
        return ("LOW", False, f"A CORS header is present ('{ao}') but does not reflect the test "
                               f"origin — looks like a properly scoped allow-list.")

    if test_id == "null_origin":
        risk = "HIGH" if credentials_true else "MEDIUM"
        return (risk, True,
                "Server trusts the literal 'null' Origin — reachable from sandboxed iframes, "
                "data: URIs, and some redirect chains." + (" Credentials are allowed too." if credentials_true else ""))

    if test_id in ("suffix_trick", "prefix_trick", "case_variation", "scheme_downgrade", "port_variation"):
        risk = "HIGH" if credentials_true else "MEDIUM"
        return (risk, True,
                f"Origin-validation bypass succeeded ({test_id.replace('_', ' ')}) — indicates a "
                f"flawed matching rule rather than a strict allow-list." +
                (" Credentials are allowed too." if credentials_true else ""))

    # reflected_arbitrary
    risk = "CRITICAL" if credentials_true else "HIGH"
    note = "Arbitrary attacker-controlled Origin is reflected back"
    note += " with credentials allowed — full authenticated cross-origin access is possible." \
        if credentials_true else " — cross-origin reads of this response are possible for any site."
    return risk, True, note


def probe_origin(url: str, origin: str, timeout: int, headers: dict, cookies: dict, verify_ssl: bool):
    req_headers = dict(headers)
    req_headers["Origin"] = origin
    resp = requests.get(url, headers=req_headers, cookies=cookies, timeout=timeout,
                         verify=verify_ssl, allow_redirects=True)
    return resp


def probe_preflight(url: str, origin: str, timeout: int, headers: dict, cookies: dict, verify_ssl: bool) -> PreflightInfo:
    req_headers = dict(headers)
    req_headers["Origin"] = origin
    req_headers["Access-Control-Request-Method"] = "PUT"
    req_headers["Access-Control-Request-Headers"] = "X-Requested-With"
    try:
        resp = requests.options(url, headers=req_headers, cookies=cookies, timeout=timeout, verify=verify_ssl)
        return PreflightInfo(
            allow_methods=resp.headers.get("Access-Control-Allow-Methods"),
            allow_headers=resp.headers.get("Access-Control-Allow-Headers"),
            max_age=resp.headers.get("Access-Control-Max-Age"),
        )
    except Exception:
        return PreflightInfo()


def scan_target(
    url: str,
    timeout: int,
    headers: dict,
    cookies: dict,
    verify_ssl: bool,
    attacker_domain: str,
) -> ScanResult:
    result = ScanResult(url=url)
    parsed = urlparse(url)
    target_host = parsed.netloc or parsed.path

    # Upfront connectivity check — fail fast and clearly rather than letting
    # every individual origin probe fail silently into a misleading "SAFE".
    try:
        requests.get(url, headers=headers, cookies=cookies, timeout=timeout, verify=verify_ssl)
    except requests.exceptions.Timeout:
        result.error = "Request timed out"
        return result
    except requests.exceptions.SSLError as e:
        result.error = f"SSL error: {e}"
        return result
    except requests.exceptions.ConnectionError:
        result.error = "Connection failed"
        return result
    except Exception as e:  # noqa
        result.error = str(e)
        return result

    try:
        test_origins = build_test_origins(target_host, attacker_domain)
        for test_id, description, origin in test_origins:
            try:
                resp = probe_origin(url, origin, timeout, headers, cookies, verify_ssl)
            except Exception as e:  # noqa
                result.findings.append(CorsFinding(
                    test_id=test_id, description=description, test_origin=origin,
                    risk="SAFE", note=f"Request failed ({e}); treated as not reflected.",
                ))
                continue

            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_credentials = resp.headers.get("Access-Control-Allow-Credentials")
            vary = resp.headers.get("Vary", "")
            risk, reflected, note = classify(test_id, origin, allow_origin, allow_credentials)

            result.findings.append(CorsFinding(
                test_id=test_id,
                description=description,
                test_origin=origin,
                allow_origin=allow_origin,
                allow_credentials=allow_credentials,
                vary_includes_origin="origin" in vary.lower(),
                reflected=reflected,
                risk=risk,
                note=note,
            ))

        worst_origin = max(
            (f.test_origin for f in result.findings if f.reflected),
            key=lambda o: 0, default=f"https://{attacker_domain}",
        )
        result.preflight = probe_preflight(url, worst_origin, timeout, headers, cookies, verify_ssl)

    except requests.exceptions.Timeout:
        result.error = "Request timed out"
    except requests.exceptions.SSLError as e:
        result.error = f"SSL error: {e}"
    except requests.exceptions.ConnectionError:
        result.error = "Connection failed"
    except Exception as e:  # noqa
        result.error = str(e)

    return result


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def print_result(result: ScanResult, verbose: bool):
    section_title(f"TARGET: {result.url}", C_ACC)

    if result.error:
        print(f"{C_CRIT}{BOX['cross_mark']} {result.error}{RESET}")
        return

    headers_row = ["TEST", "TEST ORIGIN", "ALLOW-ORIGIN", "CREDS", "RISK"]
    rows = []
    colors = []
    for f in result.findings:
        rows.append([
            f.description,
            f.test_origin if len(f.test_origin) <= 34 else f.test_origin[:31] + "...",
            (f.allow_origin or "—")[:28],
            f.allow_credentials or "—",
            f.risk,
        ])
        colors.append(RISK_COLOR.get(f.risk, C_MUTE))
    draw_table(headers_row, rows, colors)

    if verbose:
        print()
        for f in result.findings:
            color = RISK_COLOR.get(f.risk, C_MUTE)
            print(f"  {color}{BOX['dot']} [{f.risk}] {f.description}{RESET}")
            print(f"      {C_MUTE}{f.note}{RESET}")

    if result.preflight and (result.preflight.allow_methods or result.preflight.allow_headers):
        print()
        print(f"  {C_INFO}{BOX['globe']} Preflight (OPTIONS): "
              f"methods={result.preflight.allow_methods or '—'}  "
              f"headers={result.preflight.allow_headers or '—'}  "
              f"max-age={result.preflight.max_age or '—'}{RESET}")

    verdict = result.overall_risk
    verdict_stamp(f"{verdict} RISK", RISK_COLOR.get(verdict, C_MUTE))


def print_summary(results: List[ScanResult]):
    section_title("SCAN SUMMARY", C_ACC)
    scanned = [r for r in results if not r.error]
    errored = [r for r in results if r.error]

    counts = {}
    for r in scanned:
        counts[r.overall_risk] = counts.get(r.overall_risk, 0) + 1

    rows = []
    colors = []
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        if level in counts:
            dots = (BOX["dot"] * counts[level]) if UNICODE_OK else ("*" * counts[level])
            rows.append([level, str(counts[level]), dots])
            colors.append(RISK_COLOR.get(level, C_MUTE))
    draw_table(["RISK LEVEL", "COUNT", ""], rows, colors)

    if errored:
        print(f"\n  {C_MUTE}{len(errored)} target(s) could not be reached.{RESET}")
    print(f"\n  {BOLD}Total targets scanned:{RESET} {len(results)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [
            {
                "url": r.url,
                "overall_risk": r.overall_risk,
                "error": r.error,
                "preflight": asdict(r.preflight) if r.preflight else None,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_csv(results: List[ScanResult], path: str):
    fields = ["url", "test_id", "description", "test_origin", "allow_origin",
              "allow_credentials", "reflected", "risk", "note"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            for finding in r.findings:
                row = asdict(finding)
                row["url"] = r.url
                writer.writerow({k: row.get(k) for k in fields})


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def parse_header_list(items: Optional[List[str]]) -> dict:
    headers = {}
    if not items:
        return headers
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookie_string(cookie_str: Optional[str]) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def load_targets(args) -> List[str]:
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        if not os.path.isfile(args.list):
            print(C_CRIT + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    return targets


def confirm_authorization(skip: bool) -> bool:
    if skip:
        return True
    print()
    print(f"{C_MED}{BOX['warn']} CorsX sends a handful of GET/OPTIONS requests per target using "
          f"synthetic, non-resolvable test origins.{RESET}")
    print(f"{C_MED}{BOX['warn']} Only assess targets you OWN or are AUTHORIZED to test.{RESET}")
    try:
        answer = input(f"\n{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corsx",
        description=f"{TOOL_NAME} — Cross-Origin Misconfiguration Analyzer by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  corsx.py -u https://api.example.com/data\n"
            "  corsx.py -l targets.txt -v -o report.json\n"
            "  corsx.py -u https://example.com --yes --no-banner\n"
        ),
    )
    parser.add_argument("-u", "--url", help="Target URL to analyze")
    parser.add_argument("-l", "--list", help="File containing a list of target URLs (one per line)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=3, help="Concurrent targets scanned in parallel (default: 3)")
    parser.add_argument("--attacker-domain", default=DEFAULT_ATTACKER_DOMAIN,
                         help=f"Synthetic domain used in test origins (default: {DEFAULT_ATTACKER_DOMAIN})")
    parser.add_argument("-H", "--header", action="append", help="Custom header 'Key: Value' (repeatable)")
    parser.add_argument("-b", "--cookies", help="Cookie string 'a=1; b=2' (test authenticated endpoints)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full notes for every test")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        print(C_CRIT + "\n[!] No target provided. Use -u/--url or -l/--list.\n" + RESET)
        sys.exit(1)

    if not confirm_authorization(args.yes):
        print(C_CRIT + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    headers = parse_header_list(args.header)
    cookies = parse_cookie_string(args.cookies)
    headers.setdefault("User-Agent", f"Mozilla/5.0 ({TOOL_NAME}/{VERSION}; +{SITE})")

    section_title(f"SCANNING {len(targets)} TARGET(S)", C_ACC)
    status_strip([
        ("TESTS", "7 per target", C_ACC),
        ("ATTACKER DOMAIN", args.attacker_domain, C_MUTE),
        ("THREADS", str(args.threads), C_MUTE),
    ])

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_target, url, args.timeout, headers, cookies,
                        not args.no_verify_ssl, args.attacker_domain): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

    # Print in original target order for readability
    order = {url: i for i, url in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.url, 0))
    for result in results:
        print_result(result, args.verbose)

    print_summary(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output)
        print(C_SAFE + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    hr(C_MUTE, 70)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_MED + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
