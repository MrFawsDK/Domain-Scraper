#!/usr/bin/env python3
"""
domain_scraper - find ledige korte domæner (2-3 tegn), primært .dk.

Pipeline:
  1. Generér navne (tegnsæt, længder, regex-filter) og sortér efter "værdi".
  2. Asynkron DNS direkte mod TLD'ens autoritative navneservere (rå UDP).
     NXDOMAIN = kandidat. Alt med delegering er optaget. Tusindvis af opslag/sek.
  3. Bekræft kandidater via Punktum DAS (hvis du har registrator-adgang)
     eller WHOIS med adaptiv rate-limiter (~1 opslag/sek for .dk).
  4. Alt gemmes i SQLite, så kørsler kan afbrydes og genoptages, og
     domæner der allerede er tjekket for nylig springes over.

Kun standardbiblioteket - ingen afhængigheder.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import itertools
import json
import os
import random
import re
import socket
import sqlite3
import struct
import sys
import time
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

LETTERS = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
DK_EXTRA = "æøåäöüé"
VOWELS = set("aeiouyæøåäöüé")

CHARSETS = {
    "letters": LETTERS,
    "digits": DIGITS,
    "alnum": LETTERS + DIGITS,
    "all": LETTERS + DIGITS + "-",
    "dk": LETTERS + DIGITS + "-" + DK_EXTRA,
}

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
WHOIS_OVERRIDES = {"dk": "whois.punktum.dk"}
DAS_URL = "https://das.dk-hostmaster.dk/domain/is_available/{}"

NOT_FOUND_MARKERS = (
    "no entries found", "no match", "not found", "no data found",
    "no object found", "status: free", "status: available", "is available",
)
RATE_LIMIT_MARKERS = ("too many requests", "rate limit", "exceeded", "try again later")

RCODE_NOERROR, RCODE_NXDOMAIN = 0, 3


def c(text: str, color: str) -> str:
    codes = {"green": 32, "red": 31, "yellow": 33, "dim": 2, "bold": 1}
    if not sys.stdout.isatty():
        return text
    return f"\033[{codes[color]}m{text}\033[0m"


def log(msg: str = "", end: str = "\n") -> None:
    print(msg, end=end, flush=True)


# ---------------------------------------------------------------------------
# Navnegenerering og prioritering
# ---------------------------------------------------------------------------

def generate_labels(charset: str, lengths: list[int], regex: re.Pattern | None):
    for n in lengths:
        for combo in itertools.product(charset, repeat=n):
            label = "".join(combo)
            if label[0] == "-" or label[-1] == "-":
                continue
            if regex and not regex.fullmatch(label):
                continue
            yield label


def to_ascii(label: str) -> str:
    try:
        label.encode("ascii")
        return label
    except UnicodeEncodeError:
        return label.encode("idna").decode("ascii")


def score(label: str) -> int:
    """Lavere = mere værdifuldt. Bruges til at tjekke de bedste navne først."""
    s = len(label) * 100
    has_digit = any(ch.isdigit() for ch in label)
    if label.isdigit():
        s += 5                      # 123.dk er stadig attraktivt
    elif has_digit:
        s += 40                     # blandet a1b er mindst attraktivt
    if "-" in label:
        s += 60
    if any(ch in DK_EXTRA for ch in label):
        s += 20
    if label.isalpha():
        shape = "".join("v" if ch in VOWELS else "k" for ch in label)
        if shape in ("kvk", "vkv", "kv", "vk"):
            s -= 10                 # udtalbart
        if len(set(label)) == 1:
            s -= 15                 # aaa, zz
    return s


# ---------------------------------------------------------------------------
# Rå DNS (UDP) - asynkron klient
# ---------------------------------------------------------------------------

def encode_qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p) + b"\0"


def build_query(tid: int, name: str, qtype: int = 2, rd: bool = False) -> bytes:
    flags = 0x0100 if rd else 0
    return struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0) + encode_qname(name) + struct.pack(">HH", qtype, 1)


def read_name(data: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(128):
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += ln + 1
    return ".".join(labels), end


def parse_ns_answers(data: bytes) -> list[str]:
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 2:
            out.append(read_name(data, off)[0])
        off += rdlen
    return out


def find_tld_servers(tld: str) -> list[str]:
    """Slå TLD'ens autoritative navneservere op og returnér deres IPv4-adresser."""
    for resolver in PUBLIC_RESOLVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(build_query(random.randint(0, 65535), tld, rd=True), (resolver, 53))
                names = parse_ns_answers(s.recvfrom(4096)[0])
            ips = set()
            for n in names:
                try:
                    for info in socket.getaddrinfo(n, 53, socket.AF_INET, socket.SOCK_DGRAM):
                        ips.add(info[4][0])
                except socket.gaierror:
                    pass
            if ips:
                return sorted(ips)
        except OSError:
            continue
    return []


class AsyncDNS(asyncio.DatagramProtocol):
    def __init__(self):
        self.pending: dict[int, tuple[str, asyncio.Future]] = {}
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 12:
            return
        tid = struct.unpack(">H", data[:2])[0]
        entry = self.pending.get(tid)
        if not entry:
            return
        name, fut = entry
        try:
            qname, _ = read_name(data, 12)
        except (IndexError, UnicodeDecodeError):
            return
        if qname.lower() == name.lower() and not fut.done():
            fut.set_result(data)

    def error_received(self, exc):
        pass

    async def query(self, name: str, servers: list[str], timeout: float, retries: int) -> int | None:
        loop = asyncio.get_running_loop()
        for attempt in range(retries):
            tid = random.randint(0, 65535)
            while tid in self.pending:
                tid = random.randint(0, 65535)
            fut = loop.create_future()
            self.pending[tid] = (name, fut)
            server = servers[(hash(name) + attempt) % len(servers)]
            try:
                self.transport.sendto(build_query(tid, name), (server, 53))
                data = await asyncio.wait_for(fut, timeout)
                truncated = data[2] & 0x02
                rcode = data[3] & 0x0F
                an, ns = struct.unpack(">HH", data[6:10])
                # Response Rate Limiting svarer med tomme/afkortede pakker -
                # de må ikke tolkes som "findes", så vi prøver igen.
                if rcode == RCODE_NXDOMAIN and not truncated:
                    return rcode
                if rcode == RCODE_NOERROR and not truncated and (an or ns):
                    return rcode
                await asyncio.sleep(0.2 * (attempt + 1))
            except (asyncio.TimeoutError, OSError):
                pass
            finally:
                self.pending.pop(tid, None)
        return None


class RateLimiter:
    """Token bucket til DNS, så vi ikke rammer navneservernes RRL."""

    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate / 10
        self.last = time.monotonic()

    async def acquire(self):
        while True:
            now = time.monotonic()
            self.tokens = min(self.rate / 10, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            await asyncio.sleep(0.01)


async def dns_scan(items: list[tuple[str, str, str]], concurrency: int, rate: float):
    """items: (label, ascii_fqdn, tld). Returnerer dict ascii_fqdn -> 'nx'|'exists'|'error'."""
    loop = asyncio.get_running_loop()
    servers_by_tld = {}
    for tld in sorted({t for *_, t in items}):
        servers = find_tld_servers(tld)
        if not servers:
            raise SystemExit(f"Kunne ikke finde navneservere for .{tld}")
        servers_by_tld[tld] = servers
        log(c(f"  .{tld}: {len(servers)} autoritative navneservere", "dim"))

    transport, proto = await loop.create_datagram_endpoint(AsyncDNS, local_addr=("0.0.0.0", 0))
    sem = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate)
    results: dict[str, str] = {}
    done = 0
    total = len(items)
    t0 = time.time()

    async def one(fqdn: str, tld: str):
        nonlocal done
        async with sem:
            await limiter.acquire()
            rcode = await proto.query(fqdn, servers_by_tld[tld], timeout=2.0, retries=5)
        results[fqdn] = {RCODE_NXDOMAIN: "nx", RCODE_NOERROR: "exists"}.get(rcode, "error")
        done += 1
        if (done % 1000 == 0 and sys.stdout.isatty()) or done == total:
            rate = done / max(time.time() - t0, 1e-6)
            nx = sum(1 for v in results.values() if v == "nx")
            log(f"\r  DNS {done}/{total}  ({rate:.0f}/s)  kandidater: {nx}   ", end="")

    try:
        await asyncio.gather(*(one(fqdn, tld) for _, fqdn, tld in items))
    finally:
        transport.close()
    log()
    return results


# ---------------------------------------------------------------------------
# Bekræftelse: WHOIS (adaptiv rate) og Punktum DAS
# ---------------------------------------------------------------------------

def whois_raw(server: str, query: str, timeout: float = 15) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while chunk := s.recv(4096):
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


_whois_servers: dict[str, str | None] = {}


def whois_server_for(tld: str) -> str | None:
    if tld in WHOIS_OVERRIDES:
        return WHOIS_OVERRIDES[tld]
    if tld not in _whois_servers:
        server = None
        for line in whois_raw("whois.iana.org", tld).splitlines():
            if line.lower().startswith(("refer:", "whois:")):
                server = line.split(":", 1)[1].strip() or None
                if server:
                    break
        _whois_servers[tld] = server
    return _whois_servers[tld]


class AdaptiveLimiter:
    """Holder sig lige under serverens grænse: sænker farten ved rate-limit,
    øger den langsomt igen efter en række succesfulde opslag."""

    def __init__(self, interval: float):
        self.base = interval
        self.interval = interval
        self.last = 0.0
        self.streak = 0
        self.lock = asyncio.Lock()

    async def wait(self):
        async with self.lock:
            delay = self.last + self.interval - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()

    def ok(self):
        self.streak += 1
        if self.streak >= 30 and self.interval > self.base:
            self.interval = max(self.base, self.interval * 0.9)
            self.streak = 0

    def limited(self):
        self.streak = 0
        self.interval = min(self.interval * 1.25, 10.0)


async def whois_check(fqdn: str, server: str, limiter: AdaptiveLimiter) -> str:
    """Returnerer 'free' | 'taken' | 'unknown'."""
    backoff = 3.0
    for _ in range(8):
        await limiter.wait()
        try:
            resp = await asyncio.to_thread(whois_raw, server, fqdn)
        except OSError:
            resp = "too many requests"
        body = "\n".join(l for l in resp.splitlines()
                         if not l.lstrip().startswith(("#", "%"))).lower()
        if any(m in body for m in RATE_LIMIT_MARKERS):
            limiter.limited()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)
            continue
        limiter.ok()
        return "free" if any(m in body for m in NOT_FOUND_MARKERS) else "taken"
    return "unknown"


def das_check_sync(label: str, user: str, password: str) -> str:
    # DAS kræver UTF-8 (ikke punycode) i stien
    url = DAS_URL.format(urllib.parse.quote(f"{label}.dk"))
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        status = json.load(r).get("domain_status", "")
    return {"available": "free", "unavailable": "taken",
            "available-on-waiting-list": "waitlist", "enqueued": "taken"}.get(status, "unknown")


# ---------------------------------------------------------------------------
# Tilstand (SQLite)
# ---------------------------------------------------------------------------

def open_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE IF NOT EXISTS domains (
        domain     TEXT PRIMARY KEY,   -- pæn form, fx blå.dk
        ascii      TEXT NOT NULL,      -- punycode, fx xn--bl-0ia.dk
        tld        TEXT NOT NULL,
        dns        TEXT,               -- nx | exists | error
        status     TEXT,               -- free | taken | waitlist | unknown
        checked_at REAL,
        first_free REAL                -- hvornår vi første gang så den ledig
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_status ON domains(status)")
    return db


# ---------------------------------------------------------------------------
# Notifikationer
# ---------------------------------------------------------------------------

def notify(found: list[str], webhook: str | None, output: str) -> None:
    with open(output, "a", encoding="utf-8") as fh:
        for d in found:
            fh.write(d + "\n")
    if webhook and found:
        payload = json.dumps({"content": "Ledige domæner: " + ", ".join(found),
                              "text": "Ledige domæner: " + ", ".join(found)}).encode()
        req = urllib.request.Request(webhook, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as e:
            log(c(f"  webhook fejlede: {e}", "red"))


# ---------------------------------------------------------------------------
# Hovedløkke
# ---------------------------------------------------------------------------

async def run_once(args, db: sqlite3.Connection, labels: list[str], tlds: list[str]) -> list[str]:
    items = [(l, f"{to_ascii(l)}.{t}", t) for t in tlds for l in labels]
    log(c(f"\n[{time.strftime('%H:%M:%S')}] Scanner {len(items)} domæner", "bold"))

    # 1. DNS
    dns = await dns_scan(items, args.concurrency, args.dns_rate)
    now = time.time()
    cur = db.cursor()
    for label, fqdn, tld in items:
        res = dns[fqdn]
        if res == "exists":
            cur.execute("""INSERT INTO domains(domain, ascii, tld, dns, status, checked_at)
                           VALUES(?,?,?,?, 'taken', ?)
                           ON CONFLICT(domain) DO UPDATE SET dns='exists', status='taken',
                           checked_at=excluded.checked_at""",
                        (f"{label}.{tld}", fqdn, tld, res, now))
        else:
            cur.execute("""INSERT INTO domains(domain, ascii, tld, dns) VALUES(?,?,?,?)
                           ON CONFLICT(domain) DO UPDATE SET dns=excluded.dns""",
                        (f"{label}.{tld}", fqdn, tld, res))
    db.commit()

    # 2. Hvilke kandidater skal bekræftes?
    max_age = args.max_age * 3600
    candidates = []
    for label, fqdn, tld in items:
        if dns[fqdn] == "exists":
            continue
        row = db.execute("SELECT status, checked_at FROM domains WHERE domain=?",
                         (f"{label}.{tld}",)).fetchone()
        fresh = row and row[0] in ("free", "taken", "waitlist") and row[1] and now - row[1] < max_age
        if not fresh:
            candidates.append((label, fqdn, tld))
    candidates.sort(key=lambda x: (score(x[0]), x[0]))
    if args.limit:
        candidates = candidates[:args.limit]

    errors = sum(1 for v in dns.values() if v == "error")
    log(f"  DNS: {sum(1 for v in dns.values() if v == 'nx')} kandidater, "
        f"{errors} fejl, {len(candidates)} skal bekræftes")

    if args.no_confirm:
        return [f"{l}.{t}" for l, _, t in candidates]

    # 3. Bekræft
    das_user = os.environ.get("PUNKTUM_DAS_USER")
    das_pass = os.environ.get("PUNKTUM_DAS_PASSWORD")
    limiters: dict[str, AdaptiveLimiter] = {}
    newly_free: list[str] = []
    eta = len(candidates) * args.whois_interval
    if candidates and not das_user:
        log(c(f"  WHOIS ~{args.whois_interval:.1f}s/opslag, est. {eta/60:.0f} min "
              f"(afbryd når som helst - fremskridt gemmes)", "dim"))

    das_sem = asyncio.Semaphore(8)

    async def confirm(label: str, fqdn: str, tld: str) -> str:
        if tld == "dk" and das_user and das_pass:
            async with das_sem:
                try:
                    return await asyncio.to_thread(das_check_sync, label, das_user, das_pass)
                except Exception:
                    return "unknown"
        server = whois_server_for(tld)
        if not server:
            return "unknown"
        limiter = limiters.setdefault(server, AdaptiveLimiter(args.whois_interval))
        return await whois_check(fqdn, server, limiter)

    async def handle(i: int, label: str, fqdn: str, tld: str):
        domain = f"{label}.{tld}"
        status = await confirm(label, fqdn, tld)
        prev = db.execute("SELECT status FROM domains WHERE domain=?", (domain,)).fetchone()
        db.execute("""UPDATE domains SET status=?, checked_at=?,
                      first_free=CASE WHEN ?='free' AND first_free IS NULL THEN ? ELSE first_free END
                      WHERE domain=?""", (status, time.time(), status, time.time(), domain))
        db.commit()
        tag = {"free": c("LEDIG", "green"), "taken": c("optaget", "dim"),
               "waitlist": c("venteliste", "yellow"), "unknown": c("ukendt", "red")}[status]
        shown = domain if fqdn == domain else f"{domain} ({fqdn})"
        if status == "free" or args.verbose:
            log(f"  [{i}/{len(candidates)}] {shown:<24} {tag}")
        if status == "free" and (not prev or prev[0] != "free"):
            newly_free.append(domain)
            notify([domain], args.webhook, args.output)

    # DAS kan køre parallelt; WHOIS serialiseres af limiteren pr. server
    batch = 32
    for start in range(0, len(candidates), batch):
        chunk = candidates[start:start + batch]
        await asyncio.gather(*(handle(start + j + 1, *cand) for j, cand in enumerate(chunk)))
        if not args.verbose:
            log(c(f"\r  ... {min(start + batch, len(candidates))}/{len(candidates)} bekræftet", "dim"),
                end="\r")
    log()
    return newly_free


def print_known_free(db: sqlite3.Connection, tlds: list[str]) -> None:
    rows = db.execute(
        f"SELECT domain FROM domains WHERE status='free' AND tld IN ({','.join('?' * len(tlds))})",
        tlds).fetchall()
    domains = sorted((r[0] for r in rows), key=lambda d: (score(d.rsplit('.', 1)[0]), d))
    log(c(f"\n{len(domains)} kendte LEDIGE domæner (bedste først):", "bold"))
    for d in domains:
        log("  " + c(d, "green"))


def parse_args():
    ap = argparse.ArgumentParser(
        description="Find ledige korte domæner (standard: 2-3 tegn under .dk).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--tlds", default="dk", help="kommasepareret, fx dk,com,io")
    ap.add_argument("--lengths", default="2,3", help="kommasepareret, fx 2,3")
    ap.add_argument("--charset", default="all", choices=CHARSETS,
                    help="letters | digits | alnum | all (+bindestreg) | dk (+æøåäöüé)")
    ap.add_argument("--regex", help="kun navne der matcher, fx '[a-z]{3}' eller '.*x.*'")
    ap.add_argument("--limit", type=int, help="bekræft kun de N bedste kandidater")
    ap.add_argument("--concurrency", type=int, default=256, help="samtidige DNS-opslag")
    ap.add_argument("--dns-rate", type=float, default=1000,
                    help="max DNS-opslag/sek (for højt udløser navneservernes rate-limiting)")
    ap.add_argument("--whois-interval", type=float, default=1.05,
                    help="sekunder mellem WHOIS-opslag (Punktum tillader ~1/s)")
    ap.add_argument("--max-age", type=float, default=24,
                    help="timer før et bekræftet resultat tjekkes igen")
    ap.add_argument("--no-confirm", action="store_true",
                    help="kun DNS - hurtigt, men kan give falske positive")
    ap.add_argument("--watch", type=float, metavar="MIN",
                    help="kør igen hvert MIN minut og meld nye ledige domæner")
    ap.add_argument("--webhook", help="Discord/Slack webhook-URL til notifikationer")
    ap.add_argument("--db", default="domains.db", help="SQLite-fil med tilstand")
    ap.add_argument("-o", "--output", default="ledige_domaener.txt",
                    help="nye ledige domæner tilføjes her")
    ap.add_argument("--list", action="store_true", help="vis kendte ledige fra databasen og stop")
    ap.add_argument("-v", "--verbose", action="store_true", help="vis også optagne domæner")
    return ap.parse_args()


def main():
    if os.name == "nt":
        os.system("")  # aktiver ANSI-farver i Windows-terminal
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except AttributeError:
            pass
    args = parse_args()
    tlds = [t.strip().lstrip(".").lower() for t in args.tlds.split(",") if t.strip()]
    lengths = sorted({int(x) for x in args.lengths.split(",")})
    db = open_db(args.db)

    if args.list:
        print_known_free(db, tlds)
        return

    if args.charset == "dk" and tlds != ["dk"]:
        log(c("Bemærk: æøåäöüé er kun gyldige under .dk.", "yellow"))
    regex = re.compile(args.regex) if args.regex else None
    labels = list(generate_labels(CHARSETS[args.charset], lengths, regex))
    if not labels:
        raise SystemExit("Ingen navne matcher dine filtre.")

    try:
        while True:
            found = asyncio.run(run_once(args, db, labels, tlds))
            if args.no_confirm:
                log(c(f"\n{len(found)} DNS-kandidater (ikke bekræftet):", "bold"))
                log("  " + "  ".join(found[:300]) + ("  ..." if len(found) > 300 else ""))
            else:
                print_known_free(db, tlds)
                if found:
                    log(c(f"\n{len(found)} NYE ledige i denne kørsel - gemt i {args.output}", "green"))
            if not args.watch:
                break
            log(c(f"\nVenter {args.watch:g} min ... (Ctrl+C for at stoppe)", "dim"))
            time.sleep(args.watch * 60)
    except KeyboardInterrupt:
        log(c("\nAfbrudt - fremskridt er gemt i " + args.db, "yellow"))


if __name__ == "__main__":
    main()
