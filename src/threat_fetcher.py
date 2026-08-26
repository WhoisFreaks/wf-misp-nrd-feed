"""
Fetch WhoisFreaks Domain Threat Feeds (phishing, malware, spam).

Endpoint (override the base with THREAT_BASE_URL if your tier differs):

    GET https://files.whoisfreaks.com/v3.4/download/threat-feed/{phishing|malware|spam}
        ?apiKey=<KEY>[&date=YYYY-MM-DD]

Delivery model differs from the NRD feed in a way that matters:

  * omitting `date` returns a FULL DUMP of everything currently in the feed
  * passing `date` returns a DAILY UPDATE containing only new and changed rows

So the first run bootstraps from a full dump, and every run after that pulls
one small delta. All three feeds share a single CSV schema:

    domain, threat_type, confidence, first_seen, last_seen,
    No_of_threat_matched_pivots
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
import re
import time
import zipfile
from dataclasses import dataclass
from datetime import date

import requests

log = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"
THREAT_TYPES = ("phishing", "malware", "spam")

# Multi-label public suffixes common enough to matter here. Needed because
# label-counting cannot tell an apex from a subdomain: 012.net.il has two dots
# and IS an apex, while x.weebly.com has two dots and is NOT. This is a
# pragmatic subset, not the full Public Suffix List -- if `tldextract` is
# installed it is used instead and this is ignored.
_MULTI_SUFFIXES = frozenset(
    """
co.uk org.uk me.uk ltd.uk plc.uk net.uk sch.uk ac.uk gov.uk nhs.uk
com.au net.au org.au edu.au gov.au id.au asn.au
co.nz net.nz org.nz govt.nz ac.nz geek.nz school.nz
co.za org.za net.za web.za gov.za ac.za
com.br net.br org.br gov.br edu.br
com.cn net.cn org.cn gov.cn edu.cn ac.cn
co.jp ne.jp or.jp ac.jp go.jp
co.in net.in org.in gov.in ac.in firm.in gen.in ind.in
com.mx org.mx net.mx gob.mx
com.tr net.tr org.tr gov.tr edu.tr
com.ar net.ar org.ar gov.ar edu.ar
com.sg net.sg org.sg gov.sg edu.sg
com.hk net.hk org.hk gov.hk edu.hk idv.hk
com.tw net.tw org.tw gov.tw edu.tw idv.tw
net.il co.il org.il ac.il gov.il muni.il k12.il
com.ua net.ua org.ua gov.ua in.ua kiev.ua
com.pl net.pl org.pl gov.pl edu.pl waw.pl
co.kr ne.kr or.kr re.kr pe.kr go.kr ac.kr
com.my net.my org.my gov.my edu.my
com.ph net.ph org.ph gov.ph edu.ph
com.vn net.vn org.vn gov.vn edu.vn
co.th in.th ac.th go.th or.th
com.eg net.eg org.eg gov.eg edu.eg
com.sa net.sa org.sa gov.sa edu.sa
com.ng net.ng org.ng gov.ng edu.ng
com.pk net.pk org.pk gov.pk edu.pk
co.id or.id ac.id go.id web.id
com.co net.co org.co gov.co edu.co
com.pe net.pe org.pe gob.pe edu.pe
com.uy net.uy org.uy gub.uy edu.uy
com.ec net.ec org.ec gob.ec edu.ec
com.ve net.ve org.ve gob.ve edu.ve
com.do net.do org.do gob.do edu.do
com.gt net.gt org.gt gob.gt edu.gt
com.cy net.cy org.cy gov.cy ac.cy
com.mt net.mt org.mt gov.mt edu.mt
com.gr net.gr org.gr gov.gr edu.gr
com.pt net.pt org.pt gov.pt edu.pt
com.es nom.es org.es gob.es edu.es
com.ru net.ru org.ru pp.ru msk.ru spb.ru
com.kz net.kz org.kz gov.kz edu.kz
com.ge net.ge org.ge gov.ge edu.ge
com.by net.by org.by gov.by
co.ke or.ke ne.ke go.ke ac.ke
co.tz or.tz ne.tz go.tz ac.tz
co.ug or.ug ne.ug go.ug ac.ug
com.gh net.gh org.gh gov.gh edu.gh
""".split()  # noqa: SIM905 - readable block beats a 256-item literal
)

_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?"
    r"\s*(Z|[+-]\d{2}(?::?\d{2})?)?$"
)


def normalise_timestamp(raw: str) -> str:
    """
    Rewrite a feed timestamp into strict ISO-8601 for MISP.

    The feed emits things like `2026-07-21 00:16:14.99156+00`: a space instead
    of T, a two-digit UTC offset, and a fractional part of whatever length the
    database produced (5 digits here). MISP wants ISO-8601, and
    datetime.fromisoformat on Python 3.9 -- the version floor of this project --
    rejects both the bare `+00` offset and any fraction that is not exactly 3 or
    6 digits. Normalising once here keeps both happy.

    Unparseable input is returned unchanged rather than dropped: better to hand
    MISP something imperfect than to silently discard evidence.
    """
    if not raw:
        return ""
    m = _TS_RE.match(raw.strip())
    if not m:
        return raw.strip()
    day, clock, frac, off = m.groups()
    out = f"{day}T{clock}"
    if frac:
        out += "." + frac[:6].ljust(6, "0")
    if off in (None, "", "Z"):
        out += "+00:00"
    elif len(off) == 3:                 # "+00"
        out += f"{off}:00"
    elif ":" not in off:                # "+0000"
        out += f"{off[:3]}:{off[3:]}"
    else:
        out += off
    return out


def is_apex(domain: str) -> bool:
    """
    True if `domain` looks like a registrable apex rather than a subdomain.

    Used to choose the MISP attribute type: `domain` for an apex, `hostname` for
    anything below it. Uses tldextract when available, otherwise the bundled
    suffix subset above.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return True
    try:
        import tldextract
    except ImportError:
        pass  # optional; fall through to the bundled suffix subset
    else:
        try:
            return not tldextract.extract(domain).subdomain
        except (ValueError, TypeError, OSError) as exc:
            log.debug("tldextract failed on %r (%s); using bundled suffixes",
                      domain, exc)
    if len(labels) == 2:
        return True
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return len(labels) == 3
    return False


class ThreatFetchError(Exception):
    """Feed could not be retrieved."""


def decode_body(content: bytes) -> str:
    """
    Turn a response body into CSV text, whatever container it arrived in.

    Sniffs the magic number rather than trusting Content-Type or
    Content-Encoding, because transports vary in whether they pre-decompress.
    Handles gzip and zip; plain CSV passes through.

    Binary that is neither is rejected loudly. Without that check a zipped body
    decodes to mojibake, and the CSV reader happily finds "rows" in the noise —
    a handful of junk attributes is far worse than a clear failure.
    """
    if content[:2] == GZIP_MAGIC:
        content = gzip.decompress(content)
    elif content[:4] == ZIP_MAGIC:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise ThreatFetchError("zip archive is empty")
            # Feeds ship one file per archive; concatenate defensively if not.
            content = b"".join(zf.read(n) for n in sorted(names))

    text = content.decode("utf-8", errors="replace")
    sample = text[:4096]
    if sample:
        # U+FFFD counts as "printable", so testing printability alone lets
        # mojibake through. Count undecodable bytes and control characters
        # instead -- real CSV has essentially none.
        bad = sum(
            c == "\ufffd" or (not c.isprintable() and c not in "\r\n\t")
            for c in sample
        )
        if bad / len(sample) > 0.05:
            raise ThreatFetchError(
                "response body is not text CSV (and is not gzip or zip). "
                f"First bytes: {content[:16]!r}"
            )
    return text


class NoThreatDataForDate(ThreatFetchError):
    """No update published for that date yet."""


@dataclass(frozen=True)
class ThreatRecord:
    domain: str
    threat_type: str
    confidence: float
    first_seen: str
    last_seen: str
    pivots: int

    @property
    def misp_type(self) -> str:
        """`domain` for an apex, `hostname` for a subdomain -- MISP's own split."""
        return "domain" if is_apex(self.domain) else "hostname"

    def as_comment(self) -> str:
        bits = [self.threat_type]
        bits.append(f"confidence {self.confidence:g}")
        if self.pivots:
            bits.append(f"{self.pivots} infrastructure pivot"
                        f"{'s' if self.pivots != 1 else ''}")
        return "; ".join(bits)


def _num(raw: str, default: float = 0.0) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def parse_csv(body: str, threat_type: str) -> list[ThreatRecord]:
    """
    Parse a threat feed CSV.

    Tolerant by design: header names are matched case-insensitively (the docs
    show `No_of_threat_matched_pivots` with mixed case), unknown columns are
    ignored, and rows without a usable domain are dropped rather than guessed
    at. Falls back to positional parsing if no header row is present.
    """
    text = body.lstrip("\ufeff")
    if not text.strip():
        return []

    reader = csv.reader(io.StringIO(text))
    try:
        first = next(reader)
    except StopIteration:
        return []

    lower = [c.strip().lower() for c in first]
    has_header = "domain" in lower
    idx = {name: lower.index(name) for name in lower} if has_header else {}

    def col(row: list[str], name: str, pos: int) -> str:
        if has_header:
            i = idx.get(name, -1)
        else:
            i = pos
        return row[i].strip() if 0 <= i < len(row) else ""

    rows = reader if has_header else [first, *reader]
    out: list[ThreatRecord] = []
    for row in rows:
        if not row:
            continue
        domain = col(row, "domain", 0).strip('"').lower().rstrip(".")
        if not domain or "." not in domain:
            continue
        out.append(ThreatRecord(
            domain=domain,
            threat_type=(col(row, "threat_type", 1) or threat_type).lower(),
            confidence=_num(col(row, "confidence", 2), 1.0),
            first_seen=normalise_timestamp(col(row, "first_seen", 3)),
            last_seen=normalise_timestamp(col(row, "last_seen", 4)),
            pivots=int(_num(col(row, "no_of_threat_matched_pivots", 5), 0)),
        ))
    return out


def fetch_raw(
        threat_type: str,
        api_key: str,
        base_url: str,
        feed_date: date | None = None,
        timeout: int = 180,
        max_retries: int = 3,
        session: requests.Session | None = None,
) -> str:
    """
    Fetch one threat feed and return the raw CSV body.

    Raw rather than parsed so the cache stores exactly what the API returned:
    if the schema gains a column, previously cached files remain re-parseable
    instead of having been narrowed on the way in.

    Pass feed_date=None for the full dump.
    """
    if threat_type not in THREAT_TYPES:
        raise ThreatFetchError(
            f"unknown threat type {threat_type!r}; expected one of "
            f"{list(THREAT_TYPES)}"
        )

    url = f"{base_url.rstrip('/')}/{threat_type}"
    # Exactly the documented call: apiKey plus optional date. `format` is
    # omitted because CSV is the only option and the default, so sending it
    # adds a parameter the endpoint never needs.
    params = {"apiKey": api_key}
    if feed_date is not None:
        params["date"] = feed_date.isoformat()
    http = session or requests.Session()
    what = f"{threat_type} {'full dump' if feed_date is None else feed_date.isoformat()}"

    last: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = http.get(url, params=params, timeout=timeout)

            if resp.status_code == 404:
                raise NoThreatDataForDate(f"no update published for {what} (HTTP 404)")
            if resp.status_code in (401, 403):
                raise ThreatFetchError(
                    f"HTTP {resp.status_code} for {what}: key rejected. Check the "
                    "key and that your plan includes Domain Threat Feeds."
                )
            if resp.status_code == 429:
                wait = min(60, 5 * attempt)
                log.warning("rate limited on %s; sleeping %ds", what, wait)
                time.sleep(wait)
                last = ThreatFetchError("rate limited")
                continue
            resp.raise_for_status()

            body = decode_body(resp.content)
            records = parse_csv(body, threat_type)
            if not records:
                raise NoThreatDataForDate(
                    f"{what} returned no usable rows ({len(body)} bytes)"
                )
            log.info("fetched %s: %d records", what, len(records))
            return body

        except NoThreatDataForDate:
            raise
        except ThreatFetchError as exc:
            last = exc
            if "rejected" in str(exc):
                raise
        except (requests.RequestException, OSError, EOFError) as exc:
            last = exc
            log.warning("attempt %d/%d failed for %s: %s", attempt, max_retries,
                        what, str(exc).replace(api_key, "<APIKEY>") if api_key else exc)
        if attempt < max_retries:
            time.sleep(2 ** attempt)

    msg = str(last).replace(api_key, "<APIKEY>") if api_key else str(last)
    raise ThreatFetchError(f"gave up on {what} after {max_retries} attempts: {msg}")


def fetch(
        threat_type: str,
        api_key: str,
        base_url: str,
        feed_date: date | None = None,
        timeout: int = 180,
        max_retries: int = 3,
        session: requests.Session | None = None,
) -> list[ThreatRecord]:
    """Convenience wrapper: fetch and parse in one call."""
    body = fetch_raw(threat_type, api_key, base_url, feed_date, timeout,
                     max_retries, session)
    return parse_csv(body, threat_type)