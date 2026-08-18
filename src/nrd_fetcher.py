"""
Fetch newly-registered-domain lists from WhoisFreaks.

Endpoint shape (file download service, not the REST API host):

    GET https://files.whoisfreaks.com/v3.1/download/domainer/{gtld|cctld}
        ?apiKey=<KEY>&date=YYYY-MM-DD&whois=false

Response is gzipped plain text, one domain per line. Some tiers return the
body already decompressed by the transport, so we sniff the gzip magic number
rather than trusting Content-Encoding.
"""

from __future__ import annotations

import gzip
import logging
import time
from datetime import date

import requests

log = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"


class FetchError(Exception):
    """Feed could not be retrieved for a given (date, tld_set)."""


class NoDataForDate(FetchError):
    """The feed responded, but has no data published for that date yet."""


def _redact(text: str, api_key: str) -> str:
    return text.replace(api_key, "<APIKEY>") if api_key else text


def extract_domains(body: str) -> list[str]:
    """
    Pull domain names out of a feed body.

    The domains-only feed is one bare domain per line, but be tolerant: strip
    a UTF-8 BOM, skip comment and blank lines, and if a line looks like CSV
    take the first field. Anything without a dot is discarded rather than
    guessed at.
    """
    domains: list[str] = []
    for raw in body.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        candidate = line.split(",")[0].strip().strip('"').lower()
        if not candidate or "." not in candidate:
            continue
        if candidate in ("domain", "domain_name", "domainname"):  # header row
            continue
        domains.append(candidate.rstrip("."))
    return domains


def fetch_day(
    tld_set: str,
    feed_date: date,
    api_key: str,
    base_url: str,
    timeout: int = 120,
    max_retries: int = 3,
    session: requests.Session | None = None,
) -> list[str]:
    """
    Fetch and parse one (date, tld_set). Raises NoDataForDate on 404 so the
    caller can distinguish "not published yet" from "something is broken".
    """
    url = f"{base_url}/{tld_set}"
    params = {"apiKey": api_key, "date": feed_date.isoformat(), "whois": "false"}
    http = session or requests.Session()

    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = http.get(url, params=params, timeout=timeout)

            if resp.status_code == 404:
                raise NoDataForDate(
                    f"no {tld_set} data published for {feed_date.isoformat()} (HTTP 404)"
                )
            if resp.status_code in (401, 403):
                raise FetchError(
                    f"HTTP {resp.status_code} for {tld_set} {feed_date}: the API key was "
                    "rejected. Check the key and that your plan covers the NRD "
                    "(Domainer) product."
                )
            if resp.status_code == 429:
                wait = min(60, 5 * attempt)
                log.warning("rate limited on %s %s; sleeping %ds", tld_set, feed_date, wait)
                time.sleep(wait)
                last_exc = FetchError("rate limited")
                continue

            resp.raise_for_status()

            content = resp.content
            if content[:2] == GZIP_MAGIC:
                content = gzip.decompress(content)
            body = content.decode("utf-8", errors="replace")

            domains = extract_domains(body)
            if not domains:
                raise NoDataForDate(
                    f"{tld_set} {feed_date.isoformat()} returned no usable domains "
                    f"({len(body)} bytes) -- most likely not published yet"
                )

            log.info("fetched %s %s: %d domains", tld_set, feed_date, len(domains))
            return domains

        except NoDataForDate:
            raise
        except FetchError as exc:
            last_exc = exc
            if "rejected" in str(exc):
                raise
        except (requests.RequestException, OSError, EOFError) as exc:
            last_exc = exc
            log.warning(
                "attempt %d/%d failed for %s %s: %s",
                attempt,
                max_retries,
                tld_set,
                feed_date,
                _redact(str(exc), api_key),
            )

        if attempt < max_retries:
            time.sleep(2**attempt)

    raise FetchError(
        f"gave up on {tld_set} {feed_date.isoformat()} after {max_retries} attempts: "
        f"{_redact(str(last_exc), api_key)}"
    )