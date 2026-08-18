"""
Per-day cache of raw NRD feed responses.

One gzip file per (feed_date, tld_set):

    <cache_dir>/nrd-2026-07-27-gtld.txt.gz
    <cache_dir>/nrd-2026-07-27-cctld.txt.gz

Why cache at all: the retention window is a *rolling* window, so on a normal
day only one date is missing. Without a cache every run re-downloads the whole
window, which burns API credits for data that cannot have changed -- feed files
for a past date are immutable once published.

Writes are atomic (temp file + os.replace) so a run killed mid-write leaves
either the old complete file or nothing, never a truncated one.

This module is deliberately the same shape as cache_manager.py in
wf-bind9-nrd-rpz and wf-suricata-nrd-feed.
"""

from __future__ import annotations

import gzip
import logging
import os
import re
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_FILENAME_RE = re.compile(r"^nrd-(\d{4}-\d{2}-\d{2})-([a-z]+)\.txt\.gz$")


def _current_umask() -> int:
    """
    mkstemp() hardcodes 0600 and ignores umask, so cache files need an explicit
    mode. Unlike the feed directory, the cache is only ever read by this tool,
    so honouring the operator's umask is the right behaviour here.
    """
    current = os.umask(0)
    os.umask(current)
    return current


def cache_path(cache_dir: str | Path, feed_date: date, tld_set: str) -> Path:
    return Path(cache_dir) / f"nrd-{feed_date.isoformat()}-{tld_set}.txt.gz"


def anchor_date(today: date | None = None) -> date:
    """
    The most recent date we can reasonably ask for.

    Always yesterday, never today. WhoisFreaks publishes ccTLD data for the
    previous day around 03:00 UTC and gTLD not reliably until the afternoon
    UTC, so asking for today's date returns empty or 404 depending on when
    the cron fires. Anchoring on yesterday makes the run time-of-day agnostic.

    "Today" is deliberately UTC, not local: the feed is published by UTC date,
    so a host in, say, Asia/Karachi running at 02:00 local is still on the
    previous UTC day and would otherwise ask for a date that does not exist
    yet.
    """
    return (today or datetime.now(timezone.utc).date()) - timedelta(days=1)


def window_dates(days: int, anchor: date | None = None) -> list[date]:
    """The retention window, newest first."""
    end = anchor or anchor_date()
    return [end - timedelta(days=i) for i in range(days)]


def save(cache_dir: str | Path, feed_date: date, tld_set: str, domains: list[str]) -> Path:
    """Write one day's domain list, gzipped, atomically."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_path(cache_dir, feed_date, tld_set)

    payload = ("\n".join(domains) + "\n").encode("utf-8") if domains else b""

    fd, tmp_name = tempfile.mkstemp(dir=str(cache_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(
            fileobj=raw, mode="wb", mtime=0
        ) as gz:
            gz.write(payload)
        os.chmod(tmp_name, 0o666 & ~_current_umask())
        os.replace(tmp_name, target)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    log.debug("cached %d domains -> %s", len(domains), target.name)
    return target


def load(cache_dir: str | Path, feed_date: date, tld_set: str) -> list[str]:
    """Read one day's domain list. Returns [] if the file is absent."""
    path = cache_path(cache_dir, feed_date, tld_set)
    if not path.is_file():
        return []
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        log.warning("cache file %s is unreadable (%s); treating as missing", path.name, exc)
        return []


def cached_dates(cache_dir: str | Path, tld_set: str | None = None) -> set[date]:
    """Dates present in the cache, optionally restricted to one TLD set."""
    cache_dir = Path(cache_dir)
    if not cache_dir.is_dir():
        return set()
    found: set[date] = set()
    for entry in cache_dir.iterdir():
        m = _FILENAME_RE.match(entry.name)
        if not m:
            continue
        if tld_set is not None and m.group(2) != tld_set:
            continue
        try:
            found.add(date.fromisoformat(m.group(1)))
        except ValueError:
            continue
    return found


def dates_needing_backfill(
    cache_dir: str | Path,
    retention_days: int,
    tld_sets: tuple[str, ...] = ("gtld", "cctld"),
    anchor: date | None = None,
) -> list[date]:
    """
    Dates inside the window that are missing for at least one requested
    TLD set. Newest first, so a partial run still gets the freshest data.
    """
    wanted = window_dates(retention_days, anchor)
    missing: list[date] = []
    for d in wanted:
        for tld_set in tld_sets:
            if not cache_path(cache_dir, d, tld_set).is_file():
                missing.append(d)
                break
    return missing


def expire_old_cache(
    cache_dir: str | Path,
    retention_days: int,
    anchor: date | None = None,
) -> list[Path]:
    """Delete cache files for dates that have fallen out of the window."""
    keep = set(window_dates(retention_days, anchor))
    cache_dir = Path(cache_dir)
    if not cache_dir.is_dir():
        return []
    removed: list[Path] = []
    for entry in cache_dir.iterdir():
        m = _FILENAME_RE.match(entry.name)
        if not m:
            continue
        try:
            file_date = date.fromisoformat(m.group(1))
        except ValueError:
            continue
        if file_date not in keep:
            entry.unlink(missing_ok=True)
            removed.append(entry)
            log.debug("expired %s", entry.name)
    if removed:
        # INFO, not debug: deleting cached days costs API credits to replace,
        # so it must never happen invisibly.
        log.info(
            "expired %d cache file(s) outside the %d-day window",
            len(removed), retention_days,
        )
    return removed


def merge_day(
    cache_dir: str | Path,
    feed_date: date,
    tld_sets: tuple[str, ...] = ("gtld", "cctld"),
) -> list[str]:
    """
    All domains registered on one date, across the requested TLD sets,
    deduplicated and sorted.

    Sorted output matters: it makes the generated feed JSON byte-stable for
    an unchanged day, which in turn makes "did anything change" answerable
    with a file hash instead of a diff.
    """
    seen: set[str] = set()
    for tld_set in tld_sets:
        seen.update(load(cache_dir, feed_date, tld_set))
    return sorted(seen)