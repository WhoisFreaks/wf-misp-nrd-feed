"""
Build a MISP feed directory from cached NRD data.

A MISP feed is a directory tree, not a single file:

    <output_dir>/manifest.json          time-indexed list of every event
    <output_dir>/<event-uuid>.json      one file per event
    <output_dir>/hashes.csv             "<md5-of-value>,<event-uuid>" per line

MISP is pointed at the containing DIRECTORY -- not at manifest.json, which it
appends itself -- and pulls on its own schedule. Nothing here talks to the MISP
API.

Two design decisions carry most of the weight:

1.  One event per feed-day, with a *deterministic* event UUID derived from
    the date. Re-running for a day updates that event rather than creating a
    duplicate, which is what makes the whole thing idempotent and safe to
    run from cron without bookkeeping.

2.  Attributes are written with to_ids=False and disable_correlation=True.
    A day of gTLD + ccTLD NRDs is on the order of 10^5 domains. Left
    correlating, a 30-day window puts millions of rows through MISP's
    correlation engine, and since NRD membership correlates with nothing
    interesting on its own the result is a slower instance and no extra
    signal. Freshness here is *context* attached to a domain an analyst is
    already looking at, not an IoC in its own right.

The wire format is not invented -- it is pinned to what PyMISP's own
MISPEvent.to_feed()/manifest/attributes_hashes produce, and tests/ asserts
equivalence against the library. We emit plain dicts rather than building
MISPAttribute objects purely for speed: roughly 10x faster and 4x less
memory at 200k attributes, which matters when backfilling 30 days.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import uuid
from collections.abc import Iterable
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
HASHES_NAME = "hashes.csv"


# Mode for everything written into the feed directory.
#
# This is an explicit constant rather than something derived from umask, and
# that is deliberate. Two separate traps converge here:
#
#   1. tempfile.mkstemp() hardcodes 0600 and ignores umask entirely, and
#      os.replace() preserves the source mode. Without an explicit chmod every
#      file lands 0600. Setting UMask= in the systemd unit does not help,
#      because mkstemp never consults it.
#
#   2. Deriving the mode from umask looks respectful but is wrong here. A host
#      with umask 077 -- common on hardened builds -- yields 0600 and a feed
#      MISP cannot read. The directory's entire purpose is to be read by
#      another user (www-data, apache, or uid 33 in a container), so a mode
#      that excludes them is not a stricter policy, it is a broken feed.
#
# Operators who genuinely need something else can set file_mode in config.ini;
# main.py warns loudly if the result is not world-readable.
DEFAULT_FILE_MODE = 0o644


# --------------------------------------------------------------------------- #
# deterministic identity
# --------------------------------------------------------------------------- #


def _ns(namespace: str) -> uuid.UUID:
    try:
        return uuid.UUID(namespace)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(
            f"uuid_namespace {namespace!r} is not a valid UUID. It seeds every "
            "event and attribute UUID in the feed, so it must be a fixed, valid "
            "UUID chosen once per deployment."
        ) from exc


def event_uuid(feed_date: date, namespace: str) -> str:
    return str(uuid.uuid5(_ns(namespace), f"wf-nrd-event|{feed_date.isoformat()}"))


def attribute_uuid(feed_date: date, domain: str, namespace: str) -> str:
    # The date is part of the key on purpose: the same domain can legitimately
    # appear in two days' feeds (re-registration, cross-TLD-set overlap), and
    # MISP requires attribute UUIDs to be globally unique.
    return str(uuid.uuid5(_ns(namespace), f"wf-nrd-attr|{feed_date.isoformat()}|{domain}"))


def threat_event_uuid(threat_type: str, feed_date: date, namespace: str) -> str:
    return str(uuid.uuid5(
        _ns(namespace), f"wf-threat-event|{threat_type}|{feed_date.isoformat()}"))


def threat_attribute_uuid(threat_type: str, domain: str, namespace: str) -> str:
    # Deliberately NOT date-scoped, unlike the NRD equivalent. A flagged domain
    # is one indicator no matter which daily delta first carried it, so the same
    # UUID lets MISP update the existing attribute instead of creating a second
    # one when the domain reappears in a later delta.
    return str(uuid.uuid5(_ns(namespace), f"wf-threat-attr|{threat_type}|{domain}"))


def org_uuid(org_name: str, namespace: str) -> str:
    return str(uuid.uuid5(_ns(namespace), f"wf-nrd-org|{org_name}"))


def content_digest(domains: Iterable[str]) -> str:
    """Stable digest of a day's domain set, used to decide whether to re-stamp."""
    h = hashlib.sha256()
    for d in domains:
        h.update(d.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# atomic writes
# --------------------------------------------------------------------------- #


def _ensure_mode(path: Path, mode: int) -> int | None:
    """
    Bring an existing file up to the expected mode, if it isn't already.

    Guards against an operator or another process tightening permissions on the
    feed directory, which would silently stop MISP reading it.

    Returns the previous mode when a change was made, else None. Quiet no-op
    when the file is absent or we don't own it -- this is opportunistic repair,
    not something worth failing a run over.
    """
    try:
        current = path.stat().st_mode & 0o777
    except OSError:
        return None
    if current == mode:
        return None
    try:
        os.chmod(path, mode)
    except OSError as exc:
        log.warning(
            "%s is mode %04o and should be %04o, but chmod failed: %s",
            path.name, current, mode, exc.strerror or exc,
        )
        return None
    log.info("repaired mode on %s: %04o -> %04o", path.name, current, mode)
    return current


def _atomic_write_text(path: Path, text: str, mode: int = DEFAULT_FILE_MODE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _atomic_write_json(path: Path, payload: Any, mode: int = DEFAULT_FILE_MODE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True, separators=(",", ":"))
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- #
# event construction
# --------------------------------------------------------------------------- #


def _tag_entries(tags: list[str]) -> list[dict[str, Any]]:
    return [
        {"colour": "#ffffff", "local": False, "name": tag, "relationship_type": ""}
        for tag in tags
    ]


def build_event(
    feed_date: date,
    domains: list[str],
    *,
    namespace: str,
    org_name: str,
    info_prefix: str = "WhoisFreaks NRD",
    threat_level_id: int = 4,
    analysis: int = 2,
    published: bool = True,
    to_ids: bool = False,
    disable_correlation: bool = True,
    category: str = "Network activity",
    tags: list[str] | None = None,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Build the {"Event": {...}} structure for one feed-day."""
    ts = str(timestamp if timestamp is not None else _midnight(feed_date))
    ev_uuid = event_uuid(feed_date, namespace)
    comment = f"Registered {feed_date.isoformat()}; source: WhoisFreaks NRD feed"

    attributes = [
        {
            "category": category,
            "comment": comment,
            "disable_correlation": disable_correlation,
            "timestamp": ts,
            "to_ids": to_ids,
            "type": "domain",
            "uuid": attribute_uuid(feed_date, domain, namespace),
            "value": domain,
        }
        for domain in domains
    ]

    return {
        "Event": {
            "analysis": str(analysis),
            "date": feed_date.isoformat(),
            "extends_uuid": "",
            "info": f"{info_prefix} - {feed_date.isoformat()} ({len(domains)} domains)",
            "protected": False,
            "publish_timestamp": ts,
            "published": published,
            "threat_level_id": str(threat_level_id),
            "timestamp": ts,
            "uuid": ev_uuid,
            "Orgc": {"name": org_name, "uuid": org_uuid(org_name, namespace)},
            "Tag": _tag_entries(tags or []),
            "Attribute": attributes,
        }
    }


def build_threat_event(
        threat_type: str,
        feed_date: date,
        records: list[Any],
        *,
        namespace: str,
        org_name: str,
        info_prefix: str = "WhoisFreaks Threat Feed",
        threat_level_id: int = 2,
        analysis: int = 2,
        published: bool = True,
        to_ids: bool = True,
        disable_correlation: bool = False,
        category: str = "Network activity",
        tags: list[str] | None = None,
        timestamp: int | None = None,
) -> dict[str, Any]:
    """
    Build one event for a threat feed day.

    The attribute flags here are the inverse of build_event()'s, and that is the
    whole point. NRD data says "this domain is new", which is context and must
    not correlate or reach an IDS. Threat feed data says "this domain was
    observed hosting credential theft", which is a verdict: you want it exported
    to your IDS ruleset (to_ids) and you want it to correlate, because a match
    against one of your events is exactly the signal you are paying for.

    Volume makes that affordable -- these feeds are orders of magnitude smaller
    than 374k new domains a day.
    """
    ts = str(timestamp if timestamp is not None else _midnight(feed_date))
    ev_uuid = threat_event_uuid(threat_type, feed_date, namespace)

    attributes = []
    for r in records:
        # `domain` for an apex, `hostname` for a subdomain: MISP treats these as
        # distinct types, and a large share of the phishing feed is subdomains
        # on shared hosts (weebly.com and friends). Typing those as `domain`
        # would be wrong and would mislead anything filtering by type.
        attr_type = getattr(r, "misp_type", "domain")
        attr: dict[str, Any] = {
            "category": category,
            "comment": r.as_comment(),
            "disable_correlation": disable_correlation,
            "timestamp": ts,
            "to_ids": to_ids,
            "type": attr_type,
            "uuid": threat_attribute_uuid(threat_type, r.domain, namespace),
            "value": r.domain,
        }
        # MISP understands first_seen/last_seen on attributes; the feed gives
        # them to us, so pass them through rather than discarding evidence.
        if getattr(r, "first_seen", ""):
            attr["first_seen"] = r.first_seen
        if getattr(r, "last_seen", ""):
            attr["last_seen"] = r.last_seen
        attributes.append(attr)

    label = threat_type.capitalize()
    return {
        "Event": {
            "analysis": str(analysis),
            "date": feed_date.isoformat(),
            "extends_uuid": "",
            "info": (f"{info_prefix}: {label} domains - {feed_date.isoformat()} "
                     f"({len(records)} domains)"),
            "protected": False,
            "publish_timestamp": ts,
            "published": published,
            "threat_level_id": str(threat_level_id),
            "timestamp": ts,
            "uuid": ev_uuid,
            "Orgc": {"name": org_name, "uuid": org_uuid(org_name, namespace)},
            "Tag": _tag_entries(list(tags or []) +
                                [f'whoisfreaks:threat="{threat_type}"']),
            "Attribute": attributes,
        }
    }


def write_threat_day(
        threat_type: str,
        feed_date: date,
        records: list[Any],
        *,
        output_dir: str | Path,
        meta_dir: str | Path,
        cfg_kwargs: dict[str, Any],
        force: bool = False,
        file_mode: int = DEFAULT_FILE_MODE,
) -> tuple[bool, str]:
    """Write one threat-feed event plus sidecars. Mirrors write_day()."""
    output_dir, meta_dir = Path(output_dir), Path(meta_dir)
    namespace = cfg_kwargs["namespace"]
    ev_uuid = threat_event_uuid(threat_type, feed_date, namespace)
    digest = content_digest(f"{r.domain}|{r.last_seen}" for r in records)

    key = f"{threat_type}-{feed_date.isoformat()}"
    meta_path = meta_dir / f"{key}.meta.json"
    hashes_path = meta_dir / f"{key}.hashes"
    event_file = output_dir / f"{ev_uuid}.json"

    previous = None
    if meta_path.is_file():
        try:
            previous = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = None

    unchanged = bool(previous) and previous.get("content_digest") == digest
    if unchanged and not force and event_file.is_file():
        _ensure_mode(event_file, file_mode)
        _ensure_mode(hashes_path, file_mode)
        _ensure_mode(meta_path, file_mode)
        return False, ev_uuid

    if unchanged and previous:
        timestamp = int(previous["timestamp"])
    elif previous is None:
        timestamp = _midnight(feed_date)
    else:
        timestamp = int(datetime.now(timezone.utc).timestamp())

    event = build_threat_event(threat_type, feed_date, records,
                               timestamp=timestamp, **cfg_kwargs)
    _atomic_write_json(event_file, event, file_mode)
    _write_hashes(hashes_path, [r.domain for r in records], ev_uuid, file_mode)
    _atomic_write_json(meta_path, {
        "threat_type": threat_type,
        "feed_date": feed_date.isoformat(),
        "event_uuid": ev_uuid,
        "content_digest": digest,
        "domain_count": len(records),
        "timestamp": timestamp,
        "manifest": manifest_entry(event),
    }, file_mode)

    log.info("wrote %s %s: %d domains", threat_type, feed_date, len(records))
    return True, ev_uuid


def rebuild_threat_manifest(
        output_dir: str | Path,
        meta_dir: str | Path,
        keys: list[str],
        file_mode: int = DEFAULT_FILE_MODE,
) -> tuple[int, int]:
    """Assemble manifest.json and hashes.csv for the threat feed directory."""
    output_dir, meta_dir = Path(output_dir), Path(meta_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {}
    sources: list[Path] = []
    events = 0
    for key in sorted(keys):
        mp = meta_dir / f"{key}.meta.json"
        if not mp.is_file():
            continue
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifest.update(meta.get("manifest", {}))
        sources.append(meta_dir / f"{key}.hashes")
        events += 1
    _atomic_write_json(output_dir / MANIFEST_NAME, manifest, file_mode)
    lines = _concat_hashes(output_dir / HASHES_NAME, sources, file_mode)
    log.info("threat manifest: %d events, hashes.csv: %d lines", events, lines)
    return events, lines


def manifest_entry(event: dict[str, Any]) -> dict[str, Any]:
    """The manifest fragment for one event, matching MISPEvent.manifest."""
    ev = event["Event"]
    return {
        ev["uuid"]: {
            "Orgc": ev["Orgc"],
            "Tag": ev["Tag"],
            "info": ev["info"],
            "date": ev["date"],
            "analysis": int(ev["analysis"]),
            "threat_level_id": int(ev["threat_level_id"]),
            "timestamp": int(ev["timestamp"]),
        }
    }


def _midnight(feed_date: date) -> int:
    return int(
        datetime(feed_date.year, feed_date.month, feed_date.day, tzinfo=timezone.utc).timestamp()
    )


# --------------------------------------------------------------------------- #
# per-day sidecar state
# --------------------------------------------------------------------------- #


def _write_hashes(
    path: Path, domains: list[str], ev_uuid: str, mode: int = DEFAULT_FILE_MODE
) -> None:
    """
    Write one day's hash lines, streaming.

    Built as a single joined string this allocated tens of megabytes per day for
    no reason. Writing line-by-line into the temp file keeps the peak flat
    regardless of how many domains the day holds.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            for d in domains:
                out.write(f"{hashlib.md5(d.encode('utf-8')).hexdigest()},{ev_uuid}\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _concat_hashes(
    target: Path, sources: list[Path], mode: int = DEFAULT_FILE_MODE
) -> int:
    """
    Concatenate per-day hash files into hashes.csv, streaming.

    Returns the line count. The previous approach read every day's file into a
    list and then joined it, holding roughly two copies of the whole feed in
    memory at once -- about 360 MB for a 7-day gTLD+ccTLD window, which is most
    of why a run peaked near 1 GB. Copying in fixed-size chunks keeps the peak
    independent of window width, which matters because the 30-day window this
    project recommends is four times larger again.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    lines = 0
    try:
        with os.fdopen(fd, "wb") as out:
            for src in sources:
                if not src.is_file():
                    continue
                with src.open("rb") as fh:
                    while True:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        lines += chunk.count(b"\n")
                        out.write(chunk)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return lines


def _meta_path(meta_dir: Path, feed_date: date) -> Path:
    return meta_dir / f"{feed_date.isoformat()}.meta.json"


def _hashes_path(meta_dir: Path, feed_date: date) -> Path:
    return meta_dir / f"{feed_date.isoformat()}.hashes"


def load_meta(meta_dir: str | Path, feed_date: date) -> dict[str, Any] | None:
    path = _meta_path(Path(meta_dir), feed_date)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        log.warning("meta for %s is unreadable; will regenerate", feed_date)
        return None


def write_day(
    feed_date: date,
    domains: list[str],
    *,
    output_dir: str | Path,
    meta_dir: str | Path,
    cfg_kwargs: dict[str, Any],
    force: bool = False,
    file_mode: int = DEFAULT_FILE_MODE,
) -> tuple[bool, str]:
    """
    Write one day's event file plus its sidecar metadata.

    Returns (changed, event_uuid). changed=False means the day's domain set is
    byte-identical to what's already on disk, so nothing was rewritten and the
    event timestamp was left alone -- which is what stops MISP from re-pulling
    an unchanged 200k-attribute event every night.
    """
    output_dir = Path(output_dir)
    meta_dir = Path(meta_dir)
    namespace = cfg_kwargs["namespace"]
    ev_uuid = event_uuid(feed_date, namespace)
    digest = content_digest(domains)

    previous = load_meta(meta_dir, feed_date)
    event_file = output_dir / f"{ev_uuid}.json"

    unchanged = bool(previous) and previous.get("content_digest") == digest

    if unchanged and not force and event_file.is_file():
        # Content is identical, so don't rewrite 60 MB of JSON. Do still check
        # the mode: if anything outside this tool has tightened it, the only
        # code path that sets the mode is the one we're skipping, so a wrong
        # mode would persist indefinitely and MISP would stop reading the feed.
        _ensure_mode(event_file, file_mode)
        _ensure_mode(_hashes_path(meta_dir, feed_date), file_mode)
        _ensure_mode(_meta_path(meta_dir, feed_date), file_mode)
        log.debug("%s unchanged (%d domains); skipping rewrite", feed_date, len(domains))
        return False, ev_uuid

    # The timestamp tracks the *content*, not the act of writing. A --force
    # rewrite of identical data must keep the old stamp, otherwise MISP sees a
    # newer version of every attribute and re-ingests the entire window.
    #
    # First write of a historical day uses that day's midnight UTC rather than
    # now(), so a fresh backfill lands with sensible, correctly ordered
    # timestamps instead of 30 days all stamped within the same minute.
    if unchanged and previous:
        timestamp = int(previous["timestamp"])
    elif previous is None:
        timestamp = _midnight(feed_date)
    else:
        timestamp = int(datetime.now(timezone.utc).timestamp())

    event = build_event(feed_date, domains, timestamp=timestamp, **cfg_kwargs)
    _atomic_write_json(event_file, event, file_mode)

    _write_hashes(_hashes_path(meta_dir, feed_date), domains, ev_uuid, file_mode)

    _atomic_write_json(
        _meta_path(meta_dir, feed_date),  # sidecar; mode matches for consistency
        {
            "feed_date": feed_date.isoformat(),
            "event_uuid": ev_uuid,
            "content_digest": digest,
            "domain_count": len(domains),
            "timestamp": timestamp,
            "manifest": manifest_entry(event),
        },
    )

    log.info(
        "wrote %s: %d domains -> %s", feed_date, len(domains), event_file.name
    )
    return True, ev_uuid


# --------------------------------------------------------------------------- #
# feed-level assembly
# --------------------------------------------------------------------------- #


def rebuild_manifest_and_hashes(
    output_dir: str | Path,
    meta_dir: str | Path,
    window: list[date],
    file_mode: int = DEFAULT_FILE_MODE,
) -> tuple[int, int]:
    """
    Rebuild manifest.json and hashes.csv from the per-day sidecars.

    Deliberately not PyMISP's feed_meta_generator(): that reloads and re-hashes
    every event JSON in the directory on every call, which for a 30-day window
    of 200k-attribute events means re-parsing ~1.3 GB of JSON nightly. Reading
    the small sidecars instead is the same output for a fraction of the work,
    and tests/test_feed_format.py asserts the two agree byte for byte.
    """
    output_dir = Path(output_dir)
    meta_dir = Path(meta_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {}
    sources: list[Path] = []
    events = 0

    for feed_date in sorted(window):
        meta = load_meta(meta_dir, feed_date)
        if not meta:
            continue
        manifest.update(meta.get("manifest", {}))
        sources.append(_hashes_path(meta_dir, feed_date))
        events += 1

    _atomic_write_json(output_dir / MANIFEST_NAME, manifest, file_mode)
    hash_lines = _concat_hashes(output_dir / HASHES_NAME, sources, file_mode)

    _ensure_mode(output_dir / MANIFEST_NAME, file_mode)
    _ensure_mode(output_dir / HASHES_NAME, file_mode)
    log.info("manifest: %d events, hashes.csv: %d lines", events, hash_lines)
    return events, hash_lines


def prune(
    output_dir: str | Path,
    meta_dir: str | Path,
    window: list[date],
    namespace: str,
) -> list[Path]:
    """
    Remove event files and sidecars for days outside the retention window.

    This rolls the window *on disk and in the cache*. It does NOT retract data
    from MISP in fetch mode: feed ingestion is additive, and an event already
    written to MISP stays there after it leaves the manifest. Verified on a live
    instance -- 7 events in MISP against 2 on disk. Cache mode does roll, because
    the cache is rebuilt from hashes.csv. See the Retention section of README.md.

    Only files whose names match a UUID we would have
    generated ourselves are touched -- anything else in the directory is left
    alone rather than assumed to be ours.
    """
    output_dir = Path(output_dir)
    meta_dir = Path(meta_dir)
    keep_uuids = {event_uuid(d, namespace) for d in window}
    keep_dates = {d.isoformat() for d in window}
    removed: list[Path] = []

    if output_dir.is_dir():
        for entry in output_dir.glob("*.json"):
            if entry.name == MANIFEST_NAME:
                continue
            stem = entry.stem
            if stem in keep_uuids:
                continue
            try:
                uuid.UUID(stem)
            except ValueError:
                log.debug("leaving unrecognised file %s alone", entry.name)
                continue
            entry.unlink(missing_ok=True)
            removed.append(entry)

    if meta_dir.is_dir():
        for entry in list(meta_dir.glob("*.meta.json")) + list(meta_dir.glob("*.hashes")):
            day = entry.name.split(".")[0]
            if day not in keep_dates:
                entry.unlink(missing_ok=True)
                removed.append(entry)

    if removed:
        log.info("pruned %d file(s) outside the %d-day window", len(removed), len(window))
    return removed