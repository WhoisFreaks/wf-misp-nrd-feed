"""
Tests for wf-misp-nrd-feed.

The load-bearing test here is test_matches_pymisp_feed_generator: we emit the
MISP feed wire format by hand for speed, so something has to guarantee we
haven't drifted from what MISP actually expects. That test builds the same
event through PyMISP's own MISPEvent.to_feed()/manifest/attributes_hashes and
asserts the outputs agree.
"""

from __future__ import annotations

import gzip
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import cache_manager as cache
from src import config as config_mod
from src import feed_builder as builder
from src import nrd_fetcher as fetcher

NS = "b0f1e2c3-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
DAY = date(2026, 7, 27)
DOMAINS = ["0--0.jp", "aaa-example.com", "zzz-example.net"]

CFG_KWARGS = {
    "namespace": NS,
    "org_name": "WhoisFreaks",
    "info_prefix": "WhoisFreaks NRD",
    "threat_level_id": 4,
    "analysis": 2,
    "published": True,
    "to_ids": False,
    "disable_correlation": True,
    "category": "Network activity",
    "tags": ["tlp:clear", 'whoisfreaks:feed="nrd"'],
}


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #


def test_anchor_is_yesterday_never_today():
    today = date(2026, 7, 28)
    assert cache.anchor_date(today) == date(2026, 7, 27)


def test_window_starts_at_anchor_and_is_newest_first():
    win = cache.window_dates(7, anchor=DAY)
    assert win[0] == DAY
    assert len(win) == 7
    assert win[-1] == DAY - timedelta(days=6)
    assert win == sorted(win, reverse=True)


def test_save_load_roundtrip(tmp_path):
    cache.save(tmp_path, DAY, "gtld", DOMAINS)
    assert cache.load(tmp_path, DAY, "gtld") == DOMAINS


def test_save_is_gzip(tmp_path):
    p = cache.save(tmp_path, DAY, "gtld", DOMAINS)
    with gzip.open(p, "rt") as fh:
        assert fh.read().splitlines() == DOMAINS


def test_load_missing_returns_empty(tmp_path):
    assert cache.load(tmp_path, DAY, "gtld") == []


def test_corrupt_cache_treated_as_missing(tmp_path):
    p = cache.cache_path(tmp_path, DAY, "gtld")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x1f\x8b not really gzip")
    assert cache.load(tmp_path, DAY, "gtld") == []


def test_backfill_detection_and_partial_tld_set(tmp_path):
    # gtld present, cctld absent -> the day still counts as missing
    cache.save(tmp_path, DAY, "gtld", DOMAINS)
    missing = cache.dates_needing_backfill(tmp_path, 3, ("gtld", "cctld"), anchor=DAY)
    assert DAY in missing
    cache.save(tmp_path, DAY, "cctld", ["extra.io"])
    missing = cache.dates_needing_backfill(tmp_path, 3, ("gtld", "cctld"), anchor=DAY)
    assert DAY not in missing
    assert len(missing) == 2


def test_expire_drops_only_out_of_window(tmp_path):
    inside = DAY
    outside = DAY - timedelta(days=10)
    cache.save(tmp_path, inside, "gtld", ["a.com"])
    cache.save(tmp_path, outside, "gtld", ["b.com"])
    removed = cache.expire_old_cache(tmp_path, 7, anchor=DAY)
    assert len(removed) == 1
    assert cache.load(tmp_path, inside, "gtld") == ["a.com"]
    assert cache.load(tmp_path, outside, "gtld") == []


def test_merge_day_dedups_across_tld_sets(tmp_path):
    cache.save(tmp_path, DAY, "gtld", ["dup.com", "a.com"])
    cache.save(tmp_path, DAY, "cctld", ["dup.com", "b.jp"])
    merged = cache.merge_day(tmp_path, DAY, ("gtld", "cctld"))
    assert merged == ["a.com", "b.jp", "dup.com"]


# --------------------------------------------------------------------------- #
# fetcher parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body,expected",
    [
        ("a.com\nb.net\n", ["a.com", "b.net"]),
        ("\ufeffa.com\n\nb.net\n", ["a.com", "b.net"]),
        ("# comment\na.com\n", ["a.com"]),
        ("domain\na.com\n", ["a.com"]),  # header row dropped
        ('"a.com",2026-07-27\nb.net,2026-07-27\n', ["a.com", "b.net"]),
        ("A.COM\n", ["a.com"]),  # lowercased
        ("a.com.\n", ["a.com"]),  # trailing dot stripped
        ("notadomain\n", []),
        ("", []),
    ],
)
def test_extract_domains(body, expected):
    assert fetcher.extract_domains(body) == expected


def test_extract_domains_survives_binary_garbage():
    body = b"\x00\x01\x02broken\xff".decode("utf-8", errors="replace")
    assert fetcher.extract_domains(body) == []


# --------------------------------------------------------------------------- #
# deterministic identity
# --------------------------------------------------------------------------- #


def test_event_uuid_is_deterministic_and_date_scoped():
    assert builder.event_uuid(DAY, NS) == builder.event_uuid(DAY, NS)
    assert builder.event_uuid(DAY, NS) != builder.event_uuid(DAY + timedelta(1), NS)


def test_attribute_uuid_scoped_by_date_and_domain():
    a = builder.attribute_uuid(DAY, "x.com", NS)
    assert a == builder.attribute_uuid(DAY, "x.com", NS)
    assert a != builder.attribute_uuid(DAY + timedelta(1), "x.com", NS)
    assert a != builder.attribute_uuid(DAY, "y.com", NS)


def test_bad_namespace_is_rejected_clearly():
    with pytest.raises(ValueError, match="not a valid UUID"):
        builder.event_uuid(DAY, "not-a-uuid")


# --------------------------------------------------------------------------- #
# THE format-equivalence test
# --------------------------------------------------------------------------- #


def test_matches_pymisp_feed_generator():
    """Our hand-built event must equal what PyMISP would produce."""
    pytest.importorskip("pymisp")
    from pymisp import MISPAttribute, MISPEvent, MISPOrganisation

    ours = builder.build_event(DAY, DOMAINS, timestamp=1785255143, **CFG_KWARGS)

    ev = MISPEvent()
    ev.uuid = builder.event_uuid(DAY, NS)
    ev.info = ours["Event"]["info"]
    ev.date = DAY
    ev.analysis = CFG_KWARGS["analysis"]
    ev.threat_level_id = CFG_KWARGS["threat_level_id"]
    ev.published = True
    ev.timestamp = 1785255143
    ev.publish_timestamp = 1785255143

    org = MISPOrganisation()
    org.name = CFG_KWARGS["org_name"]
    org.uuid = builder.org_uuid(CFG_KWARGS["org_name"], NS)
    ev.Orgc = org

    for tag in CFG_KWARGS["tags"]:
        ev.add_tag(tag)

    for domain in DOMAINS:
        attr = MISPAttribute()
        attr.type = "domain"
        attr.value = domain
        attr.category = CFG_KWARGS["category"]
        attr.to_ids = False
        attr.disable_correlation = True
        attr.uuid = builder.attribute_uuid(DAY, domain, NS)
        attr.comment = ours["Event"]["Attribute"][0]["comment"]
        ev.add_attribute(**attr.to_dict())
        # PyMISP re-stamps attribute timestamps with now() inside
        # add_attribute, so pin it afterwards. We set ours explicitly and
        # deterministically instead -- see test_unchanged_day_keeps_timestamps.
        ev.attributes[-1].timestamp = 1785255143

    theirs = ev.to_feed(with_meta=False)

    # Event-level scalars
    for key in (
        "analysis",
        "date",
        "info",
        "published",
        "threat_level_id",
        "timestamp",
        "uuid",
        "Orgc",
    ):
        assert ours["Event"][key] == theirs["Event"][key], f"mismatch on {key}"

    assert ours["Event"]["Tag"] == theirs["Event"]["Tag"]

    # Attributes: same set of keys, same values
    for mine, mispd in zip(ours["Event"]["Attribute"], theirs["Event"]["Attribute"]):
        assert set(mine) == set(mispd), f"attribute key drift: {set(mine) ^ set(mispd)}"
        assert mine == mispd

    # Manifest fragment
    assert builder.manifest_entry(ours) == ev.manifest

    # hashes.csv values
    ours_hashes = [
        __import__("hashlib").md5(d.encode()).hexdigest() for d in DOMAINS
    ]
    assert ours_hashes == ev.attributes_hashes("md5")


def test_flags_survive_into_output():
    ev = builder.build_event(DAY, DOMAINS, **CFG_KWARGS)["Event"]
    for attr in ev["Attribute"]:
        assert attr["to_ids"] is False
        assert attr["disable_correlation"] is True
        assert attr["type"] == "domain"


# --------------------------------------------------------------------------- #
# write / manifest / prune
# --------------------------------------------------------------------------- #


def _write(tmp_path, feed_date, domains, force=False):
    return builder.write_day(
        feed_date,
        domains,
        output_dir=tmp_path / "feed",
        meta_dir=tmp_path / "meta",
        cfg_kwargs=CFG_KWARGS,
        force=force,
    )


def test_write_day_creates_expected_files(tmp_path):
    changed, ev_uuid = _write(tmp_path, DAY, DOMAINS)
    assert changed is True
    assert (tmp_path / "feed" / f"{ev_uuid}.json").is_file()
    assert (tmp_path / "meta" / f"{DAY.isoformat()}.hashes").is_file()
    assert (tmp_path / "meta" / f"{DAY.isoformat()}.meta.json").is_file()


def test_rewrite_is_skipped_when_unchanged(tmp_path):
    assert _write(tmp_path, DAY, DOMAINS)[0] is True
    assert _write(tmp_path, DAY, DOMAINS)[0] is False, "unchanged day should not rewrite"
    assert _write(tmp_path, DAY, DOMAINS, force=True)[0] is True


def test_changed_domain_set_bumps_timestamp(tmp_path):
    _write(tmp_path, DAY, DOMAINS)
    first = builder.load_meta(tmp_path / "meta", DAY)["timestamp"]
    changed, _ = _write(tmp_path, DAY, DOMAINS + ["new-arrival.com"])
    second = builder.load_meta(tmp_path / "meta", DAY)["timestamp"]
    assert changed is True
    assert second > first, "MISP needs a newer timestamp to re-pull the event"


def test_manifest_and_hashes_assembly(tmp_path):
    window = cache.window_dates(3, anchor=DAY)
    for i, d in enumerate(window):
        _write(tmp_path, d, [f"day{i}-a.com", f"day{i}-b.com"])
    events, lines = builder.rebuild_manifest_and_hashes(
        tmp_path / "feed", tmp_path / "meta", window
    )
    assert events == 3
    assert lines == 6

    manifest = json.loads((tmp_path / "feed" / "manifest.json").read_text())
    assert len(manifest) == 3
    for d in window:
        assert builder.event_uuid(d, NS) in manifest

    hashes = (tmp_path / "feed" / "hashes.csv").read_text().strip().splitlines()
    assert len(hashes) == 6
    for line in hashes:
        md5, _, ev_uuid = line.partition(",")
        assert len(md5) == 32
        assert ev_uuid in manifest


def test_manifest_matches_pymisp_meta_generator(tmp_path):
    """Our incremental manifest/hashes must equal feed_meta_generator's."""
    pytest.importorskip("pymisp")
    from pymisp.tools import feed_meta_generator

    window = cache.window_dates(2, anchor=DAY)
    for i, d in enumerate(window):
        _write(tmp_path, d, [f"x{i}.com", f"y{i}.net"])
    builder.rebuild_manifest_and_hashes(tmp_path / "feed", tmp_path / "meta", window)

    ours_manifest = json.loads((tmp_path / "feed" / "manifest.json").read_text())
    ours_hashes = sorted(
        (tmp_path / "feed" / "hashes.csv").read_text().strip().splitlines()
    )

    # Let PyMISP regenerate them from the event files alone.
    feed_meta_generator(tmp_path / "feed")
    theirs_manifest = json.loads((tmp_path / "feed" / "manifest.json").read_text())
    theirs_hashes = sorted(
        (tmp_path / "feed" / "hashes.csv").read_text().strip().splitlines()
    )

    assert ours_manifest == theirs_manifest
    assert ours_hashes == theirs_hashes


def test_prune_removes_out_of_window_events(tmp_path):
    old = DAY - timedelta(days=30)
    _write(tmp_path, DAY, DOMAINS)
    _write(tmp_path, old, ["ancient.com"])
    window = cache.window_dates(7, anchor=DAY)

    removed = builder.prune(tmp_path / "feed", tmp_path / "meta", window, NS)
    assert removed, "old event should have been pruned"
    assert (tmp_path / "feed" / f"{builder.event_uuid(DAY, NS)}.json").is_file()
    assert not (tmp_path / "feed" / f"{builder.event_uuid(old, NS)}.json").is_file()


def test_prune_leaves_foreign_files_alone(tmp_path):
    feed = tmp_path / "feed"
    feed.mkdir(parents=True)
    stranger = feed / "someone-elses-notes.json"
    stranger.write_text("{}")
    _write(tmp_path, DAY, DOMAINS)
    builder.prune(feed, tmp_path / "meta", cache.window_dates(7, anchor=DAY), NS)
    assert stranger.is_file(), "must not delete files we did not create"


def test_prune_keeps_manifest(tmp_path):
    window = cache.window_dates(2, anchor=DAY)
    _write(tmp_path, DAY, DOMAINS)
    builder.rebuild_manifest_and_hashes(tmp_path / "feed", tmp_path / "meta", window)
    builder.prune(tmp_path / "feed", tmp_path / "meta", window, NS)
    assert (tmp_path / "feed" / "manifest.json").is_file()


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #


def test_validate_requires_api_key():
    cfg = config_mod.Config(api_key="")
    with pytest.raises(config_mod.ConfigError, match="No API key"):
        cfg.validate()


def test_validate_rejects_unknown_feed():
    cfg = config_mod.Config(api_key="k", feeds=["gtld", "nonsense"])
    with pytest.raises(config_mod.ConfigError, match="Unknown feed"):
        cfg.validate()


def test_validate_guards_absurd_window():
    cfg = config_mod.Config(api_key="k", days=365)
    with pytest.raises(config_mod.ConfigError, match="guard rail"):
        cfg.validate()


def test_validate_rejects_bad_category():
    cfg = config_mod.Config(api_key="k", category="Payload delivery")
    with pytest.raises(config_mod.ConfigError, match="not a MISP category"):
        cfg.validate()


def test_meta_dir_derived_from_cache_dir():
    cfg = config_mod.Config(cache_dir="/tmp/x")
    assert cfg.meta_dir == "/tmp/x/feedmeta"


def test_ini_and_env_layering(tmp_path, monkeypatch):
    ini = tmp_path / "config.ini"
    ini.write_text(
        "[whoisfreaks]\napi_key = from_ini\nfeeds = gtld\n"
        "[retention]\ndays = 14\n"
        "[misp]\ndisable_correlation = false\n"
    )
    monkeypatch.delenv("NRD_API_KEY", raising=False)
    cfg = config_mod.load(str(ini))
    assert cfg.api_key == "from_ini"
    assert cfg.feeds == ["gtld"]
    assert cfg.days == 14
    assert cfg.disable_correlation is False

    monkeypatch.setenv("NRD_API_KEY", "from_env")
    monkeypatch.setenv("NRD_RETENTION_DAYS", "30")
    cfg = config_mod.load(str(ini))
    assert cfg.api_key == "from_env", "env must win over ini"
    assert cfg.days == 30


def test_unchanged_day_keeps_timestamps(tmp_path):
    """
    Attribute timestamps must be stable across runs for an unchanged day.

    PyMISP stamps attributes with now() on every add; we derive them from the
    event instead. Without this, every nightly run would produce a "new"
    version of every attribute and MISP would re-ingest the whole window.
    """
    _write(tmp_path, DAY, DOMAINS)
    ev_uuid = builder.event_uuid(DAY, NS)
    path = tmp_path / "feed" / f"{ev_uuid}.json"
    first = json.loads(path.read_text())
    _write(tmp_path, DAY, DOMAINS, force=True)
    second = json.loads(path.read_text())
    assert [a["timestamp"] for a in first["Event"]["Attribute"]] == [
        a["timestamp"] for a in second["Event"]["Attribute"]
    ]
    assert first == second, "forced rewrite of identical data must be byte-stable"


def test_feed_files_are_world_readable(tmp_path):
    """
    MISP reads this directory as its own web user (www-data / apache / uid 33
    in a container), not as the user that wrote it. tempfile.mkstemp hardcodes
    0600 and os.replace preserves it, so without an explicit chmod the feed
    silently ingests nothing.
    """
    import os
    import stat

    _write(tmp_path, DAY, DOMAINS)
    builder.rebuild_manifest_and_hashes(
        tmp_path / "feed", tmp_path / "meta", [DAY]
    )
    old = os.umask(0o022)
    try:
        _write(tmp_path, DAY, DOMAINS + ["another.com"])
        builder.rebuild_manifest_and_hashes(
            tmp_path / "feed", tmp_path / "meta", [DAY]
        )
        for name in ("manifest.json", "hashes.csv", f"{builder.event_uuid(DAY, NS)}.json"):
            mode = (tmp_path / "feed" / name).stat().st_mode
            assert mode & stat.S_IROTH, f"{name} is not world-readable (mode {oct(mode & 0o777)})"
    finally:
        os.umask(old)


def test_mode_ignores_restrictive_umask(tmp_path):
    """
    A hardened host with umask 077 must still produce a readable feed.

    Deriving the mode from umask would yield 0600 on such a host -- a feed MISP
    cannot read, failing silently. The mode is explicit for that reason.
    """
    import os
    import stat

    old = os.umask(0o077)
    try:
        _write(tmp_path, DAY, DOMAINS)
        mode = (tmp_path / "feed" / f"{builder.event_uuid(DAY, NS)}.json").stat().st_mode
        assert mode & stat.S_IROTH, (
            f"umask 077 produced mode {oct(mode & 0o777)}; the feed must stay "
            "readable by MISP's web user regardless of umask"
        )
    finally:
        os.umask(old)


def test_explicit_file_mode_is_honoured(tmp_path):
    """Operators can override, e.g. to 0640 for a group-based scheme."""
    import stat

    builder.write_day(
        DAY, DOMAINS,
        output_dir=tmp_path / "feed", meta_dir=tmp_path / "meta",
        cfg_kwargs=CFG_KWARGS, file_mode=0o640,
    )
    mode = (tmp_path / "feed" / f"{builder.event_uuid(DAY, NS)}.json").stat().st_mode
    assert mode & stat.S_IRGRP
    assert not mode & stat.S_IROTH


def test_validate_rejects_nonsense_file_mode():
    cfg = config_mod.Config(api_key="k", file_mode=0o200)
    with pytest.raises(config_mod.ConfigError, match="file_mode"):
        cfg.validate()


def test_unreadable_config_raises_clear_error(tmp_path, monkeypatch):
    """
    configparser.read() silently swallows PermissionError, which turned an
    unreadable config into a misleading "No API key". Regression test: an
    unreadable file must say so, and name the fix.
    """
    ini = tmp_path / "config.ini"
    ini.write_text("[whoisfreaks]\napi_key = SECRET\n")

    real_open = Path.open

    def deny(self, *a, **kw):
        if self == ini:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", deny)
    monkeypatch.delenv("NRD_API_KEY", raising=False)

    with pytest.raises(config_mod.ConfigError) as exc:
        config_mod.load(str(ini))
    message = str(exc.value)
    assert "cannot read it" in message
    assert "chmod 640" in message, "the error must name the actual fix"
    assert "No API key" not in message, "must not mask the real cause"


def test_malformed_config_raises_clear_error(tmp_path, monkeypatch):
    """A missing section header must be reported, not raise a raw traceback."""
    ini = tmp_path / "config.ini"
    ini.write_text("api_key = no_section_header\n")
    monkeypatch.delenv("NRD_API_KEY", raising=False)
    with pytest.raises(config_mod.ConfigError, match="not valid ini"):
        config_mod.load(str(ini))


def test_readable_config_still_loads(tmp_path, monkeypatch):
    ini = tmp_path / "config.ini"
    ini.write_text("[whoisfreaks]\napi_key = SECRET\n")
    monkeypatch.delenv("NRD_API_KEY", raising=False)
    assert config_mod.load(str(ini)).api_key == "SECRET"


def test_unchanged_day_repairs_bad_mode(tmp_path):
    """
    If something outside the tool tightens permissions, a normal run must fix
    them even though the content is unchanged -- otherwise the only code path
    that sets the mode is the one being skipped, and MISP silently stops
    reading the feed.
    """
    import os
    import stat

    _write(tmp_path, DAY, DOMAINS)
    event_file = tmp_path / "feed" / f"{builder.event_uuid(DAY, NS)}.json"

    os.chmod(event_file, 0o600)          # simulate an external chmod
    assert not event_file.stat().st_mode & stat.S_IROTH

    changed, _ = _write(tmp_path, DAY, DOMAINS)
    assert changed is False, "content is unchanged, so no rewrite should happen"
    assert event_file.stat().st_mode & stat.S_IROTH, "mode should have been repaired"
    assert event_file.stat().st_mode & 0o777 == 0o644


def test_mode_repair_does_not_rewrite_content(tmp_path):
    """Repair must be a chmod, not a 60 MB rewrite."""
    import os

    _write(tmp_path, DAY, DOMAINS)
    event_file = tmp_path / "feed" / f"{builder.event_uuid(DAY, NS)}.json"
    before = event_file.read_bytes()
    mtime_before = event_file.stat().st_mtime_ns
    os.chmod(event_file, 0o600)
    _write(tmp_path, DAY, DOMAINS)
    assert event_file.read_bytes() == before
    assert event_file.stat().st_mtime_ns == mtime_before, "file should not be rewritten"


def test_cli_days_override_does_not_expire_cache(tmp_path, monkeypatch):
    """
    A one-off --days override must not delete cached days. Each cached day costs
    API calls to replace, so narrowing the window for a single run must not
    destroy cache the configured window still needs.
    """
    import src.main as main_mod

    cache_dir = tmp_path / "cache"
    for i in range(5):
        cache.save(cache_dir, DAY - timedelta(days=i), "gtld", [f"d{i}.com"])
    assert len(cache.cached_dates(cache_dir)) == 5

    monkeypatch.setattr(main_mod.cache, "anchor_date", lambda today=None: DAY)
    monkeypatch.setattr(
        main_mod.fetcher, "fetch_day", lambda *a, **kw: ["stub.com"]
    )

    cfg = config_mod.Config(
        api_key="k", days=2, feeds=["gtld"],
        cache_dir=str(cache_dir), output_dir=str(tmp_path / "feed"),
        uuid_namespace=NS,
    )
    args = main_mod.parse_args(["--days", "2"])
    main_mod.run(cfg, args)

    assert len(cache.cached_dates(cache_dir)) == 5, (
        "a --days override must leave cached days intact"
    )


def test_configured_window_still_expires_cache(tmp_path, monkeypatch):
    """Without a CLI override, normal rolling expiry must still happen."""
    import src.main as main_mod

    cache_dir = tmp_path / "cache"
    for i in range(5):
        cache.save(cache_dir, DAY - timedelta(days=i), "gtld", [f"d{i}.com"])

    monkeypatch.setattr(main_mod.cache, "anchor_date", lambda today=None: DAY)
    monkeypatch.setattr(
        main_mod.fetcher, "fetch_day", lambda *a, **kw: ["stub.com"]
    )

    cfg = config_mod.Config(
        api_key="k", days=2, feeds=["gtld"],
        cache_dir=str(cache_dir), output_dir=str(tmp_path / "feed"),
        uuid_namespace=NS,
    )
    args = main_mod.parse_args([])          # no --days
    main_mod.run(cfg, args)

    assert len(cache.cached_dates(cache_dir)) == 2, (
        "the configured window should still roll the cache forward"
    )


def test_hashes_concat_matches_per_day_files(tmp_path):
    """Streaming concatenation must produce the same bytes as reading it all in."""
    window = cache.window_dates(3, anchor=DAY)
    for i, d in enumerate(window):
        _write(tmp_path, d, [f"x{i}.com", f"y{i}.net"])
    events, lines = builder.rebuild_manifest_and_hashes(
        tmp_path / "feed", tmp_path / "meta", window
    )
    expected = b"".join(
        (tmp_path / "meta" / f"{d.isoformat()}.hashes").read_bytes()
        for d in sorted(window)
    )
    assert (tmp_path / "feed" / "hashes.csv").read_bytes() == expected
    assert lines == 6
    assert events == 3