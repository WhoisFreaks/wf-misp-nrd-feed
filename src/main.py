#!/usr/bin/env python3
"""
wf-misp-nrd-feed -- publish the WhoisFreaks NRD feed as a MISP feed.

Normal daily run (fetches yesterday only, everything else is cached):

    misp-nrd-feed

First run / after a gap -- fill the whole retention window:

    misp-nrd-feed --backfill

See what would happen without writing or spending credits:

    misp-nrd-feed --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import date
from pathlib import Path

try:  # installed as a package
    from src import cache_manager as cache
    from src import config as config_mod
    from src import feed_builder as builder
    from src import nrd_fetcher as fetcher
except ImportError:  # run from a checkout
    import cache_manager as cache  # type: ignore[no-redef]
    import config as config_mod  # type: ignore[no-redef]
    import feed_builder as builder  # type: ignore[no-redef]
    import nrd_fetcher as fetcher  # type: ignore[no-redef]

log = logging.getLogger("misp-nrd-feed")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _check_writable(paths: list[Path]) -> None:
    """
    Fail early and legibly rather than with a PermissionError traceback
    halfway through a 200k-attribute write.
    """
    problems: list[str] = []
    for path in paths:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".wf-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            problems.append(f"  {path}: {exc.strerror or exc}")
    if problems:
        raise SystemExit(
            "Cannot write to the directories this needs:\n"
            + "\n".join(problems)
            + "\n\nFix with either:\n"
            "  sudo mkdir -p <dir> && sudo chown $USER <dir>\n"
            "or point them somewhere you own:\n"
            "  NRD_CACHE_DIR=~/.cache/misp-nrd MISP_FEED_DIR=~/misp-feed misp-nrd-feed"
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="misp-nrd-feed",
        description="Publish the WhoisFreaks NRD feed as a MISP feed directory.",
    )
    p.add_argument("-c", "--config", help="path to config.ini")
    p.add_argument("--days", type=int, help="retention window in days")
    p.add_argument("--feeds", help="comma-separated TLD sets (gtld,cctld)")
    p.add_argument("--output-dir", help="MISP feed directory to write")
    p.add_argument("--cache-dir", help="per-day cache directory")
    p.add_argument(
        "--backfill",
        action="store_true",
        help="fetch every missing day in the window, not just the newest",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="rewrite event files even when the day's domain set is unchanged",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be fetched and written; no network, no writes",
    )
    p.add_argument("--log-level", help="DEBUG, INFO, WARNING, ERROR")
    return p.parse_args(argv)


def apply_overrides(cfg: config_mod.Config, args: argparse.Namespace) -> config_mod.Config:
    if args.days is not None:
        cfg.days = args.days
    if args.feeds:
        cfg.feeds = [f.strip().lower() for f in args.feeds.split(",") if f.strip()]
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.cache_dir:
        cfg.cache_dir = args.cache_dir
        cfg.meta_dir = str(Path(args.cache_dir) / "feedmeta")
    if args.log_level:
        cfg.log_level = args.log_level.upper()
    return cfg


def sync_cache(cfg: config_mod.Config, backfill: bool, anchor: date) -> int:
    """
    Bring the cache up to date. Returns the number of days fetched.

    On a healthy daily schedule this fetches exactly one date, which is
    len(cfg.feeds) API calls. Missing days are treated as non-fatal: a feed
    that hasn't published yet should not abort the run and leave MISP
    pointing at a half-built manifest.
    """
    tld_sets = tuple(cfg.feeds)
    missing = cache.dates_needing_backfill(cfg.cache_dir, cfg.days, tld_sets, anchor)

    if not missing:
        log.info("cache is complete for the %d-day window; nothing to fetch", cfg.days)
        return 0

    if backfill:
        targets = missing
        log.info("backfilling %d day(s)", len(targets))
    else:
        targets = [anchor] if anchor in missing else []
        if len(missing) > 1:
            log.warning(
                "%d day(s) in the window are missing but only %s will be fetched. "
                "Run with --backfill to fill the gap.",
                len(missing),
                anchor,
            )

    fetched = 0
    for feed_date in targets:
        for tld_set in tld_sets:
            if cache.cache_path(cfg.cache_dir, feed_date, tld_set).is_file():
                continue
            try:
                domains = fetcher.fetch_day(
                    tld_set,
                    feed_date,
                    cfg.api_key,
                    cfg.base_url,
                    timeout=cfg.request_timeout,
                    max_retries=cfg.max_retries,
                )
            except fetcher.NoDataForDate as exc:
                log.warning("skipping: %s", exc)
                continue
            except fetcher.FetchError as exc:
                log.error("%s", exc)
                continue
            cache.save(cfg.cache_dir, feed_date, tld_set, domains)
        fetched += 1
    return fetched


def _warn_if_unreadable(manifest: Path) -> None:
    """
    MISP reads the feed as its own web user. If the files are not
    world-readable it will add the feed, fetch without error, and report zero
    events -- with nothing in its logs to explain why. Catch that here, where
    we can still say something useful.
    """
    import stat

    try:
        mode = manifest.stat().st_mode
    except OSError:
        return
    if not mode & stat.S_IROTH:
        log.warning(
            "%s is mode %04o -- not readable by other users. MISP runs as its "
            "own web user (www-data / apache / uid 33 in a container) and will "
            "silently ingest 0 events. Fix with:  chmod -R o+r %s",
            manifest.name,
            mode & 0o777,
            manifest.parent,
        )


def run(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    cfg.validate()
    anchor = cache.anchor_date()
    window = cache.window_dates(cfg.days, anchor)
    tld_sets = tuple(cfg.feeds)

    log.info(
        "=== wf-misp-nrd-feed starting === feeds=%s window=%dd (%s..%s) out=%s",
        ",".join(cfg.feeds),
        cfg.days,
        window[-1],
        window[0],
        cfg.output_dir,
    )

    if args.dry_run:
        missing = cache.dates_needing_backfill(cfg.cache_dir, cfg.days, tld_sets, anchor)
        cached = sorted(cache.cached_dates(cfg.cache_dir), reverse=True)
        log.info("cached days: %d %s", len(cached), [d.isoformat() for d in cached[:5]])
        log.info(
            "would fetch %d day(s): %s",
            len(missing) if args.backfill else min(1, len(missing)),
            [d.isoformat() for d in (missing if args.backfill else missing[:1])],
        )
        log.info("would write %d event file(s) to %s", len(window), cfg.output_dir)
        log.info("dry run complete; nothing fetched or written")
        return 0

    _check_writable([Path(cfg.cache_dir), Path(cfg.meta_dir), Path(cfg.output_dir)])

    sync_cache(cfg, args.backfill, anchor)

    # Cached days are expensive to replace -- each one costs API calls -- so a
    # temporary --days override must not delete them. Narrowing the window for a
    # single run (to test, or to produce a smaller feed once) would otherwise
    # silently destroy cache that the configured window still needs, and the
    # next scheduled run would quietly re-download it.
    if args.days is not None:
        log.info(
            "--days %d given on the command line; leaving the cache alone. "
            "The feed output covers %d day(s); cached days outside it are kept.",
            cfg.days, cfg.days,
        )
    else:
        cache.expire_old_cache(cfg.cache_dir, cfg.days, anchor)

    cfg_kwargs = {
        "namespace": cfg.uuid_namespace,
        "org_name": cfg.org_name,
        "info_prefix": cfg.event_info_prefix,
        "threat_level_id": cfg.threat_level_id,
        "analysis": cfg.analysis,
        "published": cfg.published,
        "to_ids": cfg.to_ids,
        "disable_correlation": cfg.disable_correlation,
        "category": cfg.category,
        "tags": cfg.tags,
    }

    total_domains = 0
    changed_days = 0
    empty_days = 0

    for feed_date in window:
        domains = cache.merge_day(cfg.cache_dir, feed_date, tld_sets)
        if not domains:
            empty_days += 1
            continue
        changed, _ = builder.write_day(
            feed_date,
            domains,
            output_dir=cfg.output_dir,
            meta_dir=cfg.meta_dir,
            cfg_kwargs=cfg_kwargs,
            force=args.force,
            file_mode=cfg.file_mode,
        )
        total_domains += len(domains)
        changed_days += int(changed)

    builder.prune(cfg.output_dir, cfg.meta_dir, window, cfg.uuid_namespace)
    events, _ = builder.rebuild_manifest_and_hashes(
        cfg.output_dir, cfg.meta_dir, window, cfg.file_mode
    )

    log.info(
        "done: %d events, %d domains, %d day(s) changed, %d day(s) with no data",
        events,
        total_domains,
        changed_days,
        empty_days,
    )
    if events == 0:
        log.error(
            "manifest is empty -- MISP will pull nothing. Run with --backfill, "
            "or --dry-run to see what the cache actually contains."
        )
        return 1
    _warn_if_unreadable(Path(cfg.output_dir) / builder.MANIFEST_NAME)
    # MISP wants the containing DIRECTORY for a MISP-format feed, not the
    # manifest file -- it appends manifest.json itself. Pointing at the file
    # is rejected with "please specify the containing directory".
    log.info("point MISP at this directory (not manifest.json): %s", cfg.output_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = apply_overrides(config_mod.load(args.config), args)
    _setup_logging(cfg.log_level)
    try:
        return run(cfg, args)
    except config_mod.ConfigError as exc:
        log.error("configuration problem: %s", exc)
        return 2
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())