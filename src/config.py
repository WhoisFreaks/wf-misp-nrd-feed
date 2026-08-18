"""
Configuration for wf-misp-nrd-feed.

Resolution order (later wins):
    1. built-in defaults
    2. config.ini  (default: /etc/misp-nrd-feed/config.ini)
    3. environment variables / .env
    4. CLI flags (applied by main.py)

Naming is deliberately kept consistent with the sibling integrations
(wf-bind9-nrd-rpz, wf-suricata-nrd-feed) so operators running more than
one of them don't have to learn two vocabularies:

    days        -> retention window, in days
    cache_dir   -> per-day gzip cache of raw feed responses
    feeds       -> which TLD sets to pull ("gtld", "cctld")
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# WhoisFreaks NRD endpoint
#
# This is the file-download service, NOT api.whoisfreaks.com. The path shape
# is /v3.1/download/domainer/{gtld|cctld} and it is called with:
#
#     ?apiKey=<KEY>&date=YYYY-MM-DD&whois=false
#
# whois=false requests the domains-only list, which is all this integration
# needs. Responses are gzipped plain text, one domain per line.
#
# Confirm the base path against your dashboard's API Reference page if your
# subscription tier differs, and override with NRD_BASE_URL if so.
# --------------------------------------------------------------------------
DEFAULT_BASE_URL = "https://files.whoisfreaks.com/v3.1/download/domainer"

DEFAULT_CONFIG_PATH = "/etc/misp-nrd-feed/config.ini"

VALID_FEEDS = ("gtld", "cctld")


class ConfigError(Exception):
    """Raised when configuration is missing or self-contradictory."""


def _default_paths() -> tuple[str, str]:
    """Return (cache_dir, output_dir) appropriate for the platform."""
    if os.name == "nt":
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "misp-nrd-feed"
        return str(base / "cache"), str(base / "feed")
    return "/var/cache/misp-nrd-feed", "/var/lib/misp-nrd-feed/feed"


_CACHE_DEFAULT, _OUTPUT_DEFAULT = _default_paths()


@dataclass
class Config:
    # --- credentials -------------------------------------------------------
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL

    # --- what to fetch -----------------------------------------------------
    feeds: list[str] = field(default_factory=lambda: ["gtld", "cctld"])
    days: int = 7

    # --- where things live -------------------------------------------------
    cache_dir: str = _CACHE_DEFAULT
    output_dir: str = _OUTPUT_DEFAULT
    meta_dir: str = ""  # derived from cache_dir when empty

    # --- MISP feed identity ------------------------------------------------
    org_name: str = "WhoisFreaks"
    # Stable namespace for deterministic event/attribute UUIDs. Changing this
    # makes every previously generated event a *different* event to MISP, so
    # treat it as write-once per deployment.
    uuid_namespace: str = "b0f1e2c3-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
    event_info_prefix: str = "WhoisFreaks NRD"
    threat_level_id: int = 4  # 4 = Undefined. NRD membership is context, not a verdict.
    analysis: int = 2  # 2 = Completed
    published: bool = True

    # --- attribute semantics ----------------------------------------------
    # to_ids=False and disable_correlation=True are the load-bearing defaults.
    # See docs/why-disable-correlation.md before changing either.
    to_ids: bool = False
    disable_correlation: bool = True
    category: str = "Network activity"

    # Mode for files written into the feed directory. MISP reads them as its
    # own web user, so they must be readable by others; 0644 is the default and
    # anything less permissive is almost certainly a mistake.
    file_mode: int = 0o644

    tags: list[str] = field(
        default_factory=lambda: [
            "tlp:clear",
            'whoisfreaks:feed="nrd"',
        ]
    )

    # --- behaviour ---------------------------------------------------------
    log_level: str = "INFO"
    request_timeout: int = 120
    max_retries: int = 3

    # ------------------------------------------------------------------ #

    def __post_init__(self) -> None:
        if not self.meta_dir:
            self.meta_dir = str(Path(self.cache_dir) / "feedmeta")

    def validate(self) -> None:
        if not self.api_key:
            raise ConfigError(
                "No API key. Set api_key in config.ini, or export NRD_API_KEY. "
                "Get one at https://billing.whoisfreaks.com/signup"
            )
        if not self.feeds:
            raise ConfigError("No feeds selected; expected at least one of gtld, cctld.")
        bad = [f for f in self.feeds if f not in VALID_FEEDS]
        if bad:
            raise ConfigError(
                f"Unknown feed(s) {bad!r}; valid values are {list(VALID_FEEDS)}."
            )
        if self.days < 1:
            raise ConfigError(f"days must be >= 1, got {self.days}.")
        if self.days > 90:
            raise ConfigError(
                f"days={self.days} exceeds the 90-day guard rail. A window this "
                "wide means millions of attributes in MISP; if you really want "
                "it, raise the guard in config.py deliberately."
            )
        if not 0o400 <= self.file_mode <= 0o777:
            raise ConfigError(
                f"file_mode={self.file_mode:04o} is out of range; expected an "
                "octal mode between 0400 and 0777."
            )
        if self.category not in (
            "Network activity",
            "External analysis",
            "Other",
        ):
            raise ConfigError(
                f"category={self.category!r} is not a MISP category that accepts "
                "the 'domain' attribute type."
            )


def _split_list(raw: str) -> list[str]:
    return [part.strip().lower() for part in raw.replace(",", " ").split() if part.strip()]


def _as_bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _whoami() -> str:
    """Best-effort current username; getpass fails when there is no login name."""
    try:
        import getpass

        return getpass.getuser()
    except (KeyError, OSError, ImportError):
        return f"uid {os.getuid()}"


def _read_ini(parser: configparser.ConfigParser, path: Path) -> None:
    """
    Read an ini file, failing loudly.

    configparser.read() swallows OSError and returns a list of files it managed
    to parse -- so an unreadable config produces an empty parser, no exception,
    and a downstream "No API key" error that points at the wrong thing entirely.
    That cost real debugging time, so every failure mode is explicit here.
    """
    try:
        with path.open(encoding="utf-8") as fh:
            parser.read_file(fh, source=str(path))
    except PermissionError:
        raise ConfigError(
            f"{path} exists but this user ({_whoami()}) cannot read it.\n"
            f"  Fix:  sudo chmod 640 {path}\n"
            f"        sudo chown root:misp-nrd {path}\n"
            "  The file must be readable by the group the service runs as. "
            "Mode 600 grants access to the owner only, which locks out the "
            "service user even when the group is correct."
        ) from None
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    except configparser.Error as exc:
        raise ConfigError(
            f"{path} is not valid ini: {exc}\n"
            "  Check for a missing [section] header or a stray quote."
        ) from None


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader. Does not overwrite already-set env vars."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


def load(config_path: str | None = None) -> Config:
    """Build a Config from ini file + environment."""
    cfg = Config()

    _load_dotenv(Path(".env"))

    path = Path(config_path or os.environ.get("NRD_CONFIG", DEFAULT_CONFIG_PATH))
    if path.is_file():
        parser = configparser.ConfigParser()
        _read_ini(parser, path)

        if parser.has_section("whoisfreaks"):
            s = parser["whoisfreaks"]
            cfg.api_key = s.get("api_key", cfg.api_key)
            cfg.base_url = s.get("base_url", cfg.base_url).rstrip("/")
            if "feeds" in s:
                cfg.feeds = _split_list(s["feeds"])

        if parser.has_section("retention"):
            cfg.days = parser["retention"].getint("days", cfg.days)

        if parser.has_section("paths"):
            s = parser["paths"]
            cfg.cache_dir = s.get("cache_dir", cfg.cache_dir)
            cfg.output_dir = s.get("output_dir", cfg.output_dir)
            cfg.meta_dir = s.get("meta_dir", "") or ""

        if parser.has_section("misp"):
            s = parser["misp"]
            cfg.org_name = s.get("org_name", cfg.org_name)
            cfg.uuid_namespace = s.get("uuid_namespace", cfg.uuid_namespace)
            cfg.event_info_prefix = s.get("event_info_prefix", cfg.event_info_prefix)
            cfg.threat_level_id = s.getint("threat_level_id", cfg.threat_level_id)
            cfg.analysis = s.getint("analysis", cfg.analysis)
            cfg.published = s.getboolean("published", cfg.published)
            cfg.to_ids = s.getboolean("to_ids", cfg.to_ids)
            cfg.disable_correlation = s.getboolean(
                "disable_correlation", cfg.disable_correlation
            )
            cfg.category = s.get("category", cfg.category)
            if "file_mode" in s:
                cfg.file_mode = int(s["file_mode"], 8)
            if "tags" in s:
                cfg.tags = [t.strip() for t in s["tags"].split(";") if t.strip()]

        if parser.has_section("logging"):
            cfg.log_level = parser["logging"].get("level", cfg.log_level).upper()

    # ---- environment overrides -------------------------------------------
    env = os.environ
    cfg.api_key = env.get("NRD_API_KEY", cfg.api_key)
    cfg.base_url = env.get("NRD_BASE_URL", cfg.base_url).rstrip("/")
    if "NRD_FEEDS" in env:
        cfg.feeds = _split_list(env["NRD_FEEDS"])
    if "NRD_RETENTION_DAYS" in env:
        cfg.days = int(env["NRD_RETENTION_DAYS"])
    cfg.cache_dir = env.get("NRD_CACHE_DIR", cfg.cache_dir)
    cfg.output_dir = env.get("MISP_FEED_DIR", cfg.output_dir)
    if "NRD_META_DIR" in env:
        cfg.meta_dir = env["NRD_META_DIR"]
    cfg.org_name = env.get("MISP_ORG_NAME", cfg.org_name)
    cfg.uuid_namespace = env.get("MISP_UUID_NAMESPACE", cfg.uuid_namespace)
    if "MISP_TO_IDS" in env:
        cfg.to_ids = _as_bool(env["MISP_TO_IDS"])
    if "MISP_DISABLE_CORRELATION" in env:
        cfg.disable_correlation = _as_bool(env["MISP_DISABLE_CORRELATION"])
    if "MISP_FILE_MODE" in env:
        cfg.file_mode = int(env["MISP_FILE_MODE"], 8)
    if "MISP_TAGS" in env:
        cfg.tags = [t.strip() for t in env["MISP_TAGS"].split(";") if t.strip()]
    cfg.log_level = env.get("NRD_LOG_LEVEL", cfg.log_level).upper()

    # meta_dir defaults relative to whatever cache_dir ended up as
    if not cfg.meta_dir:
        cfg.meta_dir = str(Path(cfg.cache_dir) / "feedmeta")

    return cfg