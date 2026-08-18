# wf-misp-nrd-feed

[![CI](https://github.com/WhoisFreaks/wf-misp-nrd-feed/actions/workflows/ci.yml/badge.svg)](https://github.com/WhoisFreaks/wf-misp-nrd-feed/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

Turn the [WhoisFreaks](https://whoisfreaks.com) **Newly Registered Domains
(NRD)** feed into a native **[MISP](https://www.misp-project.org/) feed**, so
every analyst looking at a domain can see whether it was registered days ago —
without leaving MISP and without a per-domain API call.

```
WhoisFreaks NRD API  ->  per-day gzip cache  ->  MISP feed directory  ->  MISP pulls on its own schedule
```

This writes a feed directory to disk. **It never calls the MISP API.** MISP is
pointed at the feed directory and does the ingesting itself, on its own
schedule, with its own error handling.

---

## How this differs from the WhoisFreaks MISP module

Both exist; they answer different questions.

| | [WhoisFreaks expansion module](https://misp.github.io/misp-modules/expansion/#whoisfreaks-lookup) | This repo |
|---|---|---|
| Type | Expansion module | Feed |
| Trigger | Analyst clicks enrich on one attribute | Scheduled pull, no analyst |
| Volume | One domain per call | ~200k domains/day |
| Question | "Tell me everything about this domain" | "Is this domain new, and how new?" |
| Direction | Pull, on demand | Push, ahead of time |

The module is reactive and deep. The feed is proactive and broad. Running both
is the intended configuration: the feed flags freshness on domains nobody has
looked at yet, and the module gives you the full WHOIS and DNS picture on the
one you decide to investigate.

---

## Why freshness belongs in MISP at all

Most phishing and malware C2 infrastructure is registered and weaponised
within 24–48 hours of first use. By the time a domain shows up in a
reputation feed, the campaign has usually already run. Domain age is the one
signal that is available *before* anyone has classified the domain, because it
comes from the registry rather than from observed badness.

In MISP that lands as context, not as a verdict. A domain being three days old
isn't evidence of anything on its own — but "this domain in the alert you're
triaging was registered on Tuesday" changes what you do next, and it's the
kind of thing that should already be on screen rather than something you go
and look up.

---

## Prerequisites

**Do you need MISP installed to run this? No — and yes.**

This tool never talks to MISP. It reads the WhoisFreaks API and writes files to
a directory. `install.sh` will complete and `misp-nrd-feed` will produce a
valid feed on a box with no MISP anywhere near it.

But a feed nobody consumes is just JSON on a disk. You need a MISP instance
*somewhere*, and where it lives changes one setting:

| Your setup | MISP needed on this host? | How you add the feed |
|---|---|---|
| MISP and this tool on the same box | Yes | *Input Source: **Local***, URL is the filesystem path to the feed **directory** |
| MISP on a different box | No | Serve `output_dir` over HTTP, then *Input Source: **Network***, URL is `https://your-host/nrd/` |

The same-host case is simpler and is what `install.sh` sets permissions for.
The separate-host case is better if you don't want a cron job writing to your
MISP server's disk. Nothing about the generated files differs between them.

**One caveat that decides it for you.** Local feeds require MISP's
`Security.disable_local_feed_access` to be `false`. Hardened instances set it
`true` — a local feed can point at any file the web user can read — and it's on
MISP's blocked-settings list, so it can't be flipped from the web UI or the
settings database. On such an instance, serving over HTTP is the only option.

`install.sh` detects whether MISP is present and prints which path applies.

### On the host running this tool

| Component | Requirement | Install if missing |
|---|---|---|
| Python | 3.9+ | in every distro's base repos |
| **`venv` module** | **required** | separate package on Debian/Ubuntu (`apt install python3-venv`); bundled with `python3` on RHEL-family, Arch, openSUSE; Alpine needs `apk add py3-pip` |
| `requests` | ≥2.28 | installed into the venv by `install.sh` |
| OS | any Linux | systemd gives you the timer; without it `install.sh` prints a cron line. Windows works manually — see [Windows](#windows) |
| `useradd` | required | present everywhere except Alpine (`apk add shadow`) |
| Root | for `install.sh` only | the tool itself runs as the unprivileged `misp-nrd` user |
| Egress | HTTPS to `files.whoisfreaks.com` | open it, or set `HTTPS_PROXY` in the service unit |
| Disk | ~15 MB per 100k domains per day | 7-day gTLD+ccTLD ≈ 1 GB, 30-day ≈ 4 GB, cache included |
| API key | [WhoisFreaks account](https://billing.whoisfreaks.com/signup) with the **NRD (Domainer)** product | WHOIS-only plans return HTTP 403 |

`install.sh` checks all of the above before touching anything, and refuses
with a specific fix rather than failing halfway through.

### MISP itself

**Use MISP 2.5.** Feed support has been in MISP since well before 2.4, so 2.4
works fine mechanically — but 2.4 is end-of-life and in security-fix-only
phase, and the MISP project strongly advises against standing up new 2.4
instances. Don't build something new on it.

If you don't have MISP yet, in rough order of how much pain they involve:

| Method | Link | Notes |
|---|---|---|
| **Docker** (easiest) | [MISP/misp-docker](https://github.com/MISP/misp-docker) | Official, maintained by @ostefano. Includes misp-modules. Best choice for evaluating this integration. |
| Ubuntu 24.04 installer | [misp-project.org/download](https://www.misp-project.org/download/) | The project's recommendation for production 2.5. Other distros need manual tinkering. |
| Prebuilt VM | [circl.lu/misp-images](https://www.circl.lu/misp-images/latest/) | Fastest way to a working instance for testing. |
| Full documentation | [misp.github.io/MISP](https://misp.github.io/MISP/) | Install guides and administration. |

You'll also need, on the MISP side:

- **A site admin account.** Adding a feed requires the site admin role; a
  regular org admin can't do it.
- **MySQL/MariaDB headroom.** A 7-day window is ~1.4M attributes. Check your
  instance's current size before choosing a window — see
  [Choosing a window](#choosing-a-window).
- **Read access for MISP's web user** to the feed directory, in the same-host
  case. `install.sh` sets `0755` and writes files `0644`; verify with
  `sudo -u www-data cat /var/lib/misp-nrd-feed/feed/manifest.json`
  (`apache` on RHEL-family, uid 33 inside a misp-docker container).
- **On RHEL, Rocky, AlmaLinux and Fedora: an SELinux label.** Correct
  permissions are not sufficient — httpd is denied read access without
  `httpd_sys_content_t`, and the failure is silent. `install.sh` applies it when
  SELinux is enforcing; see
  [Part 3 of the setup guide](docs/SETUP-LINUX.md#part-3--selinux-rhel-family-only).

### What you do *not* need

- **A MISP API key or automation key.** This writes files; MISP pulls. There's
  no authentication between the two.
- **`pymisp` at runtime.** It's a test-only dependency, used to assert our
  output matches the library's format byte for byte. Not installed by
  `install.sh`.
- **`misp-modules`.** The [WhoisFreaks expansion
  module](https://misp.github.io/misp-modules/expansion/#whoisfreaks-lookup) is
  a good companion but entirely independent of this feed.
- **Network access from MISP to WhoisFreaks.** Only this host talks to the API.

---

## Quick start

> **Starting from nothing?** Follow
> [`docs/SETUP-LINUX.md`](docs/SETUP-LINUX.md) instead. It covers Debian/Ubuntu,
> RHEL-family, Arch, openSUSE and Alpine — including installing MISP via Docker,
> the container volume mount a Local feed needs, and the SELinux labelling
> RHEL-family distros require. This section assumes a working MISP already.

```bash
# Debian/Ubuntu: the one package people forget. Other distros: see SETUP-LINUX.md
sudo apt install -y python3 python3-venv

git clone https://github.com/WhoisFreaks/wf-misp-nrd-feed.git
cd wf-misp-nrd-feed
sudo bash scripts/install.sh --dry-run    # preflight + show what it would do
sudo bash scripts/install.sh
```

`--dry-run` runs the full preflight (Python version, `venv` support, egress,
disk, whether MISP is on this host) and prints every command it would execute
without changing anything.

The installer creates a `misp-nrd` service user, a virtualenv at
`/opt/misp-nrd-feed/venv`, the `misp-nrd-feed` command, a systemd service and
timer, and the directories below. Run it with `--dry-run` first if you'd like
to see the commands without executing them.

Then:

**1. Add your API key and your own UUID namespace.**

```bash
uuidgen                                     # generate one, now
sudo nano /etc/misp-nrd-feed/config.ini     # set api_key and uuid_namespace
```

The UUID namespace seeds every event and attribute UUID in the feed. Set it
once, before the first run, and never change it — changing it makes every
existing event a *different* event to MISP and duplicates the whole window.

**2. Fill the window.**

```bash
sudo -u misp-nrd misp-nrd-feed --dry-run     # what would happen
sudo -u misp-nrd misp-nrd-feed --backfill    # fetch the whole window
```

A 7-day backfill is `2 × 7 = 14` API calls. After that, a normal daily run is
two calls, because past days are cached and immutable.

**3. Start the timer.**

```bash
sudo systemctl start misp-nrd-feed.timer
systemctl list-timers misp-nrd-feed.timer
```

**4. Add the feed in MISP.**

*Sync Actions → List Feeds → Add Feed*

| Field | Value |
|-------|-------|
| Enabled | ✔ |
| Caching enabled | ✔ (this is what makes lookups work — see below) |
| Lookup visible | ✔ if you want other users to see the hits |
| Input Source | **Local** |
| URL | `/var/lib/misp-nrd-feed/feed` — the **directory**, not `manifest.json` |
| Source Format | **MISP Feed** |
| Distribution | your choice |

Leave *Remove input after ingestion* **unchecked** — the feed directory is
regenerated daily and MISP deleting it would break the next pull.

Then **Fetch and store all feed data** once to prime it. After that MISP pulls
on its own schedule.

**Then cache it separately.** *Caching enabled* only marks the feed as eligible;
nothing is in Redis until you click **Cache all feeds** (or the RAM icon on the
feed's row). Fetch reads `manifest.json` and the event files into MySQL; caching
reads `hashes.csv` into Redis. They're independent, and the lookups an analyst
sees as "Feed hits" come from the cache, not the fetch. See
[Part 7b of the setup guide](docs/SETUP-LINUX.md#part-7b--cache-the-feed) for
which mode you actually want — cache-only is a reasonable default for a
reference feed this large.

> **Serving it over HTTP instead.** If MISP runs on a different host, point a
> web server at `output_dir` and use *Input Source: Network* with
> `https://your-host/nrd/` — again the directory, not the manifest. Nothing
> about the generated files changes.

---

## The two settings that matter

The defaults are `to_ids = false` and `disable_correlation = true`, and they
are the difference between this working and your MISP grinding to a halt.

A 30-day window is ~6 million domains. Left correlating, that puts more rows
in MISP's correlation table than in the rest of the database, and the
correlations you get are mostly domains matching each other for the sole
reason that they were all registered recently — a property of the feed, not a
relationship between the domains.

Turning correlation off does **not** turn off feed lookups. With *Caching
enabled* ticked, an analyst viewing any domain attribute still sees whether it
appears in this feed and in which day's event. That's the whole point, and it
costs nothing.

**Read [`docs/why-disable-correlation.md`](docs/why-disable-correlation.md)
before changing either flag.** There's a legitimate case for correlation on a
3-day window; that document explains how to do it safely.

---

## Retention: read this before choosing a window

**MISP does not delete events that leave the manifest.** Feed ingestion is
additive. Verified on a live instance: after narrowing the window so that two
event files remained on disk, MISP still listed all seven previously ingested
events.

This matters because it decides whether your window is real:

| Mode | Rolls? | What grows |
|---|---|---|
| **Cache** (`hashes.csv` → Redis) | **Yes** — verified: a domain from a pruned day stops resolving after a re-cache | Redis keys, bounded by the window |
| **Fetch** (events → MySQL) | **No** — verified: 7 events remained in MISP with 2 on disk | events and attributes, without bound |

Both rows were measured on a live instance, not inferred.

So in fetch mode a 7-day window does not mean 7 days in MISP. It means 7 days
arriving per week and nothing leaving. After two months you hold roughly two
months of events — on the order of 22 million attributes — which is precisely
the database growth the rest of this design works to avoid.

Three ways to handle it:

**1. Cache-only — the recommended default.** Enable caching, never run a fetch.

Measured on an instance holding **0 events and 0 attributes**: a cache hit still
reports the matching event's ID, its date, and its domain count. Registration-date
attribution survives with nothing ingested, because MISP reads event metadata
from `manifest.json` on demand and each event's `info` field carries its date.

So you get the freshness signal, the exact registration date, a window that
genuinely rolls, ingest in seconds, no database growth, and no possibility of the
correlation problem this project spends so much effort neutralising — because no
attribute is ever created.

What you give up is attributes as first-class objects: you cannot search, filter,
tag or pivot on them, and `/attributes/restSearch` will not find them. If a SOAR
playbook needs to query this programmatically, check whether MISP's feed-cache
search covers your case before assuming cache-only is sufficient.

**2. Fetch, and purge deliberately.** Only worth it if you need attributes as
real objects — searchable, taggable, pivotable. You do *not* need it merely for
the registration date, which caching already gives you. Delete aged-out events
yourself:
The event UUIDs are deterministic — `uuid5(namespace, "wf-nrd-event|<date>")` —
so the events to remove are computable without querying anything. This needs a
MISP API key and a scheduled purge; this tool deliberately does not talk to the
MISP API.

**3. Fetch with a deliberately small window and accept the growth.** Viable for
evaluation, not for a long-lived instance.

Pick one before you turn on the scheduler. Option 3 by accident is the failure
mode.

---

## Choosing a window

`days` in `[retention]` is the main lever.

Sizes below are what a *single pass* of the window contains. In fetch mode
they are the amount arriving, not the steady-state total — see
[Retention](#retention-read-this-before-choosing-a-window).

| Window | Attributes | Notes |
|--------|-----------|-------|
| 3 | ~600k | Small enough to consider enabling correlation |
| **7** | **~1.4M** | **Default. Good balance for most instances.** |
| 14 | ~2.8M | Comfortable on a well-resourced instance |
| 30 | ~6M | Unit 42's recommended detection window. Size MySQL first. |

Anything over 90 is refused outright — raise the guard in `src/config.py` if
you truly mean it.

Cutting `feeds` to `gtld` alone drops volume by roughly 20% and removes most
of the ccTLD tail, which is the pragmatic move if you're tight on resources.

---

## Usage

```bash
misp-nrd-feed                    # daily run: fetch yesterday, rebuild feed
misp-nrd-feed --backfill         # fetch every missing day in the window
misp-nrd-feed --dry-run          # no network, no writes, just report
misp-nrd-feed --force            # rewrite event files even if unchanged
misp-nrd-feed --days 14          # override the window for one run (cache kept)
misp-nrd-feed --feeds gtld       # gTLD only for one run
```

A `--days` override applies to the generated feed only; it deliberately does not
expire cached days, since each one costs API calls to replace. Rolling cache
expiry happens on runs that use the configured window.

Exit codes: `0` success, `1` the feed came out empty, `2` configuration
problem, `130` interrupted.

---

## Layout

```
src/config.py              ini + env config, with guard rails
src/cache_manager.py       per-day gzip cache: save/load/expire/merge
src/nrd_fetcher.py         WhoisFreaks NRD download + tolerant parsing
src/feed_builder.py        MISP feed format: events, manifest, hashes, pruning
src/main.py                CLI orchestration
scripts/install.sh         installer (--dry-run, --uninstall)
systemd/                   oneshot service + daily timer
config/config.ini.example  annotated configuration
docs/                      setup walkthrough + design rationale
tests/                     39 tests, incl. format equivalence vs PyMISP
```

Generated at runtime:

```
/var/cache/misp-nrd-feed/               nrd-YYYY-MM-DD-{gtld,cctld}.txt.gz
/var/cache/misp-nrd-feed/feedmeta/      per-day manifest + hash sidecars
/var/lib/misp-nrd-feed/feed/            manifest.json, <uuid>.json, hashes.csv
```

`feedmeta` must stay **outside** the feed directory: MISP parses every `*.json`
it finds alongside `manifest.json`.

---

## Design notes

**One event per feed-day carries the date without ingestion.** Each event's
`info` field reads `WhoisFreaks NRD - <date> (<n> domains)`, and MISP resolves it
from `manifest.json` when a cached hash matches. That is what lets cache-only
mode report the registration date while storing nothing — the granularity is
doing work even when no event is imported.

**One event per feed-day, with a deterministic UUID.** The event UUID is
`uuid5(namespace, "wf-nrd-event|<date>")`, so re-running for a day updates that
event instead of creating a duplicate. That's what makes the whole thing
idempotent and safe to run from cron without any state tracking.

**Timestamps track content, not runs.** A day's event timestamp only changes
when that day's domain set actually changes. Without this, every nightly run
would look to MISP like a new version of every attribute in the window, and
MISP would re-ingest millions of rows every night for no reason. There's a test
for it.

**The wire format is pinned, not guessed.** The feed JSON, `manifest.json`
structure, and `hashes.csv` lines are asserted equal to what PyMISP's own
`MISPEvent.to_feed()`, `.manifest`, and `feed_meta_generator()` produce
(`tests/test_misp_nrd_feed.py`). We emit plain dicts rather than building
`MISPAttribute` objects only for speed — about 10× faster and 4× less memory at
200k attributes, which is the difference between a 30-day backfill taking one
minute and taking ten.

**Incremental manifest.** PyMISP's `feed_meta_generator()` re-reads and
re-hashes every event JSON in the directory on every call. For a 30-day window
of 200k-attribute events that's re-parsing well over a gigabyte of JSON
nightly. This reads small per-day sidecars instead and produces identical
output — again, with a test asserting it.

**Rolling by pruning.** A domain ages out when its day's event drops out of the
manifest. Pruning only touches files whose names match a UUID this tool would
have generated, so anything else in the directory is left alone.

**Always yesterday, never today.** WhoisFreaks publishes ccTLD data for the
previous day around 03:00 UTC and gTLD not reliably until the afternoon, so
asking for today's date returns nothing depending on when the job fires.
Anchoring on yesterday makes the schedule time-of-day agnostic.

---

## Verifying it worked

```bash
# The feed directory
ls -la /var/lib/misp-nrd-feed/feed/
python3 -c "import json;m=json.load(open('/var/lib/misp-nrd-feed/feed/manifest.json'));\
print(len(m),'events');[print(' ',v['date'],v['info']) for v in m.values()]"

# Line count should equal total domains in the window
wc -l /var/lib/misp-nrd-feed/feed/hashes.csv

# Service logs
journalctl -u misp-nrd-feed.service --since today --no-pager
```

In MISP, after a fetch: *Sync Actions → List Feeds* shows a non-zero event
count against the feed. Search any domain from the window under
*Event Actions → Search* and it should resolve to the right day's event.

---

## Troubleshooting

**`python3 venv support missing`** during install — `python3-venv` is a
separate package on Debian/Ubuntu. `sudo apt install python3-venv` and re-run.
The installer refuses before making any changes, so there's nothing to undo.

**`configuration problem: No API key`** — either `api_key` really is unset and
`NRD_API_KEY` isn't exported, or the service user cannot read the config file.
If you tightened the mode by hand, `600` grants the owner only and locks out
`misp-nrd` even though the group is right:

```bash
ls -l /etc/misp-nrd-feed/config.ini      # want 640 root:misp-nrd
sudo chmod 640 /etc/misp-nrd-feed/config.ini
```

An unreadable config is reported as such, not as a missing key.

**`HTTP 401/403 ... the API key was rejected`** — either the key is wrong or
your plan doesn't include the NRD (Domainer) product. WHOIS-only plans return
403 here.

**`no <tld> data published for <date> (HTTP 404)`** — usually benign, and
expected if you run early in the UTC day. The run continues and picks that day
up tomorrow. If it persists for several days, check the date range your
subscription covers.

**`manifest is empty -- MISP will pull nothing`** — the cache has no usable
days. Run `--dry-run` to see what's actually cached, then `--backfill`.

**MISP shows the feed with 0 events** — three usual causes: the URL points at
`manifest.json` rather than at its containing directory; *Source Format* is set to
Freetext or CSV instead of **MISP Feed**; or MISP's web user can't read the
directory (`sudo -u www-data cat /var/lib/misp-nrd-feed/feed/manifest.json`
should work — on RHEL the user is `apache`).

**Ingest is slow or MISP gets sluggish** — check `disable_correlation` really
is `true` in your config *and* that the feed's own settings in MISP haven't
re-enabled it. Then reduce `days`. See
[`docs/why-disable-correlation.md`](docs/why-disable-correlation.md).

**`Cannot write to the directories this needs`** — the run isn't the
`misp-nrd` user. Use `sudo -u misp-nrd misp-nrd-feed`, or point
`NRD_CACHE_DIR` and `MISP_FEED_DIR` somewhere you own.

### Windows

No installer, but the tool itself is cross-platform. Paths default under
`%PROGRAMDATA%\misp-nrd-feed`. Run `python -m src.main` from a checkout and
schedule it with Task Scheduler; serve the feed directory over HTTP for MISP
to pull, since a Windows path won't work as a MISP *Local* feed.

---

## Development

```bash
git clone https://github.com/WhoisFreaks/wf-misp-nrd-feed.git
cd wf-misp-nrd-feed
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pymisp ruff

python -m pytest tests/ -v
ruff check src/ tests/ --ignore E501
```

The tests need no network and no MISP instance. If `pymisp` isn't installed,
the two format-equivalence tests skip rather than fail — but don't let them
skip in CI, they're the ones that matter.

---

## Related integrations

Same NRD feed, different surfaces:

- [wf-pihole-nrd-feed](https://github.com/WhoisFreaks/wf-pihole-nrd-feed) — DNS blocking
- [wf-adguard-nrd-feed](https://github.com/WhoisFreaks/wf-adguard-nrd-feed) — DNS blocking
- [wf-bind9-nrd-rpz](https://github.com/WhoisFreaks/wf-bind9-nrd-rpz) — DNS firewall via RPZ
- [wf-rspamd-postfix-nrd-feed](https://github.com/WhoisFreaks/wf-rspamd-postfix-nrd-feed) — email scoring
- [wf-spamassassin-nrd-feed](https://github.com/WhoisFreaks/wf-spamassassin-nrd-feed) — email scoring
- [wf-suricata-nrd-feed](https://github.com/WhoisFreaks/wf-suricata-nrd-feed) — IDS alerting
- [wf-zeek-nrd-feed](https://github.com/WhoisFreaks/wf-zeek-nrd-feed) — passive network analysis

## License

[MIT](LICENSE)

## Acknowledgments

- [WhoisFreaks](https://whoisfreaks.com/) for the NRD data
- The [MISP project](https://www.misp-project.org/) and PyMISP, whose feed
  format this implements