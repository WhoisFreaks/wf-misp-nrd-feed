# Setting this up on Linux, from nothing

Covers Debian/Ubuntu, RHEL-family (RHEL, Rocky, AlmaLinux, Fedora), Arch,
openSUSE, and Alpine.

You need root or `sudo`, an internet connection, and a WhoisFreaks API key with
the **NRD (Domainer)** product enabled.

**Budget:** about 40 minutes, most of it waiting for MISP's first boot.

---

## What actually differs between distributions

Less than you'd expect, because MISP runs in a container and containers are the
same everywhere. Four things vary, and one of them is a silent failure:

| | Varies how | Where |
|---|---|---|
| Package names | `python3-venv` vs bundled vs `py3-pip` | [Part 1](#part-1--base-packages) |
| Docker install | different repos and package managers | [Part 4](#part-4--docker) |
| **SELinux** | **RHEL-family denies MISP read access even with correct permissions** | [Part 3](#part-3--selinux-rhel-family-only) |
| Scheduler | systemd timer vs cron (Alpine, Void) | [Part 9](#part-9--schedule-it) |

Everything else — the tool, its config, the MISP setup, the feed registration —
is byte-identical across distributions.

If you're on RHEL, Rocky, AlmaLinux, or Fedora, **do not skip Part 3.** SELinux
will block MISP from reading the feed while every permission looks perfect, and
MISP reports zero events with nothing in its logs to explain why.

---

## Before you start: where will MISP live?

This guide puts MISP and the feed generator **on the same machine**, with MISP
in Docker. Fastest path to something you can look at.

The wrinkle: MISP in a container can't see your host filesystem unless you
mount it in. [Part 6](#part-6--mount-the-feed-into-the-container) handles that,
and it's the step people skip. To keep MISP on a separate box, skip Parts 4–6
and see [Alternative: separate
hosts](#alternative-misp-on-a-different-machine).

**Machine sizing.** MISP is the heavy part, not this tool. At least 4 GB RAM
(8 GB for a 30-day window) and 30 GB disk. On 2 GB, MISP's workers get
OOM-killed, which presents as a hang rather than an error.

---

## Part 1 — Base packages

**Debian / Ubuntu**
```bash
sudo apt update
sudo apt install -y python3 python3-venv git curl uuid-runtime
```
`python3-venv` is a separate package here and its absence is the most common
install failure.

**RHEL / Rocky / AlmaLinux / Fedora**
```bash
sudo dnf install -y python3 python3-pip git curl util-linux policycoreutils-python-utils
```
`venv` ships with `python3`. `policycoreutils-python-utils` provides `semanage`,
needed in Part 3.

**Arch**
```bash
sudo pacman -Syu --needed python git curl util-linux
```

**openSUSE**
```bash
sudo zypper install -y python3 python3-pip git curl util-linux
```

**Alpine**
```bash
sudo apk add python3 py3-pip git curl shadow util-linux
```
`shadow` provides `useradd` — Alpine's busybox `adduser` isn't compatible, and
the installer refuses without it.

**Verify, on any distro:**
```bash
python3 --version                          # 3.9+
python3 -c 'import ensurepip; print("venv ok")'
```

---

## Part 2 — Install the feed generator

Identical everywhere. Do this **before** Docker, so the feed directory exists
with the right ownership before anything tries to mount it — if Docker creates
it first, it'll be root-owned and the service user can't write to it.

```bash
git clone https://github.com/WhoisFreaks/wf-misp-nrd-feed.git
cd wf-misp-nrd-feed

sudo bash scripts/install.sh --dry-run
```

The preflight checks Python, `venv`, `useradd`, the nologin shell, systemd,
SELinux, egress, disk, and whether MISP is on this host. It prints what it
would do without changing anything.

Every line should be `[ ok ]` except **`no local MISP install detected`**, which
is expected at this point — you haven't installed it yet.

The connectivity line reads `reached files.whoisfreaks.com (HTTP 404)`. The 404
is correct and not a problem: the bare host root has no content, since the
download service expects a path and an API key. Anything other than exit
code 0 from curl gets reported as a specific transport failure — DNS, connect,
timeout, or TLS.

```bash
sudo bash scripts/install.sh
```

It adapts: uses whichever `nologin` path exists, applies SELinux labels if
enforcing, and falls back to printing a cron line if there's no systemd.

### Configure it

```bash
uuidgen                                    # copy the output
sudo nano /etc/misp-nrd-feed/config.ini
```

```ini
[whoisfreaks]
api_key = your_actual_key_here

[misp]
uuid_namespace = the-uuid-you-just-generated
```

**Generate your own UUID namespace now, before the first run.** It seeds every
event and attribute UUID. Changing it later makes every existing event a
*different* event to MISP and duplicates the whole window.

Keep the first run small — widen once you've seen it work:

```ini
[retention]
days = 3
feeds = gtld
```

Roughly 500k domains instead of 6 million. Ingests in minutes rather than
hours, which is the difference between validating the integration and sitting
there wondering if it's broken.

### First run

```bash
sudo -u misp-nrd misp-nrd-feed --dry-run    # no credits spent
sudo -u misp-nrd misp-nrd-feed --backfill
```

```
done: 3 events, 512431 domains, 3 day(s) changed, 0 day(s) with no data
point MISP at this directory (not manifest.json): /var/lib/misp-nrd-feed/feed
```

```bash
ls -l /var/lib/misp-nrd-feed/feed/
```

Every file should be **`0644`**. MISP reads them as its own web user, so
anything more restrictive means a feed it can't read. The tool sets this
explicitly and warns on every run if the manifest ends up unreadable, so you
shouldn't have to think about it.

HTTP 403 on fetch means your key doesn't cover the Domainer product.
`no gtld data published` means you're asking for a date WhoisFreaks hasn't
published yet — harmless, resolves tomorrow.

---

## Part 3 — SELinux (RHEL-family only)

**Skip this on Debian, Ubuntu, Arch, openSUSE, and Alpine.** Read it on RHEL,
Rocky, AlmaLinux, and Fedora, where SELinux is enforcing by default.

```bash
getenforce
```

If that prints `Enforcing`, POSIX permissions are not the whole story. A file
can be `0644` and owned correctly, and httpd will still be denied read access
because of its security context. The symptom is indistinguishable from a
permissions problem: MISP adds the feed happily, fetches without error, reports
**0 events**, and logs nothing useful.

`install.sh` already applies the label. Verify it took:

```bash
ls -Z /var/lib/misp-nrd-feed/feed/
```

You want `httpd_sys_content_t` in the context. If not:

```bash
sudo chcon -R -t httpd_sys_content_t /var/lib/misp-nrd-feed/feed
sudo semanage fcontext -a -t httpd_sys_content_t '/var/lib/misp-nrd-feed/feed(/.*)?'
sudo restorecon -R /var/lib/misp-nrd-feed/feed
```

`chcon` alone doesn't survive a filesystem relabel; `semanage` makes it
permanent. Do both.

**Docker bind mounts need a relabel flag too** — noted again in Part 6, because
it's easy to miss.

If something is still being denied, SELinux will tell you:

```bash
sudo ausearch -m avc -ts recent | grep -i nrd
```

Don't reach for `setenforce 0`. It'll make the symptom vanish and teach you
nothing, and you'll ship a doc that only works with SELinux off.

---

## Part 4 — Docker

**Debian / Ubuntu**
```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```
On Debian, swap both `ubuntu` occurrences for `debian`.

The `.deb` usually starts the daemon for you, but not always — run
`systemctl enable --now docker` regardless. Note `docker-ce-cli` is the client
and `docker-ce` is the daemon; installing only the former gives you a working
`docker` command with nothing to talk to.

**RHEL / Rocky / AlmaLinux**
```bash
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```
On Fedora use `.../linux/fedora/docker-ce.repo`. On newer dnf, the subcommand
is `dnf config-manager addrepo --from-repofile=<url>`.

**Arch**
```bash
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker
```

**openSUSE**
```bash
sudo zypper install -y docker docker-compose
sudo systemctl enable --now docker
```

**Alpine**
```bash
sudo apk add docker docker-cli-compose
sudo rc-update add docker default
sudo service docker start
```

**Then, everywhere:**
```bash
sudo usermod -aG docker $USER
newgrp docker              # or log out and back in
docker run --rm hello-world
```

---

## Part 5 — MISP

Identical on every distro.

```bash
cd ~
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
```

Defaults are fine for local testing. To reach MISP from another machine, set
`BASE_URL` — including the port if it isn't 443:

```bash
ip -4 addr show | grep inet
nano .env                  # BASE_URL=https://192.168.1.50
```

### Login credentials

These live in `.env`, and are usually commented out in `template.env` so the
defaults apply:

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_EMAIL` | `admin@admin.test` | username for user #1 |
| `ADMIN_PASSWORD` | `admin` | password for user #1 |
| `ADMIN_ORG` | | organisation name for user #1 |
| `ADMIN_KEY` | auto-generated | API key, if you want to script the feed setup |

They only initialise user #1 **on first boot**. Editing them against an
existing database changes nothing, so if you've already started MISP, log in
with the defaults and change the password in the UI.

> **One trap.** misp-docker re-applies env-driven settings on every container
> start. If `ADMIN_PASSWORD` is set in `.env`, a password you change in the web
> UI silently reverts on the next `docker compose restart`. Either change it in
> both places, or leave `ADMIN_PASSWORD` commented out and manage the password
> only in the UI. For a test instance, the latter is simpler.

Don't start it yet. Part 6 adds a volume, and doing it now saves a restart.

---

## Part 6 — Mount the feed into the container

**This is the step that makes or breaks a Local feed.** MISP runs inside a
container with its own filesystem. `/var/lib/misp-nrd-feed/feed` does not exist
as far as MISP is concerned.

Don't edit `docker-compose.yml` — it'll conflict next time you `git pull` in
misp-docker. Use an override file, which Compose merges automatically and
misp-docker doesn't track:

**Debian/Ubuntu, Arch, openSUSE, Alpine:**
```bash
cd ~/misp-docker
cat > docker-compose.override.yml <<'EOF'
services:
  misp-core:
    volumes:
      - "/var/lib/misp-nrd-feed/feed:/nrd-feed:ro"
EOF
```

**RHEL / Rocky / AlmaLinux / Fedora — note the `,z`:**
```bash
cd ~/misp-docker
cat > docker-compose.override.yml <<'EOF'
services:
  misp-core:
    volumes:
      - "/var/lib/misp-nrd-feed/feed:/nrd-feed:ro,z"
EOF
```

The `z` tells Docker to relabel the mount so the container can read it under
SELinux. Without it the mount appears but every read is denied — same silent
zero-event symptom as Part 3. Lowercase `z` shares the label (safe here, since
the directory is read-only to the container); uppercase `Z` would make it
private to this container.

Inside the container the feed lives at **`/nrd-feed`**. That container path is
what you type into MISP — the **directory**, not the host path and not
`manifest.json`.

MISP validates this: give it the manifest file and it refuses outright with
*"For MISP type local feeds, please specify the containing directory."* It
appends `manifest.json` itself. (MISP's own documentation says to point at the
manifest; the running code disagrees, and the code wins.)

Start it:

```bash
docker compose pull        # a few GB
docker compose up -d
docker compose logs -f misp-core
```

First boot takes several minutes — database schema, default taxonomies. Wait
for the healthcheck, then `Ctrl-C`.

While it boots you'll see a line like:

```
Updating unset minimum_config setting 'Security.disable_local_feed_access' to 'false'...
```

That one matters: `false` means local-file feeds are permitted, which the whole
same-host approach depends on. misp-docker sets it for you. If it were `true`,
no Local feed would work regardless of how correct your URL is — see
[Alternative: separate hosts](#alternative-misp-on-a-different-machine).

**Verify the mount before touching the UI:**

```bash
docker compose exec misp-core ls -l /nrd-feed/
docker compose exec misp-core head -c 200 /nrd-feed/manifest.json
```

JSON means you're good. Empty or an error means the mount is wrong, and no
amount of clicking in MISP will fix it.

---

## Part 7 — Add the feed in MISP

Open **https://localhost** (or your `BASE_URL`) and accept the self-signed
certificate.

Log in with the credentials from `.env` — by default `admin@admin.test` /
`admin`. It forces a password change. This account is a site admin, which you
need: **adding a feed requires the site admin role**; an org admin can't.

**Sync Actions → List Feeds → Add Feed**:

| Field | Value |
|---|---|
| Enabled | ✔ |
| Caching enabled | ✔ |
| **Disable correlation** | **✔ — see below, this one matters** |
| Lookup visible | ✔ |
| Name | `WhoisFreaks NRD` |
| Provider | `WhoisFreaks` |
| Input Source | **Local** |
| URL | `/nrd-feed` ← container **directory**, not the manifest file |
| Source Format | **MISP Feed** |
| Distribution | Your organisation only |

**Tick "Disable correlation".** It disables correlations for every event coming
from this feed, and it is the feed-level enforcement of the whole design. The
generated attributes already carry `disable_correlation: true`, but that depends
on MISP honouring the per-attribute flag through ingest; this tick guarantees it
at the ingest layer. With 600k+ attributes, belt and braces is the right call —
this setting can also override what the feed data says, so leaving it off is the
one mistake that can undo the design.

You lose nothing by ticking it. Feed lookups are driven by *Caching enabled*,
not correlation: a matching domain still appears as a "Feed hit" on the event
you're viewing, it just doesn't enter the correlation graph. That is precisely
the trade this integration is built around.

Three common mistakes: pointing at `/nrd-feed/manifest.json` instead of
`/nrd-feed` (MISP rejects this outright), using the host path instead of the
container path, and leaving Source Format on the Freetext default. The last two
give you a feed that silently loads nothing.

### The other fields

The form is dynamic — fields appear and disappear depending on Source Format
and Input Source, so you won't see all of these. **Leave anything not listed
above at its default.** The feed carries its own semantics in the JSON, so the
form only needs to say where the data is and what format it's in.

| Field | Do | Why |
|---|---|---|
| Auto Publish | leave unchecked | Events already carry `published: true`. Ticking it publishes each one on import, firing notifications for no benefit. |
| Override IDS Flag | leave unchecked | It forces the IDS flag false; we already write `to_ids: false`. Redundant, though harmless as a guard. |
| Default Tag | leave empty | Events already carry `tlp:clear` and `whoisfreaks:feed="nrd"`. |
| Filter rules (tags / orgs) | leave empty | For allow/blocklisting someone else's feed. Everything in ours is wanted. |
| Headers | leave empty | Network sources only. |
| Unpublish events | leave unchecked | Known MISP bug: ticking it publishes events instead of unpublishing them, the inverse of the label. Our events are already `published: true`. |
| Lock events | leave unchecked | Marks events as externally owned and not locally editable. Defensible, since they're regenerated daily — but it also blocks analysts tagging or commenting during evaluation. |
| Remove input after ingestion | leave unchecked | Deletes the source file after use, which would break the next pull. It appears once Input Source is **Local** — if you can't see it, check that Input Source isn't still on Network. |
| Target Event / Target Event ID | — | Freetext and CSV only. |
| Exclusion Regex | — | Freetext and CSV only. |
| Delta Merge | — | Freetext and CSV only. |
| Value field(s) / Delimiter | — | CSV only. |

Two checks before you save:

- If *Target Event*, *Delta Merge*, *Exclusion Regex*, or the CSV fields are
  visible, Source Format is not set to **MISP Feed**.
- If *Remove input after ingestion* is **not** visible, Input Source is probably
  not set to **Local** — in which case the container path won't resolve and you
  will get zero events.

Save, then **Fetch and store all feed data** — **once**. It queues a background
job; clicking again starts a second concurrent job on the same feed, which
duplicates work and contends for the same tables.

### How long this takes

Longer than you'd expect, and it's worth knowing the shape of it before you sit
watching a spinner. Measured on a laptop-class machine: roughly **25–30k
attributes per minute**.

| Window | Attributes | First backfill |
|---|---|---|
| 3 days, gTLD | ~500k | ~20 minutes |
| 7 days, gTLD + ccTLD | ~1.4M | ~1 hour |
| 30 days, gTLD + ccTLD | ~6M | several hours |

**This cost is front-loaded.** A backfill ingests the entire window once; after
that a daily run adds one event, so steady state is a handful of minutes a night
no matter how wide the window. Plan the first fetch accordingly and don't judge
the integration by it.

Generating the feed is the cheap half: a 7-day gTLD+ccTLD run (2.6M domains)
takes about 5 seconds of CPU and peaks near 220 MB RSS. Nearly all the elapsed
time is MISP ingesting.

Track progress instead of guessing — *Administration → Jobs* shows each
`fetch_feed` job, or:

```bash
docker compose exec db sh -c 'mariadb \
  -u"${MARIADB_USER:-$MYSQL_USER}" -p"${MARIADB_PASSWORD:-$MYSQL_PASSWORD}" \
  "${MARIADB_DATABASE:-$MYSQL_DATABASE}" -e "
SELECT COUNT(*) attributes FROM attributes;
SELECT id,status,LEFT(message,60) msg FROM jobs WHERE job_type=\"fetch_feed\"\G"'
```

In the `jobs` table, `status: 0` is running and `status: 4` is completed. Don't
start searching for domains until the jobs finish — an event that hasn't been
written yet won't be found, and that looks identical to a broken feed.

**If you clicked Fetch twice, let both jobs run.** MISP has no per-job cancel;
the Jobs page is informational, and the only lever is restarting the workers,
which kills every running job rather than the one you meant. Under supervisord
the workers restart automatically, and a cancelled job can resume when they come
back — so it's messier than waiting. The duplicate wastes CPU but cannot corrupt
anything: because event and attribute UUIDs are deterministic, both jobs upsert
the same rows instead of inserting duplicates.

If you do need to stop everything:

```bash
docker compose exec misp-core supervisorctl restart misp-workers:*
```

Then click Fetch once. Re-fetching after an interruption converges correctly,
for the same UUID reason.

```bash
docker compose logs -f misp-core | grep -i feed
```

---

## Part 7b — Cache the feed

**Fetching and caching are separate operations, and you need both.** This is not
obvious from the UI, and skipping it makes the feed look half-broken.

| | Fetch | Cache |
|---|---|---|
| Reads | `manifest.json` + event files | `hashes.csv` |
| Stores into | MySQL — events and attributes | Redis |
| Gives you | attributes as real objects: searchable, taggable, pivotable | "Feed hit" on any domain, **including the matching event's date and domain count** |
| Found by | *Event Actions → Search Attributes* | *Sync Actions → Search Feed Caches* |
| Time for 3 days | ~20 minutes | seconds |

Ticking *Caching enabled* on the feed only makes it **eligible**. Nothing is
cached until you trigger it:

*Sync Actions → List Feeds* → **Cache all feeds**, or the small RAM icon on the
feed's own row to cache just that one.

The `Cached` column reads *Not Cached* until this runs. Caching is quick — it
reads a single CSV instead of parsing hundreds of megabytes of JSON.

If it still says *Not Cached* afterwards, there is an open MISP issue describing
exactly that, so it isn't your configuration.

### Which mode do you actually want?

**Short answer: caching, unless you specifically need searchable attributes.**
Decide deliberately rather than doing both by default — and note that only one of
the two respects your retention window.

**Cache-only** is the right default for a reference feed like this one. No events,
no attributes in MySQL, nothing entering the correlation engine, ingest in
seconds, and an analyst still sees a Feed hit on any domain they look at. A
30-day window costs you Redis keys instead of six million database rows.

Crucially, it does not cost you the registration date. Verified on an instance
with **0 events and 0 attributes**: the cache hit still showed the matching
event's ID, date and domain count. MISP resolves that from `manifest.json` on
demand, and each event's `info` field carries its date — so the per-day event
granularity pays off even when nothing is imported.

It also has the decisive advantage on retention. **MISP does not delete events
that leave the manifest**, so fetch mode is additive: a 7-day window means seven
days arriving per week and nothing leaving. Verified on a live instance — MISP
listed 7 events while only 2 remained on disk.

Caching does roll. Also verified: after narrowing the window and re-caching, a
domain from a pruned day no longer resolves in *Search Feed Caches*. So the
window you configure is the window you get, which is not true in fetch mode.

**Fetch** gives you the one thing caching can't: attributes as real objects, which
you can search, filter, tag and pivot on, and reach through
`/attributes/restSearch`. Note it is *not* needed for the registration date —
caching already provides that.

Both together is the most capable and the most expensive. The MISP community has
raised the obvious objection — once the data is in the database, copying it into
Redis as well looks redundant.

Remember that fetch mode does not respect your retention window, and caching
does. Unless you specifically need attributes as objects, cache-only is both the
lighter and the more correct choice.

---

## Part 8 — Verify

First, confirm nothing ate your input:

```bash
ls /var/lib/misp-nrd-feed/feed/
```

The event files, `manifest.json`, and `hashes.csv` should all still be there.
The volume is mounted read-only precisely so this can't go wrong, but it costs
one command to be sure.

**In MISP.** *Sync Actions → List Feeds* shows a non-zero event count.
*Event Actions → List Events* shows one event per day, titled
`WhoisFreaks NRD - 2026-07-27 (170813 domains)`.

Then the real test. Pick a domain from the feed:

```bash
sudo -u misp-nrd zcat /var/cache/misp-nrd-feed/nrd-*-gtld.txt.gz | head -1
```

There are two separate things to check, and they can fail independently.

**Ingestion** — *Event Actions → Search Attributes*. Put the domain in the
**value** field and leave the rest at defaults. This queries the attributes
table directly, so `disable_correlation` has no effect on it. A hit means the
attribute is stored; clicking through shows which day's event holds it, and
that event's date **is** the registration date. Domain age becomes a
subtraction rather than a lookup.

**Lookup** — *Sync Actions → List Feeds → Search Feed Caches* in the side menu.
This searches the Redis cache that *Caching enabled* populates, and it's the
machinery behind "Feed hits" showing up on events an analyst is already viewing.

Check both. The first says the data is stored; the second says the feed will
surface freshness on domains that aren't in any of your events yet — which is
the actual value of this integration. If caching failed to populate, the first
passes while the second doesn't.

**On the host:**

```bash
python3 -c "import json;m=json.load(open('/var/lib/misp-nrd-feed/feed/manifest.json'));\
print(len(m),'events');[print(' ',v['date'],v['info']) for v in m.values()]"

wc -l /var/lib/misp-nrd-feed/feed/hashes.csv
```

Logs, depending on init:

```bash
journalctl -u misp-nrd-feed.service --since today --no-pager   # systemd
grep misp-nrd /var/log/messages                                # cron/syslog
```

---

## Part 9 — Schedule it

Only after a successful ingest.

**With systemd** (most distros):
```bash
sudo systemctl start misp-nrd-feed.timer
systemctl list-timers misp-nrd-feed.timer
```
Daily at 20:30 UTC with up to 15 minutes of jitter.

**Without systemd** (Alpine, Void, containers) — `install.sh` prints this line
for you:
```bash
sudo crontab -u misp-nrd -e
# 30 20 * * *  /usr/local/bin/misp-nrd-feed
```

On Alpine, make sure a cron daemon is actually running:
```bash
sudo rc-update add crond default && sudo service crond start
```

Each run fetches only yesterday — two API calls — because past days are cached
and immutable.

### Widening the window

One step at a time:

```bash
sudo nano /etc/misp-nrd-feed/config.ini     # days = 7, feeds = gtld, cctld
sudo -u misp-nrd misp-nrd-feed --backfill
```

Re-fetch in MISP, then watch your database. Confirm the service names first —
they differ between MISP deployments, and in misp-docker the database service is
`db`:

```bash
cd ~/misp-docker
docker compose ps                  # service names, and what is actually running
```

Read the credentials from inside the container rather than from `.env` — the
variables are often left commented out there, and an empty `-p` just makes the
client prompt for a password:

```bash
docker compose exec db sh -c 'mariadb \
  -u"${MARIADB_USER:-$MYSQL_USER}" \
  -p"${MARIADB_PASSWORD:-$MYSQL_PASSWORD}" \
  "${MARIADB_DATABASE:-$MYSQL_DATABASE}" \
  -e "SELECT COUNT(*) FROM attributes; SELECT COUNT(*) FROM default_correlations;"'
```

Note the single quotes: the variables must expand *inside* the container. The
client is `mariadb` on current images; older ones have `mysql`.

None of this is required. The UI answers the same questions without credentials
— *Sync Actions → List Feeds* for the event count, *Administration → Jobs* for
fetch status.

`default_correlations` should stay flat as attributes grow. If it's growing in
proportion, `disable_correlation` isn't taking effect — check the feed's own
settings in MISP, which can override the config. See
[`why-disable-correlation.md`](why-disable-correlation.md).

---

## Alternative: MISP on a different machine

Use this when MISP lives elsewhere — or when it lives here but has local feed
access disabled.

**When it's the only option.** A local feed can point at any path MISP's web
user can read, so a site admin could use one to read files off the server.
Hardened deployments therefore set `Security.disable_local_feed_access` to
`true`, and that setting is on MISP's blocked-settings list — it cannot be
changed from the web UI or the settings database, only from the config file or
CLI. On such an instance the Local input source is unusable and serving the feed
over HTTP is the only route.

Check before you plan a customer deployment:

```bash
# inside the misp-core container, or on the MISP host
sudo -u www-data /var/www/MISP/app/Console/cake Admin getSetting \
  Security.disable_local_feed_access
```

Skip Parts 4–6. On the host running this tool:

```bash
# Debian/Ubuntu
sudo apt install -y nginx
# RHEL family:  sudo dnf install -y nginx && sudo systemctl enable --now nginx
# Arch:         sudo pacman -S nginx
# Alpine:       sudo apk add nginx && sudo rc-update add nginx default

sudo ln -s /var/lib/misp-nrd-feed/feed /var/www/html/nrd
sudo systemctl reload nginx
curl -s http://localhost/nrd/manifest.json | head -c 200
```

On RHEL-family the nginx root is `/usr/share/nginx/html`, and SELinux needs the
same `httpd_sys_content_t` label from Part 3 plus:

```bash
sudo setsebool -P httpd_read_user_content 1
```

Open the port:

```bash
sudo ufw allow from <misp-ip> to any port 80        # Debian/Ubuntu
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" \
  source address="<misp-ip>" port port=80 protocol=tcp accept'   # RHEL family
sudo firewall-cmd --reload
```

Then in MISP use **Input Source: Network** with `http://your-host/nrd/` — the
directory again, not the manifest. Make sure nginx serves that path with
directory access working; MISP requests `<url>/manifest.json` beneath it.

Restrict access — this is your paid data. An IP allowlist is the minimum; TLS
and basic auth are better.

---

## Troubleshooting

**`python3 venv support missing`** — see Part 1 for your distro. The installer
refuses before changing anything, so there's nothing to undo.

**`useradd not found`** — Alpine. `sudo apk add shadow`.

**`docker: permission denied`** — you haven't re-logged-in after
`usermod -aG docker`. `newgrp docker` or a new session.

**`failed to connect to the docker API at unix:///var/run/docker.sock ... no
such file or directory`** — different problem: the socket doesn't exist, so the
daemon isn't running. (Contrast with *permission denied*, where the socket exists
but you can't reach it.)

```bash
sudo systemctl enable --now docker      # fixes most cases
```

If that doesn't do it:

```bash
dpkg -l | grep -E "docker-ce|containerd"   # is the daemon installed at all?
which dockerd                              # empty means only the CLI is present
systemctl status docker --no-pager -l | head -20
docker version                             # "Server: Cannot connect" = daemon side
snap list docker                           # a snap install competing for the socket
```

Missing daemon: `sudo apt install -y docker-ce containerd.io`. A snap install
alongside the apt one gives you two Dockers and one wrong socket — remove one.

**MISP won't load, containers restart repeatedly** — almost always RAM.
`docker compose logs misp-core | grep -i "killed\|memory"`.

**`docker compose exec misp-core ls /nrd-feed` is empty** — the mount didn't
apply. Confirm `docker-compose.override.yml` sits beside `docker-compose.yml`,
then `docker compose up -d` again (a plain `restart` won't pick up new
volumes). Inspect with `docker compose config | grep -A3 volumes`.

**Feed added, 0 events after fetching** — in order of likelihood:

1. URL is the host path instead of the container path `/nrd-feed`
2. Source Format isn't *MISP Feed*
3. **SELinux** — missing `,z` on the mount, or missing `httpd_sys_content_t`
   (RHEL family only; check `sudo ausearch -m avc -ts recent`)
4. The manifest is genuinely empty (`--dry-run` will say)

**A warning that the manifest isn't world-readable** — something outside the
tool changed the modes. `sudo chmod -R o+r /var/lib/misp-nrd-feed/feed`, or
just re-run `misp-nrd-feed`, which repairs modes without re-fetching.

**Ingest starts then stalls, or the feed shows 0 events after fetching** — check
*Administration → Jobs* first. "Fetch and store all feed data" queues a
background job, so if the workers aren't running the UI reports success and
nothing happens, with no error surfaced anywhere. Also check
*Administration → Server Settings & Maintenance → Workers*.

```bash
cd ~/misp-docker
docker compose ps                                     # is anything exited?
docker compose logs --tail=200 misp-core 2>&1 | grep -iE "feed|worker|error|memory"
```

And confirm the feed saved the way you intended — faster to read than to click
through the edit form:

```bash
docker compose exec db sh -c 'mariadb \
  -u"${MARIADB_USER:-$MYSQL_USER}" -p"${MARIADB_PASSWORD:-$MYSQL_PASSWORD}" \
  "${MARIADB_DATABASE:-$MYSQL_DATABASE}" -e "
SELECT id,name,url,input_source,source_format,enabled,caching_enabled
FROM feeds WHERE url LIKE \"%nrd%\"\G"'
```

`url` should be the directory, `source_format` should be `misp`, and
`input_source` should be `local`.

If the job failed on memory or timed out, the event files may simply be too
large for the instance. Test with a single small day, then re-fetch:

```bash
sudo -u misp-nrd misp-nrd-feed --days 1 --feeds gtld
```

One day ingesting where three don't means capacity, not configuration — reduce
`days`, or `feeds` to `gtld` alone.

**`No API key` even though you set one in config.ini** — the service user
can't read the file. This happens if you tighten the mode to `600` by hand:
that grants the owner (root) only and locks out `misp-nrd`, even though the
group is correct.

```bash
ls -l /etc/misp-nrd-feed/config.ini      # want 640 root:misp-nrd
sudo chmod 640 /etc/misp-nrd-feed/config.ini
```

`install.sh` sets this correctly and verifies it, so you'll only see this if
the file was edited or replaced manually.

**`config.ini is not valid ini`** — usually a setting placed above its
`[section]` header, or a stray quote. The error names the line.

**`For MISP type local feeds, please specify the containing directory`** — the
URL points at `manifest.json`. Use the directory, `/nrd-feed`. MISP appends the
filename itself.

**`Cannot write to the directories this needs`** — run it as the service user:
`sudo -u misp-nrd misp-nrd-feed`.

---

## Starting over

```bash
cd ~/misp-docker && docker compose down -v

cd ~/wf-misp-nrd-feed && sudo bash scripts/install.sh --uninstall
sudo rm -rf /etc/misp-nrd-feed /var/cache/misp-nrd-feed /var/lib/misp-nrd-feed
```

`--uninstall` deliberately leaves config, cache, and feed directory in place;
the second command removes them.

On RHEL family, also drop the SELinux rule:

```bash
sudo semanage fcontext -d '/var/lib/misp-nrd-feed/feed(/.*)?' 2>/dev/null || true
```