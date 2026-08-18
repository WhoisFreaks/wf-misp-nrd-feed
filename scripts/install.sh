#!/usr/bin/env bash
#
# Installer for wf-misp-nrd-feed.
#
#   sudo bash scripts/install.sh              install
#   sudo bash scripts/install.sh --dry-run    print what it would do
#   sudo bash scripts/install.sh --uninstall  remove units + /opt payload
#
# Re-running is safe: source files are always refreshed (the BIND9 installer's
# habit of only copying src/ on first install caused hours of confusion, so
# this one overwrites every time).

set -euo pipefail

PREFIX=/opt/misp-nrd-feed
CONFIG_DIR=/etc/misp-nrd-feed
CACHE_DIR=/var/cache/misp-nrd-feed
FEED_DIR=/var/lib/misp-nrd-feed/feed
BIN=/usr/local/bin/misp-nrd-feed
SERVICE_USER=misp-nrd

DRY_RUN=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

run() {
  if [[ $DRY_RUN -eq 1 ]]; then echo "  + $*"; else eval "$@"; fi
}

require_root() {
  if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
    echo "This needs root. Re-run with sudo." >&2; exit 1
  fi
}

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $UNINSTALL -eq 1 ]]; then
  require_root
  echo "Removing wf-misp-nrd-feed..."
  run "systemctl disable --now misp-nrd-feed.timer 2>/dev/null || true"
  run "rm -f /etc/systemd/system/misp-nrd-feed.service /etc/systemd/system/misp-nrd-feed.timer"
  run "systemctl daemon-reload"
  run "rm -rf $PREFIX $BIN"
  echo
  echo "Left in place on purpose (delete by hand if you mean it):"
  echo "  $CONFIG_DIR   (your API key)"
  echo "  $CACHE_DIR    (cached feed days)"
  echo "  $FEED_DIR     (the feed MISP is pointed at)"
  echo "Also remove the feed from MISP: Sync Actions -> List Feeds."
  exit 0
fi

require_root

# ---- preflight ------------------------------------------------------------
# Everything that can be checked cheaply is checked here, before we create
# users or directories. A failure halfway through an install is much more
# annoying to clean up than a refusal at the start.

echo "==> Preflight"
FATAL=0
note_fatal() { echo "  [FAIL] $1" >&2; FATAL=1; }
note_warn()  { echo "  [WARN] $1" >&2; }
note_ok()    { echo "  [ ok ] $1"; }

# Python interpreter
if ! command -v python3 >/dev/null 2>&1; then
  note_fatal "python3 not found. Install Python 3.9+ and re-run."
else
  PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
  if [[ "$PY_OK" != "1" ]]; then
    note_fatal "Python 3.9+ required; found $(python3 -V 2>&1)."
  else
    note_ok "$(python3 -V 2>&1)"
  fi
fi

# The venv module. On Debian/Ubuntu this is a SEPARATE package from python3,
# and its absence is the single most common reason this installer used to
# fail -- `python3 -m venv` dies with an ensurepip error.
if command -v python3 >/dev/null 2>&1; then
  if python3 -c 'import ensurepip' >/dev/null 2>&1; then
    note_ok "python3 venv support"
  else
    note_fatal "python3 venv support missing. Install it:
           Debian/Ubuntu:  sudo apt install python3-venv
           RHEL/Rocky:     sudo dnf install python3-devel
           then re-run this script."
  fi
fi

# Account tooling. Alpine ships busybox `adduser` and has no `useradd`
# unless the shadow package is installed.
if ! command -v useradd >/dev/null 2>&1; then
  note_fatal "useradd not found. On Alpine: apk add shadow. Otherwise install
           the shadow-utils package for your distribution."
else
  note_ok "useradd present"
fi

# nologin lives in different places. On distros where /sbin is a symlink to
# /usr/sbin either path resolves, but Alpine and some minimal images only
# have one of them.
NOLOGIN=""
for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
  if [[ -x "$candidate" ]]; then NOLOGIN="$candidate"; break; fi
done
if [[ -z "$NOLOGIN" ]]; then
  note_fatal "no nologin shell found (looked in /usr/sbin, /sbin, /bin/false)"
else
  note_ok "login shell for service user: $NOLOGIN"
fi

# systemd. Not universal -- Alpine uses OpenRC, Void uses runit, and
# containers often have no init at all. The tool works fine either way; only
# the scheduling mechanism changes.
HAVE_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  HAVE_SYSTEMD=1
  note_ok "systemd detected"
else
  note_warn "systemd not detected. The timer will be skipped; this script will
           print a cron line to use instead."
fi

# SELinux. This is the one that silently breaks the integration on RHEL-family
# distros: file permissions can be perfectly correct and httpd will still be
# denied read access because of the security context, with nothing obvious in
# the MISP logs to explain it.
SELINUX_ENFORCING=0
if command -v getenforce >/dev/null 2>&1; then
  SELINUX_STATE="$(getenforce 2>/dev/null || echo Unknown)"
  if [[ "$SELINUX_STATE" == "Enforcing" ]]; then
    SELINUX_ENFORCING=1
    if command -v chcon >/dev/null 2>&1; then
      note_ok "SELinux enforcing; will label the feed directory for httpd"
    else
      note_warn "SELinux is enforcing but chcon is missing. Install
           policycoreutils, or MISP will be denied read access to the feed."
    fi
  else
    note_ok "SELinux $SELINUX_STATE"
  fi
fi

# Outbound access to the feed host.
#
# Only transport-level failures matter here. The bare root of the download
# service legitimately returns 404 -- it expects /domainer/{gtld,cctld} plus an
# API key -- so an HTTP error status proves the host is reachable rather than
# the opposite. Checking with `curl -f` (which rejects any 4xx) made this warn
# on every healthy install.
if command -v curl >/dev/null 2>&1; then
  set +e
  HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 \
    "https://files.whoisfreaks.com" 2>/dev/null)
  CURL_RC=$?
  set -e
  case "$CURL_RC" in
    0)
      note_ok "reached files.whoisfreaks.com (HTTP $HTTP_CODE)"
      ;;
    6)
      note_warn "cannot resolve files.whoisfreaks.com. Check DNS
           (/etc/resolv.conf) before the first fetch."
      ;;
    7)
      note_warn "cannot connect to files.whoisfreaks.com. Check firewall or
           proxy rules for outbound HTTPS."
      ;;
    28)
      note_warn "timed out reaching files.whoisfreaks.com. Slow link, or
           traffic is being silently dropped."
      ;;
    35|60)
      note_warn "TLS problem reaching files.whoisfreaks.com (curl $CURL_RC).
           Usually a TLS-inspecting proxy or a missing CA bundle."
      ;;
    *)
      note_warn "connectivity check inconclusive (curl exit $CURL_RC).
           Not fatal; verify with the first --dry-run fetch."
      ;;
  esac
else
  note_warn "curl not found; skipping the connectivity check"
fi

# Disk. A 7-day gtld+ccTLD window is ~1 GB across cache + feed; 30 days ~4 GB.
AVAIL_MB=$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}')
if [[ -n "${AVAIL_MB:-}" ]]; then
  if (( AVAIL_MB < 2048 )); then
    note_warn "only ${AVAIL_MB} MB free on /var. A 7-day window needs ~1 GB,
           30 days ~4 GB. Consider a smaller window or another path."
  else
    note_ok "${AVAIL_MB} MB free on /var"
  fi
fi

# MISP itself is NOT required for this to install or run -- this tool only
# writes files to disk. But if MISP is not on this host, the feed has to be
# served over HTTP instead of registered as a Local feed, so say so plainly.
MISP_FOUND=0
for candidate in /var/www/MISP /var/www/html/MISP /opt/MISP; do
  if [[ -d "$candidate" ]]; then
    MISP_FOUND=1
    note_ok "found a MISP install at $candidate"
    break
  fi
done
if [[ $MISP_FOUND -eq 0 ]]; then
  note_warn "no local MISP install detected. That is fine -- this tool never
           talks to MISP and will install and run regardless. But a Local
           feed needs the files on MISP's own filesystem, so either:
             - install MISP on this host, or
             - serve $FEED_DIR over HTTP and add it as a Network feed.
           See the Prerequisites section of README.md."
fi

if [[ $FATAL -ne 0 ]]; then
  echo >&2
  echo "Preflight failed. Nothing has been changed on this system." >&2
  exit 1
fi

echo "==> Creating service user and directories"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  run "useradd --system --no-create-home --shell $NOLOGIN $SERVICE_USER"
else
  echo "  service user $SERVICE_USER already exists"
fi

run "mkdir -p $PREFIX $CONFIG_DIR $CACHE_DIR $FEED_DIR"

echo "==> Installing source to $PREFIX"
run "cp -r '$REPO_DIR/src' $PREFIX/"
run "cp '$REPO_DIR/requirements.txt' $PREFIX/"
run "find $PREFIX -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"

echo "==> Creating virtualenv"
if [[ ! -x $PREFIX/venv/bin/python ]]; then
  run "python3 -m venv $PREFIX/venv"
fi
run "$PREFIX/venv/bin/pip install --quiet --upgrade pip"
run "$PREFIX/venv/bin/pip install --quiet -r $PREFIX/requirements.txt"

echo "==> Installing $BIN"
if [[ $DRY_RUN -eq 1 ]]; then
  echo "  + write launcher to $BIN"
else
  cat > "$BIN" <<LAUNCHER
#!/usr/bin/env bash
cd $PREFIX
exec $PREFIX/venv/bin/python -m src.main "\$@"
LAUNCHER
  chmod 755 "$BIN"
fi

echo "==> Installing config"
if [[ -f $CONFIG_DIR/config.ini ]]; then
  echo "  $CONFIG_DIR/config.ini exists; keeping your settings"
  # A 600 config looks more secure but locks out the service user, which reads
  # it via the group. Repair the mode without touching the contents.
  CUR_MODE=$(stat -c '%a' "$CONFIG_DIR/config.ini" 2>/dev/null || echo "")
  if [[ "$CUR_MODE" == "600" ]]; then
    echo "  fixing mode 600 -> 640 so $SERVICE_USER can read it"
    run "chmod 640 $CONFIG_DIR/config.ini"
    run "chown root:$SERVICE_USER $CONFIG_DIR/config.ini"
  fi
  run "cp '$REPO_DIR/config/config.ini.example' $CONFIG_DIR/config.ini.example"
else
  run "cp '$REPO_DIR/config/config.ini.example' $CONFIG_DIR/config.ini"
  # 640, not 600: the file is owned by root but READ by the service user via
  # the group. Mode 600 grants the owner only, which locks out misp-nrd and
  # surfaces as a confusing "No API key" error.
  run "chmod 640 $CONFIG_DIR/config.ini"
  run "chown root:$SERVICE_USER $CONFIG_DIR/config.ini"
fi

echo "==> Setting ownership"
run "chown -R $SERVICE_USER:$SERVICE_USER $CACHE_DIR $FEED_DIR"
run "chown -R root:$SERVICE_USER $CONFIG_DIR"
run "chmod 750 $CONFIG_DIR"
# MISP's web user must be able to read the feed directory. Which user that is
# depends on the distribution: www-data on Debian/Ubuntu, apache on RHEL-family,
# or uid 33 inside a misp-docker container.
run "chmod 755 $FEED_DIR"
run "chmod 755 /var/lib/misp-nrd-feed"

if [[ $SELINUX_ENFORCING -eq 1 ]] && command -v chcon >/dev/null 2>&1; then
  echo "==> Applying SELinux labels"
  # Without httpd_sys_content_t, httpd is denied read access regardless of
  # POSIX permissions -- the feed loads 0 events and nothing explains why.
  run "chcon -R -t httpd_sys_content_t $FEED_DIR"
  if command -v semanage >/dev/null 2>&1; then
    # chcon alone does not survive a filesystem relabel; semanage makes it stick.
    run "semanage fcontext -a -t httpd_sys_content_t '${FEED_DIR}(/.*)?' 2>/dev/null || true"
    run "restorecon -R $FEED_DIR"
  else
    echo "  NOTE: semanage not found (install policycoreutils-python-utils)."
    echo "        The chcon label above will not survive a relabel."
  fi
fi

if [[ $HAVE_SYSTEMD -eq 1 ]]; then
  echo "==> Verifying the service user can read its config"
if [[ $DRY_RUN -eq 0 ]]; then
  if runuser -u "$SERVICE_USER" -- test -r "$CONFIG_DIR/config.ini" 2>/dev/null \
     || su -s /bin/sh -c "test -r $CONFIG_DIR/config.ini" "$SERVICE_USER" 2>/dev/null; then
    echo "  [ ok ] $SERVICE_USER can read $CONFIG_DIR/config.ini"
  else
    echo "  [FAIL] $SERVICE_USER cannot read $CONFIG_DIR/config.ini" >&2
    echo "         sudo chmod 640 $CONFIG_DIR/config.ini" >&2
    echo "         sudo chown root:$SERVICE_USER $CONFIG_DIR/config.ini" >&2
    exit 1
  fi
else
  echo "  + verify $SERVICE_USER can read $CONFIG_DIR/config.ini"
fi

echo "==> Installing systemd units"
  run "cp '$REPO_DIR/systemd/misp-nrd-feed.service' /etc/systemd/system/"
  run "cp '$REPO_DIR/systemd/misp-nrd-feed.timer' /etc/systemd/system/"
  run "systemctl daemon-reload"
  run "systemctl enable misp-nrd-feed.timer"
else
  echo "==> Skipping systemd units (no systemd on this host)"
fi

if [[ $HAVE_SYSTEMD -eq 1 ]]; then
  SCHEDULE_HELP="       sudo systemctl start misp-nrd-feed.timer
       systemctl list-timers misp-nrd-feed.timer"
else
  SCHEDULE_HELP="       No systemd here, so add a cron entry instead:
       sudo crontab -u $SERVICE_USER -e
       30 20 * * *  $BIN"
fi

cat <<NEXT

Installed.

Next steps, in order:

  1. Add your API key:
       sudo nano $CONFIG_DIR/config.ini      # set api_key

  2. Generate your own UUID namespace (do this once, now, not later):
       uuidgen
       sudo nano $CONFIG_DIR/config.ini      # set uuid_namespace

  3. Dry run, then a real backfill:
       sudo -u $SERVICE_USER misp-nrd-feed --dry-run
       sudo -u $SERVICE_USER misp-nrd-feed --backfill

  4. Schedule it:
$SCHEDULE_HELP

  5. Add the feed in MISP:
       Sync Actions -> List Feeds -> Add Feed
         Input Source:   Local
         URL:            $FEED_DIR          # the DIRECTORY, not manifest.json
         Source Format:  MISP Feed
         Enabled:        yes
         Caching:        yes
       Then: Fetch and store all feed data.

NEXT