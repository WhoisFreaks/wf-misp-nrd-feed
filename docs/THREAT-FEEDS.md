# Adding the Domain Threat Feeds

The NRD feed answers *how old is this domain*. The
[Domain Threat Feeds](https://whoisfreaks.com/products/threat-intelligence-feed)
answer a different question: *has this domain been observed doing something
bad*. This integration can publish both.

They are separate WhoisFreaks products, so the threat feeds are **off by
default**. Enable them and you get a second MISP feed alongside the NRD one.

---

## Why not all newly registered domains are threats

Worth being blunt about, because it is the most common way NRD data gets
misused: **the overwhelming majority of newly registered domains are
completely legitimate.** Businesses launch, people start blogs, campaigns get
microsites, companies rebrand. Roughly 200,000 domains are registered every
day and only a small fraction of them will ever be used maliciously.

That is exactly why the NRD feed ships with `to_ids: false` and
`disable_correlation: true`. Age is *context* — a reason to look closer, never a
verdict. Treat "new" as "bad" and you will block your customer's rebrand and a
conference microsite in the same afternoon.

The threat feeds are the other half of that picture. Where NRD tells you a
domain is young, these tell you a domain has been observed hosting credential
theft pages, distributing malware, or feeding spam networks. That *is* a
verdict, and it earns the settings that come with one.

Running both gives an analyst two independent signals on the same screen: this
domain is four days old, **and** it appears in the phishing feed. Either alone
is weaker than the pair.

---

## The three feeds

All three share one CSV schema, so one parser handles all of them.

| Feed | What it flags | MISP threat level |
|---|---|---|
| [Phishing](https://whoisfreaks.com/documentation/threat-intelligence-feed#phishing-domain-feed) | credential theft pages, brand impersonation | 2 — Medium |
| [Malware](https://whoisfreaks.com/documentation/threat-intelligence-feed#malware-domain-feed) | payload distribution, infected downloaders | 1 — High |
| [Spam](https://whoisfreaks.com/documentation/threat-intelligence-feed#spam-domain-feed) | bulk senders, spam link networks | 3 — Low |

Each row carries `domain`, `threat_type`, `confidence` (0–1), `first_seen`,
`last_seen`, and `No_of_threat_matched_pivots` — the number of shared
infrastructure attributes (registrant email, phone, organisation, NS, MX,
CNAME) that linked the domain to a confirmed seed. That pivot count is why the
feeds surface related domains before they reach public blocklists.

Files arrive **gzipped** (`application/gzip`, containing e.g.
`sample_malware_domains.csv`). You can inspect the shape without an API key:

```bash
curl -s https://files.whoisfreaks.com/v3.4/download/threat-feed/malware/sample | zcat | head -3
```

```
domain,threat_type,confidence,first_seen,last_seen,No_of_threat_matched_pivots
00000001gogoli.info,malware,1.0,2026-06-25 13:45:40.258478+00,2026-07-21 00:16:14.99156+00,0
00000.hikvision-cctv.su,malware,1.0,2026-06-25 13:45:00.511284+00,2026-08-25 00:15:24.476354+00,0
```

Two details from the real data that the tool handles for you.

**Timestamps are normalised.** The feed emits a space separator, a bare `+00`
offset, and a fractional part of whatever length the database produced (five
digits above). MISP wants ISO-8601, and Python 3.9's `fromisoformat` rejects
both quirks, so `first_seen`/`last_seen` are rewritten to
`2026-07-21T00:16:14.991560+00:00` before they reach MISP.

**Subdomains become `hostname`, not `domain`.** A large share of these feeds is
subdomains on shared hosts — 114 of the 300 sample rows, mostly `weebly.com` and
similar. MISP treats apex domains and hostnames as different attribute types, so
typing `x.weebly.com` as `domain` would be wrong and would mislead anything
filtering by type. Label-counting cannot make the call (`012.net.il` has two dots
and *is* an apex; `x.weebly.com` has two dots and is not), so the tool uses
[`tldextract`](https://pypi.org/project/tldextract/) when it is installed and a
bundled subset of multi-label public suffixes otherwise. Installing `tldextract`
is optional and improves accuracy on unusual TLDs.

Note that every row in the current samples has `confidence` of `1.0`, so
`min_confidence` is effectively a no-op today. It exists for when the feeds start
emitting graded scores.

---

## The settings are the inverse of the NRD feed's

This is the part to understand before enabling anything.

| | NRD feed | Threat feeds |
|---|---|---|
| The data means | this domain is new | this domain was observed being malicious |
| Semantics | context | verdict |
| `to_ids` | `false` | **`true`** |
| `disable_correlation` | `true` | **`false`** |
| MISP *Disable correlation* | **ticked** | **unticked** |
| Volume | ~374k/day | far smaller |
| Recommended mode | cache-only | fetch |

Both inversions are deliberate.

**`to_ids: true`** because you *want* these exported into IDS rulesets. That
would be absurd for 374,000 new domains a day; it is exactly right for a
curated list of domains seen serving malware.

**Correlation enabled** because a threat-feed domain matching an attribute in
one of your events is the single most valuable thing MISP can tell you. For NRD
data, correlations are mostly noise — millions of domains matching each other
for the sole reason that they are all new. Here, a match means an indicator you
already hold has been independently flagged. Volume makes it affordable: these
feeds are orders of magnitude smaller than the NRD window.

### Which forces two separate MISP feeds

*Disable correlation* is a **per-feed** setting in MISP. The NRD feed needs it
ticked and the threat feeds need it unticked, so they cannot be the same feed,
which means they cannot share a directory. The tool enforces this — pointing
both at one path is a configuration error.

---

## Enable it

```ini
[threat]
enabled = true

; Different API version and path segment from the NRD download service
; (/v3.1/download/domainer). Override only if your tier differs.
base_url = https://files.whoisfreaks.com/v3.4/download/threat-feed

types = phishing, malware, spam

; Defaults to a sibling of the NRD feed directory. Must not equal it.
; output_dir = /var/lib/misp-nrd-feed/threat-feed

; Drop rows below this confidence (0–1). 0 keeps everything.
min_confidence = 0.0

; The inverse of the NRD settings, on purpose. See above.
to_ids = true
disable_correlation = false

; A flagged domain does not stop being flagged, so unlike the NRD window there
; is nothing to age out. 0 keeps every day.
retention_days = 0
```

Or for a single run, without touching config:

```bash
sudo -u misp-nrd misp-nrd-feed --threat
sudo -u misp-nrd misp-nrd-feed --threat-only --threat-types phishing,malware
```

### Delivery model differs from NRD

The threat API returns a **full dump** when no date is passed, and a **daily
delta** of new and changed rows when one is. So the first run per feed
bootstraps from a full dump and every run afterwards pulls one small delta.
The tool handles that automatically — it takes a baseline the first time and
deltas thereafter, and reconstructs current state by replaying the baseline plus
every delta in order.

One consequence worth knowing: attribute UUIDs for threat domains are **not**
date-scoped, unlike NRD attributes. A flagged domain is one indicator no matter
which delta first carried it, so when it reappears in a later delta MISP updates
the existing attribute rather than creating a second one.

---

## Register the second feed in MISP

*Sync Actions → List Feeds → Add Feed*, exactly as for the NRD feed, with three
differences:

| Field | Value |
|---|---|
| Name | `WhoisFreaks Domain Threat Feeds` |
| URL | the **threat** directory (e.g. `/nrd-threat-feed` in a container) |
| **Disable correlation** | **unticked** ← the important one |
| Caching enabled | ✔ |
| Enabled | ✔ |
| Source Format | MISP Feed |
| Input Source | Local |

If you run MISP in Docker, add a second mount:

```yaml
services:
  misp-core:
    volumes:
      - "/var/lib/misp-nrd-feed/feed:/nrd-feed:ro"
      - "/var/lib/misp-nrd-feed/threat-feed:/nrd-threat-feed:ro"
```

On RHEL-family hosts append `,z` to both, as in the main setup guide.

### Fetch here, unlike NRD

For the NRD feed, cache-only is recommended: you want the lookup, not millions
of attributes. For the threat feeds, **fetch** is usually right. The volume is
manageable, and attributes as real objects are the point — you want to search
them, tag them, pivot on them, and export them to IDS rulesets. None of that
works from the cache alone.

Caching them as well is reasonable and cheap.

---

## Verifying

```bash
sudo -u misp-nrd misp-nrd-feed --threat-only --log-level INFO
ls -l /var/lib/misp-nrd-feed/threat-feed/
```

One event per threat type per day, named
`WhoisFreaks Threat Feed: Phishing domains - 2026-08-17 (N domains)`.

After fetching in MISP, an attribute from the feed should show `to_ids` set and
should appear in correlations if the same domain exists elsewhere in your
instance — which is the behaviour the NRD feed deliberately suppresses.