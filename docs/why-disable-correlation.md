# Why this feed ships with `disable_correlation = true`

Short version: correlation is where MISP instances fall over under a
high-volume feed, and for newly registered domains the correlations you'd get
are almost all noise. If you turn it on, do it deliberately and with a smaller
window.

## The arithmetic

WhoisFreaks publishes on the order of 200,000 new domains a day across gTLD
and ccTLD combined. A window multiplies that:

| Window | Domains in the feed |
|--------|--------------------|
| 7 days | ~1.4 million |
| 14 days | ~2.8 million |
| 30 days | ~6 million |

Those are per-pass figures. If you ingest as events rather than only caching,
MISP does not remove events that age out of the manifest, so the real total keeps
climbing — see the Retention section of the README. Cache mode is bounded by the
window; fetch mode is not.

Every correlating attribute MISP ingests gets compared against every other
correlating attribute already in the database, and matches are written to a
correlation table. The cost is not linear in the number of new attributes —
it scales with new attributes multiplied by the size of the existing corpus.

On a modest instance that already holds a few hundred thousand attributes,
adding six million correlating domains means a correlation table larger than
the rest of the database put together, an ingest that takes hours instead of
minutes, and event views that time out because rendering them means reading
that table.

## The signal problem

Set aside performance for a moment: what would those correlations actually
tell you?

A correlation fires when the same value appears in two places. If
`suspicious-thing.com` is in your NRD feed and also in a phishing event
someone shared, that's a genuinely useful hit — and you still get it, because
**`disable_correlation` does not disable feed lookups**. What it disables is
this feed's attributes participating in the correlation *graph*.

What you lose is mostly self-correlation: 6 million domains that correlate
with each other only in the sense that they were all registered recently. That
is a property of the feed, not a relationship between the domains. It clutters
every event view with matches that mean "this is also a new domain," which you
already knew, because that's why it's in the feed.

## What you keep

With `disable_correlation = true` and `to_ids = false`, the feed still does the
job it's here for:

- **Feed lookups / caching.** With *Caching enabled* ticked on the feed in
  MISP, an analyst looking at any domain attribute sees whether it appears in
  this feed, and in which day's event. That is the "how old is this domain"
  answer, delivered at the point of triage.
- **Search and API.** The attributes are real attributes. `/attributes/restSearch`
  finds them, so your SOAR playbooks and enrichment scripts can ask "is this
  domain in the NRD window" without a separate API call to WhoisFreaks.
- **The freshness signal.** Each domain sits in the event for the day it was
  registered, so the event date *is* the registration date. Age is a
  subtraction, not a lookup.

## When to turn it on

There is a legitimate case for correlation: a small window, treated as a
detection feed rather than a reference set.

```ini
[retention]
days = 3

[misp]
disable_correlation = false
```

Three days of gTLD only is on the order of 150,000 attributes — a size where
correlation is affordable and where a hit genuinely means something, because a
domain registered in the last 72 hours that also appears in one of your events
is worth a look.

If you go this route:

1. Change one thing at a time. Shrink the window first, run for a week,
   then enable correlation.
2. Watch `SELECT COUNT(*) FROM default_correlations;` before and after.
3. Have a rollback ready. Re-running with `disable_correlation = true` writes
   corrected attributes, but MISP will need to re-ingest the window for the
   change to take effect — `--force` plus a feed re-fetch.

## `to_ids` is a separate decision

`to_ids = false` is about export, not correlation. MISP generates IDS
rulesets (Suricata, Snort, Bro/Zeek) from attributes where `to_ids` is true.
Flipping it here would push ~200,000 domain rules per day into those exports,
which no sensor wants — and if you actually want NRD detection in an IDS,
[`wf-suricata-nrd-feed`](https://github.com/WhoisFreaks/wf-suricata-nrd-feed)
and [`wf-zeek-nrd-feed`](https://github.com/WhoisFreaks/wf-zeek-nrd-feed) do
it natively with a dataset and the Intel framework respectively, which is far
cheaper than routing it through MISP.

Pick the tool that matches the surface: MISP for analyst context, Suricata or
Zeek for wire detection, BIND 9 RPZ or Pi-hole for blocking.