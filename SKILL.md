---
name: dns-preflight
description: >
  Check what will BREAK before repointing a domain's nameservers or migrating its DNS. Reads the
  live zone over DNS-over-HTTPS plus RDAP and answers the question nobody else answers — not
  "what are my records" but "if I move this today, what stops working?" Catches the three
  failures that silently take a business offline: DNSSEC left enabled at the registrar (which
  takes the whole domain dark, mail included), an MX target that lives inside the zone being
  moved (inbound mail dies while the website looks perfect), and a registrar lock or imminent
  expiry that stops the change on the day. Read-only — no credentials, no API keys, no account,
  nothing is ever written. Use whenever someone is changing nameservers, moving DNS to
  Cloudflare, transferring a domain, taking over a client's website, migrating hosting, or asks
  "is it safe to point this at the new site".
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, AskUserQuestion, WebFetch
---

# dns-preflight

One question, answered properly: **if this domain were repointed today, what would break?**

Every DNS lookup tool dumps records. That is not the problem. The problem is that a migration
looks fine right up until the part that was never visible — and the part that was never visible
is almost always email.

```bash
node "$SKILL/scripts/preflight.mjs" theirdomain.com
```

Read-only. Public DNS over HTTPS and one RDAP call. No credentials, no API key, no account, and
**no write path anywhere in the tool** — a tool that holds no token cannot be talked into taking
a client's mail down.

## The three things it is really looking for

Each one is silent. The website keeps working, so nothing looks wrong, and the thing that
actually broke is discovered days later by a customer who never got a reply.

**DNSSEC left on at the registrar.** If the parent zone publishes a DS record and you change
nameservers, every validating resolver rejects the new answers. That is the site *and* the mail,
at once, with a SERVFAIL symptom that looks like an outage rather than a misconfiguration and
gets misdiagnosed as propagation for hours. The report prints the **real DS TTL** as the wait,
because it is knowable — not the usual "24 to 48 hours", which is unfalsifiable and usually wrong.

**An MX target inside the zone you are moving.** The classic shared-hosting shape: MX points at
`mail.theirdomain.com`, which is an A record *inside* the zone. Move the nameservers and that
name stops existing unless somebody recreated it. Mail stops; the website is perfect. The report
names the host **and the address to recreate it as**, because "recreate mail.example.com" without
the address has moved the problem rather than solved it.

**A registrar lock, or an expiry inside 30 days.** Neither breaks anything by itself. Both stop
the change from being possible, on the day, after everything else has been arranged.

## What it cannot do, and says so on every report

**A zone cannot be enumerated from outside it.** `ANY` is refused (Cloudflare answers
`Status 4 / EDE(21) Not Supported`) and `AXFR` is refused everywhere. There is no other
mechanism.

So this probes a **known list** of ~38 names — the apex, `www`, `mail`, `autodiscover`, `smtp`,
`_dmarc`, the common DKIM selectors, and the handful of hostnames a small site actually uses —
and reports what it found. It never claims to have read the zone.

That limit is printed at the bottom of every report and again in the header of every exported
zone file, because the dangerous version of this tool is one that looks complete. **Always export
the real zone from the losing provider if you can, and use this to check that export for gaps** —
that is the job it is best at.

## Using it

```bash
node "$SKILL/scripts/preflight.mjs" theirdomain.com                 # the report
node "$SKILL/scripts/preflight.mjs" theirdomain.com --zone zone.txt # + a BIND file (partial!)
node "$SKILL/scripts/preflight.mjs" theirdomain.com --json r.json   # + machine-readable
node "$SKILL/scripts/preflight.mjs" theirdomain.com --strict        # non-zero exit on a blocker
```

`--strict` is opt-in for a reason: this is a report, and a report that fails by default teaches
people to stop running it.

### Reading the verdict

- **GO** — nothing found that would break on a repoint. Still export the real zone first.
- **GO, WITH CARE** — no blockers, but read the findings. Usually long TTLs or a missing SPF.
- **NO-GO** — a blocker is live. Fix it before touching nameservers.

### When to run it

- Before quoting a website rebuild, so "and we'll move your DNS" is priced with the DNSSEC
  and mail work in it rather than discovered afterwards.
- Before every cutover, on the morning of.
- When taking over a client from another agency — it tells you what you have inherited before
  you are responsible for it.
- After the move, to confirm the new zone actually carries what the old one did.

## For the agent driving this

**Run it before you offer an opinion about a migration.** A live lookup on the actual domain
beats any general advice about DNS, and it takes three seconds.

**Read the findings out in plain language.** The person you are talking to may not know what a DS
record is, and does not need to. "Your domain has a security setting switched on that has to be
turned off at GoDaddy first, or the whole thing goes dark for a day" is the useful sentence.

**Never present the zone file as complete.** It is not, it cannot be, and the records it could not
see are exactly the ones that carry mail. Say "here is what I could see from outside" every time.

**If mail is involved, say so first.** The website is what people ask about; the mail is what ends
the relationship.

Companion skill: `scroll-scrub-hero` and `scroll-flight` build the site. This one makes sure
pointing the domain at it does not take the client's email down on the way.
