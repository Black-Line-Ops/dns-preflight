# dns-preflight

**What breaks if you repoint this domain today?**

Every DNS tool dumps records. That has never been the problem. The problem is that a migration
looks fine right up until the part nobody could see — and the part nobody could see is almost
always email.

```bash
node scripts/preflight.mjs theirdomain.com
```

```
dns-preflight  blacklineops.ai

  ================================================================
  NO-GO — fix the blockers below before touching nameservers
  ================================================================

  Where it lives now
    nameservers   daphne.ns.cloudflare.com, rick.ns.cloudflare.com
    registrar     GoDaddy.com, LLC
    expires       2028-02-27
    mail          mx1-usg2.ppe-hosted.com, smtp.google.com
    DNSSEC        not enabled
    records found 22 across 38 probed names

  [WILL BREAK] The domain is locked at the registrar
    Status: client delete prohibited, client renew prohibited, client transfer
    prohibited, client update prohibited. The registrar will refuse a nameserver
    or transfer change while this is set.
      -> Unlock it in the registrar control panel first.
```

**Read-only.** Public DNS over HTTPS and one RDAP call. No credentials, no API key, no account,
and no write path anywhere in the tool — something holding no token cannot be talked into taking
a client's mail down.

**Zero dependencies.** Node 18+ and nothing else. No `dig`, no `whois`, no `npm install`.

---

## The three things it is really looking for

Each one is **silent**. The website keeps working, so nothing looks wrong, and what actually
broke is discovered days later by a customer who never got a reply.

### 1. DNSSEC left on at the registrar

If the parent zone publishes a DS record and you change nameservers, every validating resolver
rejects the new answers. That is the site *and* the mail, at once, with a SERVFAIL symptom that
reads as an outage rather than a misconfiguration — and gets misdiagnosed as propagation for
hours.

The report prints the **real DS TTL** as the wait, because it is knowable. Not the usual
"24 to 48 hours", which is unfalsifiable and usually wrong.

### 2. An MX target inside the zone you are moving

The classic shared-hosting shape: MX points at `mail.theirdomain.com`, which is an A record
*inside* the zone. Move the nameservers and that name stops existing unless somebody recreated
it. Mail stops. The website is perfect, which is exactly why nobody notices.

The report names the host **and the address to recreate it as** — "recreate mail.example.com"
without the address has moved the problem, not solved it.

### 3. A registrar lock, or an expiry inside 30 days

Neither breaks anything by itself. Both stop the change from being possible, on the day, after
everything else has been arranged.

Plus warnings for long TTLs (how long a mistake stays wrong) and a missing SPF record on a domain
that receives mail (not caused by the migration, but it will be blamed on it).

---

## What it cannot do, and says so on every report

**A zone cannot be enumerated from outside it.** `ANY` is refused — Cloudflare answers
`Status 4 / EDE(21) Not Supported` — and `AXFR` is refused everywhere. There is no other
mechanism.

So this probes a **known list** of ~38 names: the apex, `www`, `mail`, `autodiscover`, `smtp`,
`_dmarc`, the common DKIM selectors, and the handful of hostnames a small site actually uses. It
reports what it found and never claims to have read the zone.

That limit is printed at the bottom of every report, and again in the header of every exported
zone file, because the dangerous version of this tool is one that looks complete.

> **Always export the real zone from the losing provider if you can, and use this to check that
> export for gaps.** That is the job it is best at.

---

## Usage

```bash
node scripts/preflight.mjs theirdomain.com                 # the report
node scripts/preflight.mjs theirdomain.com --zone zone.txt # + a BIND file (partial — read its header)
node scripts/preflight.mjs theirdomain.com --json r.json   # + machine-readable
node scripts/preflight.mjs theirdomain.com --strict        # non-zero exit on a blocker, for CI
node scripts/preflight.mjs theirdomain.com --quiet         # only the files, no console output
```

`--strict` is opt-in on purpose: this is a report, and a report that fails by default teaches
people to stop running it.

### The verdict line

| | |
|---|---|
| **GO** | Nothing found that would break on a repoint. Still export the real zone first. |
| **GO, WITH CARE** | No blockers, but read the findings. Usually long TTLs or a missing SPF. |
| **NO-GO** | A blocker is live. Fix it before touching nameservers. |

### When to run it

- **Before quoting a rebuild**, so "and we'll move your DNS" is priced with the DNSSEC and mail
  work in it rather than discovered afterwards.
- **On the morning of every cutover.**
- **When taking over a client from another agency** — it tells you what you have inherited before
  you are responsible for it.
- **After the move**, to confirm the new zone carries what the old one did.

---

## Why DoH rather than `dig` or `node:dns`

`dig` is not on Windows and never will be. But the real reason is the resolver.

`node:dns` talks to whatever resolver the machine happens to be using, and on a corporate laptop,
a VPN, or a router doing "DNS optimisation", that is a resolver which lies. A pre-flight that
reads the wrong zone because the office router served a stale answer is **worse than no
pre-flight** — it produces a confident report about a domain nobody else can see.

DNS-over-HTTPS goes to a named public resolver over 443, which also means it works on the hotel
and guest wifi where emergency migrations actually happen.

---

## Known gaps

- **`.io` and `.co` have no IANA RDAP bootstrap entry**, so registrar, expiry and lock status come
  back **unknown** for them. The report says "unknown", never "no lock found" — absence of data
  must not read as reassurance.
- **The probe list is the coverage.** A record on an unusual hostname is invisible here.
- **It reads; it never writes.** By design, permanently.

## Tests

```bash
npm test
```

21 tests, all offline. Every DNS answer and RDAP response is a stub — a DNS tool whose tests need
DNS is flaky in exactly the conditions it exists to diagnose.

## Companion skills

`scroll-scrub-hero` and `scroll-flight` build the site. This one makes sure pointing the domain at
it does not take the client's email down on the way.

---

MIT © 2026 Black Line Ops, LLC
