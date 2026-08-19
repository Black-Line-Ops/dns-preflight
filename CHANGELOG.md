# Changelog

## [0.1.0] — 2026-08-19

First cut. Read-only, zero dependencies, Node 18+.

### Added

- `preflight.mjs` — the report. Verdict (GO / GO, WITH CARE / NO-GO), a "will break" list with
  the fix spelled out step by step, what it could not see, and optional `--zone` / `--json`.
- Three blocker rules, chosen because each is SILENT: DNSSEC active at the parent (takes the
  whole domain dark, mail included), an MX target inside the zone being moved (mail dies while
  the website looks perfect), and a registrar lock or expiry inside 30 days (stops the change on
  the day). Plus warnings for long TTLs and missing SPF.
- DNS over HTTPS rather than `dig` or `node:dns`. No `dig` on Windows, and the system resolver on
  a corporate laptop or VPN is a resolver that may lie — a pre-flight that reads the wrong zone is
  worse than none. DoH is also all HTTPS/443, so it works on networks that block UDP/53.
- RDAP for registrar, expiry and lock status.

### Notes on what it deliberately does not do

- **It cannot enumerate a zone**, and says so on every report and in every exported zone file.
  `ANY` is refused (`Status 4 / EDE(21) Not Supported`, measured) and `AXFR` is refused
  everywhere, so it probes a known list of ~38 names. A tool that presented a partial dump as
  complete would lose exactly the records that carry mail.
- **No write verbs and no credentials.** A tool holding no token cannot be talked into changing
  a client's DNS.
- `.io` and `.co` have no IANA RDAP bootstrap entry, so registrar/expiry/lock come back
  **unknown** rather than "no lock found" — absence of data must never render as reassurance.

### Fixed before it ever shipped

- **RDAP lock detection missed the RFC form.** RFC 9083 specifies status values as space-separated
  words (`"client transfer prohibited"`); EPP and many RDAP mirrors use camelCase
  (`clientTransferProhibited`). Matching only camelCase reported a genuinely locked domain as
  unlocked — the exact false reassurance this tool exists to prevent. Caught by a test built from
  a real response shape, and confirmed against a live registrar: `blacklineops.ai` returns the
  space-separated form and IS locked.
