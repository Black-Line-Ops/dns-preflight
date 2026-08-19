/* dns-preflight: what breaks if you repoint this domain today.
   Read-only. No credentials, no writes, no account anywhere. */
import fs from 'node:fs'
import path from 'node:path'
import { makeResolver, rdap, TYPE, TYPE_NAME, COMMON_NAMES, POLICY_NAMES, LookupError } from './dns.mjs'
import { judge, toZoneFile } from './verdict.mjs'

function args (argv = process.argv.slice(2)) {
  const o = {}
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i]
    if (!t.startsWith('--')) { if (!o._) o._ = t; continue }
    const eq = t.indexOf('=')
    if (eq !== -1) { o[t.slice(2, eq)] = t.slice(eq + 1); continue }
    const k = t.slice(2)
    o[k] = (i + 1 < argv.length && !argv[i + 1].startsWith('--')) ? argv[++i] : true
  }
  return o
}

const a = args()
const domain = String(a.domain || a._ || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '')
if (!domain || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) {
  console.error('usage: node preflight.mjs <domain>  [--json report.json] [--zone zone.txt] [--strict] [--quiet]\n')
  console.error('  Reports what would break if this domain were repointed to new nameservers today.')
  console.error('  Read-only: public DNS and RDAP lookups. No credentials, no account, nothing is changed.\n')
  console.error('  --strict   exit non-zero when a blocker is found (for CI)')
  console.error('  --zone F   write the observed records as a BIND-format file')
  console.error('  --json F   write the whole report as JSON')
  process.exit(1)
}

const quiet = !!a.quiet
const say = (...m) => { if (!quiet) console.log(...m) }
const resolve = makeResolver()

/* Batched with a small concurrency cap. Neither Cloudflare nor Google documents a rate limit for
   this endpoint, and a ~150-query sweep from one IP is exactly the shape that gets an undocumented
   one enforced. Six at a time finishes a sweep in a couple of seconds and stays polite. */
async function pool (items, worker, limit = 6) {
  const out = []
  let i = 0
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++
      out[idx] = await worker(items[idx], idx)
    }
  }))
  return out
}

const soft = (p) => p.then(v => v, (e) => ({ error: e instanceof LookupError ? e.message : String(e) }))
const ok = (r) => r && !r.error && !r.nxdomain && r.answers && r.answers.length

say(`\ndns-preflight  ${domain}\n`)
say('  Reading public DNS and RDAP. Nothing is changed, and no credentials are used.')

/* ---------- the apex, and the three things that decide the verdict ---------- */
const [ns, soa, ds, mx, apexA, apexAAAA, apexTxt, caa, whois] = await Promise.all([
  soft(resolve(domain, 'NS')), soft(resolve(domain, 'SOA')), soft(resolve(domain, 'DS')),
  soft(resolve(domain, 'MX')), soft(resolve(domain, 'A')), soft(resolve(domain, 'AAAA')),
  soft(resolve(domain, 'TXT')), soft(resolve(domain, 'CAA')),
  rdap(domain),
])

/* MX targets get resolved because the blocker rule needs to know whether they live inside the
   zone AND what to recreate them as. A rule that says "recreate mail.example.com" without the
   address it currently points at has moved the problem, not solved it. */
const mxHosts = ok(mx)
  ? [...new Set(mx.answers.map(r => String(r.data).split(/\s+/).pop().replace(/\.$/, '').toLowerCase()))]
  : []
const mxTargetList = await pool(mxHosts, async (h) => [h, await soft(resolve(h, 'A'))])
const mxTargets = Object.fromEntries(mxTargetList)

/* ---------- the sweep: a KNOWN LIST, never a zone dump ---------- */
const probes = []
for (const label of COMMON_NAMES) {
  const fqdn = label ? `${label}.${domain}` : domain
  probes.push([fqdn, 'A'], [fqdn, 'CNAME'])
}
for (const label of POLICY_NAMES) probes.push([`${label}.${domain}`, 'TXT'])

const swept = await pool(probes, async ([n, t]) => ({ n, t, r: await soft(resolve(n, t)) }))

/* ---------- collect what was actually observed ---------- */
const records = []
const push = (rec) => { if (ok(rec)) for (const ans of rec.answers) records.push({ name: ans.name, ttl: ans.ttl, type: TYPE_NAME[ans.type] || String(ans.type), data: ans.data }) }
push(ns); push(mx); push(apexA); push(apexAAAA); push(apexTxt); push(caa)
for (const s of swept) push(s.r)
/* Dedup: A and CNAME probes on the same name return overlapping CNAME chains. */
const seen = new Set()
const unique = records.filter(r => {
  const k = `${r.name}|${r.type}|${r.data}`
  if (seen.has(k)) return false
  seen.add(k); return true
})

const zone = { domain, ns, soa, ds, mx, mxTargets, apexA, apexAAAA, apexTxt, caa, whois, records: unique }
const { findings, blockers, verdict } = judge(zone)

/* ---------- the report ---------- */
const VERDICT_LINE = { 'GO': 'GO — nothing found that would break on a repoint', 'GO, WITH CARE': 'GO, WITH CARE — no blockers, but read the findings', 'NO-GO': 'NO-GO — fix the blockers below before touching nameservers' }
say(`\n  ${'='.repeat(64)}`)
say(`  ${VERDICT_LINE[verdict]}`)
say(`  ${'='.repeat(64)}\n`)

say('  Where it lives now')
say(`    nameservers   ${ok(ns) ? ns.answers.map(r => r.data).join(', ') : '(none found)'}`)
say(`    registrar     ${whois.available ? (whois.registrar || 'unknown') : `unknown — ${whois.reason}`}`)
if (whois.available && whois.expiry) say(`    expires       ${String(whois.expiry).slice(0, 10)}`)
say(`    mail          ${ok(mx) ? mx.answers.map(r => String(r.data).split(/\s+/).pop()).join(', ') : 'no MX — this domain does not receive mail'}`)
say(`    DNSSEC        ${ok(ds) ? `ACTIVE (${ds.answers.length} DS record${ds.answers.length === 1 ? '' : 's'})` : 'not enabled'}`)
say(`    records found ${unique.length} across ${COMMON_NAMES.length + POLICY_NAMES.length} probed names\n`)

if (findings.length) {
  for (const f of findings) {
    const tag = { blocker: 'WILL BREAK', warning: 'WORTH FIXING', advice: 'ADVICE' }[f.severity]
    say(`  [${tag}] ${f.title}`)
    say(`    ${f.detail.replace(/\s+/g, ' ').match(/.{1,86}(\s|$)/g).join('\n    ').trim()}`)
    for (const step of f.fix) say(`      -> ${step}`)
    say('')
  }
} else {
  say('  No blockers, warnings or advice. Still export the real zone from the losing provider')
  say('  before you cut over — see the limits below.\n')
}

/* ---------- what this could NOT see. Never omitted, never softened. ---------- */
say('  What this could NOT check')
say('    A zone cannot be enumerated from outside it — ANY and AXFR are both refused everywhere.')
say(`    So the ${unique.length} records above come from probing ${COMMON_NAMES.length + POLICY_NAMES.length} common names, not from reading the zone.`)
say('    Anything on an unusual hostname is invisible here and WILL be lost if you migrate from')
say('    this report alone. Export the zone from the current provider and use this to check it.')
if (!whois.available) say(`    Registrar, expiry and lock status are unknown (${whois.reason}).`)
const failed = swept.filter(s => s.r.error).length
if (failed) say(`    ${failed} lookup(s) failed outright and were skipped rather than reported as absent.`)
say('')

if (typeof a.zone === 'string') {
  fs.writeFileSync(path.resolve(a.zone), toZoneFile(zone))
  say(`  wrote ${path.resolve(a.zone)}  (partial — read its header)`)
}
if (typeof a.json === 'string') {
  fs.writeFileSync(path.resolve(a.json), JSON.stringify({ domain, verdict, findings, records: unique, whois, checkedAt: new Date().toISOString() }, null, 2))
  say(`  wrote ${path.resolve(a.json)}`)
}

/* --strict is opt-in for the same reason it is in the sibling skills: this is a report, and a
   report that fails by default teaches people to stop running it. */
process.exitCode = a.strict && blockers.length ? 1 : 0
