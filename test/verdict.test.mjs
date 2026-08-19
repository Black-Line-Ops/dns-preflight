/* The judgement layer, against canned zones. No network.

   A DNS tool whose tests need DNS is flaky in exactly the conditions it exists to diagnose -
   bad wifi, a lying resolver, a captive portal - so every rule here is exercised against a
   hand-built zone object rather than a live domain.

   What each test is really asserting is that the rule fires on the SILENT case. All three
   blockers share a shape: the website keeps working, so nothing looks wrong, and the thing that
   actually broke is email, discovered days later by a customer who never got a reply. A rule
   that only caught the loud failures would be worthless. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { judge, toZoneFile } from '../scripts/verdict.mjs'

const rec = (answers) => ({ nxdomain: false, answers, status: 0 })
const none = { nxdomain: true, answers: [], status: 3 }

const clean = () => ({
  domain: 'example.com',
  ns: rec([{ name: 'example.com', type: 2, ttl: 3600, data: 'ns1.host.net' }]),
  ds: none,
  mx: rec([{ name: 'example.com', type: 15, ttl: 3600, data: '10 mx.googlemail.com' }]),
  mxTargets: {},
  apexA: rec([{ name: 'example.com', type: 1, ttl: 300, data: '203.0.113.10' }]),
  apexTxt: rec([{ name: 'example.com', type: 16, ttl: 3600, data: 'v=spf1 include:_spf.google.com ~all' }]),
  whois: { available: true, registrar: 'Test Registrar', status: ['clientTransferProhibited'.replace('clientTransferProhibited', 'ok')], expiry: '2030-01-01T00:00:00Z', locked: false },
  records: [],
})

test('a clean zone is a GO', () => {
  const { verdict, blockers } = judge(clean())
  assert.equal(verdict, 'GO')
  assert.equal(blockers.length, 0)
})

test('DNSSEC is a blocker, and the fix quotes the REAL DS TTL', () => {
  const z = clean()
  z.ds = rec([{ name: 'example.com', type: 43, ttl: 7200, data: '12345 13 2 abcdef' }])
  const { verdict, findings } = judge(z)

  assert.equal(verdict, 'NO-GO')
  const f = findings.find(x => x.id === 'dnssec')
  assert.ok(f, 'DNSSEC must be caught')
  /* The DS TTL is the actual wait, and it is knowable - so it gets printed rather than the
     usual "24 to 48 hours", which is both wrong and unfalsifiable. */
  assert.ok(f.fix.some(s => s.includes('7200s')), `the real TTL must appear in the fix: ${JSON.stringify(f.fix)}`)
  assert.ok(f.fix[0].includes('REGISTRAR'), 'DNSSEC is disabled at the registrar, not the DNS host - the distinction is the whole fix')
})

test('an MX target inside the zone is a blocker, and the fix names the address to recreate', () => {
  /* The cPanel pattern: MX -> mail.example.com -> A record inside the zone being moved. Move the
     nameservers, that A record stops existing, inbound mail dies - and the website is fine, which
     is why nobody notices for days. */
  const z = clean()
  z.mx = rec([{ name: 'example.com', type: 15, ttl: 3600, data: '10 mail.example.com' }])
  z.mxTargets = { 'mail.example.com': rec([{ name: 'mail.example.com', type: 1, ttl: 3600, data: '203.0.113.25' }]) }
  const { verdict, findings } = judge(z)

  assert.equal(verdict, 'NO-GO')
  const f = findings.find(x => x.id === 'mx-inside-zone')
  assert.ok(f)
  assert.ok(f.fix[0].includes('mail.example.com'), 'must name the host')
  /* A rule that says "recreate mail.example.com" without saying what it points at has moved the
     problem rather than solved it. */
  assert.ok(f.fix[0].includes('203.0.113.25'), `must name the address: ${f.fix[0]}`)
})

test('an EXTERNAL mail host is not flagged - that is the normal case', () => {
  const z = clean()
  z.mx = rec([{ name: 'example.com', type: 15, ttl: 3600, data: '10 aspmx.l.google.com' }])
  assert.equal(judge(z).blockers.length, 0, 'Google-hosted mail survives a nameserver change untouched')
})

test('a lookalike domain is not mistaken for an inside-the-zone target', () => {
  /* notexample.com ENDS WITH example.com as a string but is a different domain. A naive
     endsWith check flags it and sends somebody recreating records they do not own. */
  const z = clean()
  z.mx = rec([{ name: 'example.com', type: 15, ttl: 3600, data: '10 mail.notexample.com' }])
  assert.equal(judge(z).blockers.length, 0, 'only a real subdomain counts - the dot matters')
})

test('a registrar lock blocks, and an imminent expiry escalates with time', () => {
  const locked = clean()
  locked.whois = { ...locked.whois, locked: true, status: ['clientUpdateProhibited'] }
  assert.ok(judge(locked).findings.some(f => f.id === 'registrar-lock'))

  const soon = clean()
  soon.whois = { ...soon.whois, expiry: new Date(Date.now() + 5 * 86400000).toISOString() }
  const f = judge(soon).findings.find(x => x.id === 'expiry')
  assert.equal(f.severity, 'blocker', 'inside a week is a blocker')

  const later = clean()
  later.whois = { ...later.whois, expiry: new Date(Date.now() + 20 * 86400000).toISOString() }
  assert.equal(judge(later).findings.find(x => x.id === 'expiry').severity, 'warning')

  const distant = clean()
  assert.equal(judge(distant).findings.some(x => x.id === 'expiry'), false, 'a 2030 expiry is not news')
})

test('unknown registrar data produces no registrar findings at all', () => {
  /* .io and .co have no RDAP entry. Absence of data must never render as absence of a lock -
     "no lock found" reads as reassurance and would send somebody into a cutover unprepared. */
  const z = clean()
  z.whois = { available: false, reason: 'no RDAP service is published for this TLD' }
  const ids = judge(z).findings.map(f => f.id)
  assert.equal(ids.includes('registrar-lock'), false)
  assert.equal(ids.includes('expiry'), false)
})

test('long TTLs are advice, not a blocker', () => {
  const z = clean()
  z.apexA = rec([{ name: 'example.com', type: 1, ttl: 86400, data: '203.0.113.10' }])
  const f = judge(z).findings.find(x => x.id === 'high-ttl')
  assert.equal(f.severity, 'advice')
  assert.equal(judge(z).verdict, 'GO, WITH CARE')
})

test('mail with no SPF is a warning; no mail at all is silence', () => {
  const z = clean()
  z.apexTxt = rec([{ name: 'example.com', type: 16, ttl: 3600, data: 'google-site-verification=abc' }])
  assert.ok(judge(z).findings.some(f => f.id === 'no-spf'))

  const noMail = clean()
  noMail.mx = none
  assert.equal(judge(noMail).findings.some(f => f.id === 'no-spf'), false,
    'a domain that receives no mail does not need SPF advice')
})

test('blockers sort above warnings and advice', () => {
  const z = clean()
  z.ds = rec([{ name: 'example.com', type: 43, ttl: 3600, data: 'x' }])
  z.apexA = rec([{ name: 'example.com', type: 1, ttl: 86400, data: '203.0.113.10' }])
  const sev = judge(z).findings.map(f => f.severity)
  assert.equal(sev[0], 'blocker', 'the thing that breaks must be read first')
})

test('the zone file says, in its own header, that it is not the whole zone', () => {
  /* The most dangerous artefact this tool produces. Presented as complete, it becomes the
     migration plan, and every record it could not see is lost. */
  const z = clean()
  z.records = [{ name: 'example.com', ttl: 300, type: 'A', data: '203.0.113.10' },
    { name: 'www.example.com', ttl: 300, type: 'CNAME', data: 'example.com' }]
  const out = toZoneFile(z)
  assert.match(out, /NOT THE COMPLETE ZONE/)
  assert.match(out, /AXFR are both refused|AXFR is refused/)
  assert.match(out, /^@\t300\tIN\tA\t203\.0\.113\.10$/m, 'the apex must render as @')
  assert.match(out, /^www\t300\tIN\tCNAME/m, 'subdomains render relative')
})
