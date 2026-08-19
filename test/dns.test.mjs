/* The resolver, against a stub fetch. No network.

   The distinctions being asserted here are the ones that decide whether a report is trustworthy:
   NXDOMAIN is an ANSWER (this name does not exist) while SERVFAIL is a FAILURE (we do not know),
   and a tool that conflates them reports "no record" for a domain it simply could not read. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeResolver, rdap, LookupError, COMMON_NAMES, POLICY_NAMES } from '../scripts/dns.mjs'

const reply = (body, { ok = true, status = 200 } = {}) =>
  async () => ({ ok, status, json: async () => body })

test('a normal answer is parsed, trailing dots stripped', async () => {
  const q = makeResolver({ fetchImpl: reply({ Status: 0, Answer: [{ name: 'example.com.', type: 1, TTL: 300, data: '203.0.113.10' }] }) })
  const r = await q('example.com', 'A')
  assert.equal(r.nxdomain, false)
  assert.equal(r.answers[0].name, 'example.com', 'the trailing dot must go, or every comparison against a bare domain fails')
  assert.equal(r.answers[0].ttl, 300)
})

test('NXDOMAIN is an answer, not an error', async () => {
  const q = makeResolver({ fetchImpl: reply({ Status: 3 }) })
  const r = await q('nope.example.com', 'A')
  assert.equal(r.nxdomain, true)
  assert.equal(r.answers.length, 0)
})

test('SERVFAIL throws, because "we could not read it" is not "it is not there"', async () => {
  const q = makeResolver({ fetchImpl: reply({ Status: 2 }) })
  await assert.rejects(() => q('example.com', 'A'), (e) => e instanceof LookupError && /SERVFAIL/.test(e.message))
})

test('a refused type reports the resolver’s own explanation', async () => {
  /* ANY is refused with EDE(21). Surfacing that text is what stops somebody concluding their
     domain is broken when the resolver simply declined the question. */
  const q = makeResolver({ fetchImpl: reply({ Status: 4, Comment: ['EDE(21): Not Supported'] }) })
  await assert.rejects(() => q('example.com', 'ANY'), /Not Supported/)
})

test('the mandatory Accept header is always sent', async () => {
  /* Cloudflare answers a bare 400 without it, with nothing in the body to explain why. */
  let sawHeader = null
  const q = makeResolver({ fetchImpl: async (url, opts) => { sawHeader = opts.headers.accept; return { ok: true, status: 200, json: async () => ({ Status: 0 }) } } })
  await q('example.com', 'A')
  assert.equal(sawHeader, 'application/dns-json')
})

test('a non-JSON response fails clearly rather than throwing a parse error', async () => {
  const q = makeResolver({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => { throw new Error('bad json') } }) })
  await assert.rejects(() => q('example.com', 'A'), /did not return JSON/)
})

test('a hung resolver times out instead of hanging the whole sweep', async () => {
  const q = makeResolver({ timeoutMs: 40, fetchImpl: (url, opts) => new Promise((_, rej) => {
    opts.signal.addEventListener('abort', () => { const e = new Error('aborted'); e.name = 'AbortError'; rej(e) })
  }) })
  await assert.rejects(() => q('example.com', 'A'), /timed out after 40ms/)
})

test('RDAP 404 means UNKNOWN and says which TLDs do this', async () => {
  /* .io and .co have no bootstrap entry. Reporting this as "not locked" would be reassurance
     the tool has no basis for. */
  const r = await rdap('example.io', { fetchImpl: async () => ({ ok: false, status: 404 }) })
  assert.equal(r.available, false)
  assert.match(r.reason, /\.io and \.co/)
})

test('RDAP lock and expiry are read out of the real response shape', async () => {
  const r = await rdap('example.com', { fetchImpl: reply({
    status: ['client transfer prohibited'],
    events: [{ eventAction: 'expiration', eventDate: '2027-05-01T00:00:00Z' }],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]] }],
    nameservers: [{ ldhName: 'NS1.EXAMPLE.NET' }],
  }) })
  assert.equal(r.available, true)
  assert.equal(r.registrar, 'Example Registrar')
  assert.equal(r.locked, true)
  assert.equal(r.expiry, '2027-05-01T00:00:00Z')
  assert.equal(r.nameservers[0], 'ns1.example.net', 'lowercased for comparison against DNS answers')
})

test('the probe list covers the names that actually break a business', () => {
  /* This list IS the coverage - a zone cannot be enumerated - so its contents are a product
     decision, not an implementation detail. */
  for (const n of ['', 'www', 'mail', 'autodiscover', 'smtp']) {
    assert.ok(COMMON_NAMES.includes(n), `${n || '(apex)'} must be probed`)
  }
  for (const n of ['_dmarc', 'google._domainkey']) {
    assert.ok(POLICY_NAMES.includes(n), `${n} must be probed - deliverability breaks silently`)
  }
})
