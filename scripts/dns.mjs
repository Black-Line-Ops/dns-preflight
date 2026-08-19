/* DNS and RDAP lookups over HTTPS. No `dig`, no `whois`, no dependencies.

   WHY DoH RATHER THAN node:dns. Two reasons, and the second is the one that matters.

   `dig` is not installed on Windows and never will be, and node:dns talks to whatever resolver
   the machine happens to be using - which on a corporate laptop, a VPN, or a router doing
   "DNS optimisation" is a resolver that lies. A pre-flight that reads the wrong zone because the
   office router served a cached answer is worse than no pre-flight: it produces a confident
   report about a domain nobody else can see.

   DoH is also all HTTPS on 443, so it works on hotel wifi and guest networks that block UDP/53 -
   which is exactly where someone ends up doing an emergency migration check.

   THE HARD LIMIT, stated here because every consumer has to repeat it: you cannot enumerate a
   zone from outside it. ANY is refused (1.1.1.1 answers Status 4 / EDE(21) Not Supported,
   measured), AXFR is refused everywhere, and there is no other mechanism. So this probes a KNOWN
   LIST of names and reports what it found - never "here is your zone". Any tool claiming a
   complete dump is guessing, and the records it silently misses are exactly the ones that carry
   email. */

const DOH = 'https://cloudflare-dns.com/dns-query'
/* Google as the second opinion. Two independent resolvers disagreeing is itself a finding -
   usually mid-propagation, occasionally a split-horizon setup - and it is worth surfacing rather
   than picking one at random. */
const DOH_ALT = 'https://dns.google/resolve'
const RDAP = 'https://rdap.org/domain/'

/* rcodes worth naming. 3 (NXDOMAIN) is a real answer - "this name does not exist" - and must not
   be confused with a lookup that failed. */
export const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' }

export class LookupError extends Error {
  constructor (msg, { name = '', type = '' } = {}) {
    super(msg); this.name = 'LookupError'; this.qname = name; this.qtype = type
  }
}

/* fetchImpl is injectable so the suite can feed canned responses. A DNS tool whose tests need
   the network is a tool whose tests are flaky in exactly the conditions it exists to diagnose. */
export function makeResolver ({ fetchImpl = globalThis.fetch, endpoint = DOH, timeoutMs = 8000 } = {}) {
  if (typeof fetchImpl !== 'function') throw new LookupError('no fetch available - Node 18+ is required')

  return async function query (name, type) {
    const url = `${endpoint}${endpoint.includes('?') ? '&' : '?'}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`
    const ctl = new AbortController()
    const timer = setTimeout(() => ctl.abort(), timeoutMs)
    let res
    try {
      /* The Accept header is MANDATORY on Cloudflare's endpoint - without it you get a bare 400
         and no explanation. Measured. Google's endpoint ignores it, so sending it always is
         correct for both. */
      res = await fetchImpl(url, { headers: { accept: 'application/dns-json' }, signal: ctl.signal })
    } catch (e) {
      throw new LookupError(`${type} ${name}: ${e.name === 'AbortError' ? `timed out after ${timeoutMs}ms` : e.message}`,
        { name, type })
    } finally { clearTimeout(timer) }

    if (!res.ok) throw new LookupError(`${type} ${name}: HTTP ${res.status} from the resolver`, { name, type })
    let body
    try { body = await res.json() } catch (_) {
      throw new LookupError(`${type} ${name}: the resolver did not return JSON`, { name, type })
    }

    const status = Number(body?.Status ?? -1)
    /* NXDOMAIN is an ANSWER, not a failure - "no such name" is frequently the correct and useful
       result (a hostname that does not exist yet). Only genuinely broken statuses throw. */
    if (status !== 0 && status !== 3) {
      const label = RCODE[status] || `rcode ${status}`
      const ede = Array.isArray(body?.Comment) ? body.Comment.join('; ') : (body?.Comment || '')
      throw new LookupError(`${type} ${name}: ${label}${ede ? ` - ${ede}` : ''}`, { name, type })
    }

    return {
      name,
      type,
      status,
      nxdomain: status === 3,
      /* Cloudflare returns the TTL the AUTHORITATIVE server gave, decremented by whatever the
         resolver has cached. It is a floor, not a promise - said here so the report can say it
         too rather than presenting a countdown as gospel. */
      answers: (body?.Answer || []).map(a => ({
        name: String(a.name || '').replace(/\.$/, ''),
        type: a.type,
        ttl: Number(a.TTL),
        data: String(a.data || '').replace(/\.$/, ''),
      })),
      authority: (body?.Authority || []).map(a => ({ type: a.type, ttl: Number(a.TTL), data: String(a.data || '') })),
    }
  }
}

/* Numeric RRtypes, because the JSON API answers with numbers and reads back with them. */
export const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, CAA: 257 }
export const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]))

/* The names worth probing. There is no way to discover a zone's contents, so this list IS the
   coverage - and it must be honest about being a list. Chosen as the names that break a business
   when they are missed: mail, the marketing tools that verify by CNAME, and the two or three
   hostnames every small site actually uses. */
export const COMMON_NAMES = [
  '', 'www', 'mail', 'webmail', 'autodiscover', 'autoconfig', 'ftp', 'cpanel', 'webdisk',
  'smtp', 'imap', 'pop', 'ns1', 'ns2', 'blog', 'shop', 'app', 'api', 'staging', 'dev',
  'portal', 'vpn', 'remote', 'cdn', 'assets', 'img', 'static', 'm', 'test',
]
/* TXT names that carry policy rather than content. Missing one of these does not break the site;
   missing it on the OTHER side of a migration silently breaks deliverability weeks later. */
export const POLICY_NAMES = [
  '_dmarc', '_domainkey', 'default._domainkey', 'google._domainkey', 'selector1._domainkey',
  'selector2._domainkey', 'k1._domainkey', 'mandrill._domainkey', '_acme-challenge',
]

export async function rdap (domain, { fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {}) {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  try {
    const res = await fetchImpl(RDAP + encodeURIComponent(domain), { headers: { accept: 'application/rdap+json' }, signal: ctl.signal })
    /* Measured: .com and .ai resolve (302 to the registry's own RDAP server, followed
       automatically); .io and .co have NO entry in the IANA bootstrap file and 404. That is a
       gap in the protocol's coverage, not a problem with the domain, and the report must say
       "unknown" rather than "no lock found" - the second reads as reassurance. */
    if (res.status === 404) return { available: false, reason: `no RDAP service is published for this TLD (common for .io and .co)` }
    if (!res.ok) return { available: false, reason: `RDAP answered HTTP ${res.status}` }
    const body = await res.json()
    const events = Object.fromEntries((body.events || []).map(e => [e.eventAction, e.eventDate]))
    const registrar = (body.entities || [])
      .filter(e => (e.roles || []).includes('registrar'))
      .map(e => {
        const v = (e.vcardArray && e.vcardArray[1]) || []
        const fn = v.find(x => x[0] === 'fn')
        return fn ? fn[3] : (e.handle || '')
      })[0] || null
    return {
      available: true,
      registrar,
      status: body.status || [],
      expiry: events.expiration || null,
      created: events.registration || null,
      /* These two are what actually stop a nameserver change on cutover day.

         The whitespace in the pattern is load-bearing. RFC 9083 specifies RDAP status values as
         SPACE-SEPARATED words - "client transfer prohibited" - while EPP, and a good many RDAP
         servers mirroring it, use camelCase: "clientTransferProhibited". Both are live in the
         wild. Matching only the camelCase form reports a genuinely locked domain as unlocked,
         which is the exact false reassurance this tool exists to prevent: somebody arranges a
         cutover, arrives on the day, and the registrar refuses the change. Caught by a test
         built from a real RFC-shaped response. */
      locked: (body.status || []).some(s => /transfer\s*prohibited|update\s*prohibited/i.test(s)),
      nameservers: (body.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()),
    }
  } catch (e) {
    return { available: false, reason: e.name === 'AbortError' ? 'RDAP timed out' : e.message }
  } finally { clearTimeout(timer) }
}

export { DOH, DOH_ALT, RDAP }
