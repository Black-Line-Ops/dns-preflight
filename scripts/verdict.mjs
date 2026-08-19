/* The judgement layer, separated from the lookups so it can be tested against canned zones
   without a network.

   This is the whole value of the tool. Anyone can dump DNS records; a dozen sites do it for
   free. What nobody does is answer the question actually being asked, which is never "what are
   my records" - it is "if I repoint this domain today, what breaks?"

   Three rules cover every failure that genuinely takes a business offline. They are stated as
   BLOCKERS rather than warnings because each one is silent: the site keeps working, the check
   passes, and the thing that breaks is email, days later, with no obvious cause. */

/* A DS record at the parent means DNSSEC is active. Change nameservers with it in place and the
   new nameservers' answers fail validation - the domain goes dark for everyone using a
   validating resolver, which today is most people. Site AND mail, at once, with a symptom
   (SERVFAIL) that looks like nothing else and gets misdiagnosed as a propagation delay for
   hours. This is the single most expensive thing this tool exists to catch. */
function dnssecRule ({ ds }) {
  if (!ds || ds.nxdomain || !ds.answers.length) return null
  const ttl = ds.answers[0].ttl
  return {
    id: 'dnssec',
    severity: 'blocker',
    title: 'DNSSEC is active — repointing nameservers now would take the whole domain dark',
    detail:
      `The parent zone publishes ${ds.answers.length} DS record${ds.answers.length === 1 ? '' : 's'}. ` +
      'Until they are removed, any resolver that validates DNSSEC will reject answers from new ' +
      'nameservers — that is the website and the email at the same time, and the failure looks ' +
      'like an outage rather than a misconfiguration.',
    fix: [
      'Turn DNSSEC OFF at the REGISTRAR (not at the DNS host) before changing anything.',
      /* The DS TTL is the real wait, and it is knowable - so print it rather than the usual
         hand-wave about 24-48 hours, which is both wrong and unfalsifiable. */
      `Wait for the DS record to expire from caches: its TTL is ${ttl}s (~${Math.round(ttl / 60)} min).`,
      'Only then change the nameservers.',
      'Re-enable DNSSEC at the new provider afterwards, once the zone is serving correctly.',
    ],
  }
}

/* The classic shared-hosting pattern: MX points at mail.example.com, which is an A record INSIDE
   the zone being moved. Move the nameservers and that A record ceases to exist at the new
   provider unless somebody recreated it - so mail stops, while the website (whose A record
   everyone remembers to copy) works perfectly. The site looking fine is what makes this take
   days to notice. */
function mxInsideZoneRule ({ domain, mx, mxTargets }) {
  if (!mx || mx.nxdomain || !mx.answers.length) return null
  const inside = mx.answers
    .map(a => String(a.data).split(/\s+/).pop().replace(/\.$/, '').toLowerCase())
    .filter(host => host === domain || host.endsWith('.' + domain))
  if (!inside.length) return null
  const resolved = inside.map(h => {
    const rec = mxTargets && mxTargets[h]
    const ips = rec && !rec.nxdomain ? rec.answers.map(a => a.data) : []
    return { host: h, ips }
  })
  return {
    id: 'mx-inside-zone',
    severity: 'blocker',
    title: 'Mail is delivered to a hostname inside this zone — moving it breaks email silently',
    detail:
      `${inside.length} MX target${inside.length === 1 ? ' is' : 's are'} inside the domain you are moving ` +
      `(${resolved.map(r => r.host).join(', ')}). Those names only exist because the CURRENT ` +
      'nameservers answer for them. Point the domain somewhere else without recreating them and ' +
      'inbound mail stops — while the website carries on working perfectly, which is why this is ' +
      'usually noticed days later by a customer who never got a reply.',
    fix: [
      ...resolved.map(r => r.ips.length
        ? `Recreate  ${r.host}  as A ${r.ips.join(' / ')}  at the new provider BEFORE cutover.`
        : `Recreate  ${r.host}  at the new provider — its address could not be resolved, so copy it from the current DNS panel by hand.`),
      'Then send a real test message in BOTH directions before you consider the move done.',
    ],
  }
}

/* A registrar lock or an imminent expiry does not break anything by itself - it stops the change
   from being possible at all, on the day, after everything else has been arranged. Cheap to
   check, embarrassing to discover live. */
function registrarRule ({ whois }) {
  if (!whois || !whois.available) return null
  const out = []
  if (whois.locked) {
    out.push({
      id: 'registrar-lock',
      severity: 'blocker',
      title: 'The domain is locked at the registrar',
      detail: `Status: ${whois.status.join(', ')}. The registrar will refuse a nameserver or transfer change while this is set.`,
      fix: ['Unlock it in the registrar control panel first. It is usually a single toggle, and worth re-locking afterwards.'],
    })
  }
  if (whois.expiry) {
    const days = Math.round((new Date(whois.expiry) - Date.now()) / 86400000)
    if (days <= 30) {
      out.push({
        id: 'expiry',
        severity: days <= 7 ? 'blocker' : 'warning',
        title: `The registration expires in ${days} day${days === 1 ? '' : 's'}`,
        detail: `Expires ${String(whois.expiry).slice(0, 10)}. Renew before migrating — a domain that lapses mid-move is far harder to recover than one that lapses quietly.`,
        fix: ['Renew now. It is cheap, and it removes the worst possible failure from the window.'],
      })
    }
  }
  return out.length ? out : null
}

/* Not a blocker, but the thing that decides how long a mistake lasts. A 24h TTL means a wrong
   record is wrong for a day; 300s means it is wrong for five minutes. */
function ttlRule ({ apexA, mx }) {
  const high = []
  for (const [label, rec] of [['A/AAAA at the apex', apexA], ['MX', mx]]) {
    if (!rec || rec.nxdomain || !rec.answers.length) continue
    const ttl = Math.max(...rec.answers.map(a => a.ttl))
    if (ttl > 3600) high.push({ label, ttl })
  }
  if (!high.length) return null
  return {
    id: 'high-ttl',
    severity: 'advice',
    title: 'Long TTLs — a mistake on cutover day would stay wrong for hours',
    detail: high.map(h => `${h.label}: ${h.ttl}s (~${Math.round(h.ttl / 3600)}h)`).join('; '),
    fix: [
      'A day or two BEFORE the move, lower these to 300–600s at the current provider.',
      'Raise them again once the new zone is confirmed good. This is the cheapest insurance in the whole process.',
    ],
  }
}

/* Mail exists but SPF does not: not a migration blocker, but the migration is the moment somebody
   will notice, and a missing SPF is the difference between arriving and going to spam. */
function spfRule ({ mx, apexTxt }) {
  if (!mx || mx.nxdomain || !mx.answers.length) return null
  const txts = apexTxt && !apexTxt.nxdomain ? apexTxt.answers.map(a => a.data) : []
  if (txts.some(t => /v=spf1/i.test(t))) return null
  return {
    id: 'no-spf',
    severity: 'warning',
    title: 'This domain receives mail but publishes no SPF record',
    detail: 'Not caused by the migration, but it will be blamed on it. Whatever sends mail for this domain is more likely to land in spam without one.',
    fix: ['Ask the mail provider for their SPF line and add it as a TXT record at the apex — before the move, so the change is not a suspect afterwards.'],
  }
}

export function judge (zone) {
  const findings = []
  for (const rule of [dnssecRule, mxInsideZoneRule, registrarRule, ttlRule, spfRule]) {
    const r = rule(zone)
    if (!r) continue
    Array.isArray(r) ? findings.push(...r) : findings.push(r)
  }
  const order = { blocker: 0, warning: 1, advice: 2 }
  findings.sort((a, b) => order[a.severity] - order[b.severity])
  const blockers = findings.filter(f => f.severity === 'blocker')
  return {
    findings,
    blockers,
    /* Three words, chosen so nobody has to interpret them. NO-GO means a blocker is live and a
       cutover today would break something. */
    verdict: blockers.length ? 'NO-GO' : findings.length ? 'GO, WITH CARE' : 'GO',
  }
}

/* A zone file the new provider can import, built ONLY from what was actually observed. Every
   record carries where it came from, and the header says plainly that this is not the whole
   zone - because it cannot be, and a file presented as complete is how records get lost. */
export function toZoneFile (zone) {
  const { domain, records } = zone
  const lines = [
    `; Partial zone for ${domain}`,
    `; Generated ${new Date().toISOString()} by dns-preflight, from PUBLIC LOOKUPS ONLY.`,
    ';',
    '; THIS IS NOT THE COMPLETE ZONE, AND IT CANNOT BE. A zone cannot be enumerated from',
    '; outside it (ANY is refused, AXFR is refused). These are the records found by probing a',
    '; known list of names. Anything on an unusual hostname is NOT here and will be lost if you',
    '; treat this file as the whole truth. Export the real zone from the losing provider if you',
    '; possibly can, and use this only to check that export for gaps.',
    ';',
  ]
  for (const r of records) {
    const name = r.name === domain ? '@' : r.name.replace(new RegExp(`\\.${domain}$`), '')
    lines.push(`${name}\t${r.ttl}\tIN\t${r.type}\t${r.data}`)
  }
  return lines.join('\n') + '\n'
}
