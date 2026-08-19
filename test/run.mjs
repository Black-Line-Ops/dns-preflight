/* Entry point for the whole suite:  node test/run.mjs  (or  npm test  ).

   Deliberately not `node --test`. Importing the suites into one process needs no flag, so it runs
   the same way on every Node this tool supports, and it keeps the promise the rest of the repo
   makes: a bare `node <file>` with nothing installed.

   Nothing in here touches the network. Every DNS answer and every RDAP response is a stub, which
   matters more here than in most repos: a DNS tool whose tests need DNS is flaky in exactly the
   conditions it exists to diagnose. */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const suites = fs.readdirSync(here).filter(f => f.endsWith('.test.mjs')).sort()

if (!suites.length) {
  console.error(`no *.test.mjs files in ${here}`)
  process.exit(1)
}

for (const s of suites) await import(pathToFileURL(path.join(here, s)).href)
