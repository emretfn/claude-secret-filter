// Pure redaction logic: no engine dependency, testable on its own.
//
// Layers, applied in this order to every string of a tool's output:
//   0. known values: any value masked before (or seeded from the project's secret
//      files) is masked wherever it shows up again, also base64 / URL-encoded
//   1. known formats: our own provider rules, then gitleaks' ruleset
//   2. secret-named fields: `dbPassword = "..."`, `"clientSecret": "..."`, `Password=...;`
//   3. entropy: long random-looking tokens with no known format or label
//   + env mode: for .env-style files and `env`/`printenv`, every value is masked

import { GITLEAKS_GLOBAL_ALLOW, GITLEAKS_RULES, type Src } from './gitleaks-rules'

// ---------------------------------------------------------------------------
// Placeholders: each masked value gets its own id, `[REDACTED:<id>]` with an
// 8-hex-digit id. The real value is kept only in this module's memory (never
// written to disk, never sent to the model); Edit/Write turn placeholders back
// into real values, but only in a file the value was read from.
export const MASK = '[REDACTED'
const PLACEHOLDER = /\[REDACTED:[0-9a-f]{8}\]/

// id -> the real value, and the files it was seen in (the only files it is restored into)
type Entry = { value: string; sources: Set<string> }
const vault = new Map<string, Entry>()
const MAX_VAULT = 50_000
const idOf = new Map<string, string>()

// SHA-256, synchronous (crypto.subtle is async): ids are a keyed hash, so a placeholder
// seen outside (a URL, a commit message) cannot be checked against guessed values.
const K256 = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])
export function sha256hex(text: string): string {
  const msg = new TextEncoder().encode(text)
  const len = Math.ceil((msg.length + 9) / 64) * 64
  const buf = new Uint8Array(len)
  buf.set(msg)
  buf[msg.length] = 0x80
  const bits = msg.length * 8
  const dv = new DataView(buf.buffer)
  dv.setUint32(len - 8, Math.floor(bits / 2 ** 32))
  dv.setUint32(len - 4, bits >>> 0)
  const h = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))
  for (let off = 0; off < len; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4)
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!, b = w[i - 2]!
      w[i] = (w[i - 16]! + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7]! + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>> 0
    }
    let [a, b, c, d, e, f, g, hh] = h as unknown as number[] as [number, number, number, number, number, number, number, number]
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i]! + w[i]!) >>> 0
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    const v = [a, b, c, d, e, f, g, hh]
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + v[i]!) >>> 0
  }
  return [...h].map(x => x.toString(16).padStart(8, '0')).join('')
}

const KEY = [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('')
const keyedId = (s: string) => sha256hex(KEY + s).slice(0, 8)

// The files the output being redacted came from (set by `redact`): every value masked in
// it may be restored into them.
let currentSources: readonly string[] = []

// A deadline for the redaction of one tool result (`withBudget`). Past it `redact` throws,
// and the hook withholds the output: the engine would otherwise give up on the hook and
// pass the raw result.
let deadline = Infinity
export class BudgetExceeded extends Error {}
const checkBudget = () => {
  if (Date.now() > deadline) throw new BudgetExceeded('secret-filter: redaction ran out of time')
}
export function withBudget<T>(ms: number, fn: () => T): T {
  const outer = deadline
  deadline = Math.min(outer, Date.now() + ms)
  try {
    return fn()
  } finally {
    deadline = outer
  }
}

/**
 * Masks a value. `learn`: also mask it wherever it shows up later. Off for the
 * entropy layer, a guess: one false positive there must not spread.
 */
export function mask(value: string, learn = true): string {
  let id = idOf.get(value)
  if (id === undefined) {
    id = keyedId(value)
    while (vault.has(id)) id = keyedId(id + value)
    // past the cap a value is still masked, but not kept: its placeholder cannot be restored
    if (vault.size >= MAX_VAULT) return `${MASK}:${id}]`
    vault.set(id, { value, sources: new Set() })
    idOf.set(value, id)
  }
  for (const s of currentSources) vault.get(id)!.sources.add(normPath(s))
  if (learn) remember(value)
  return `${MASK}:${id}]`
}

// Paths compare case-insensitively: macOS and Windows file systems are, and a looser
// match only matters where the line check in `restore` already holds.
const normPath = (p: string) => p.replace(/\/+/g, '/').replace(/\/(?:\.\/)+/g, '/').toLowerCase()

export const hasPlaceholder = (text: string) => PLACEHOLDER.test(text)

/** Hits per layer / rule (`gitleaks:<id>`, `field`, `entropy`, ...): for tests and tuning. */
export const hits = new Map<string, number>()
const hit = (k: string) => hits.set(k, (hits.get(k) ?? 0) + 1)

/**
 * Turns placeholders back into real values, for a write to `target`. A value is restored
 * only into a file it was read from (`foreign` lists the others), never under `.git/`:
 * a placeholder copied into a new script, a URL or another file would otherwise carry
 * the real value out. `missing`: placeholders this module does not know.
 */
export function restore(text: string, target: string): { text: string; missing: string[]; foreign: string[]; values: string[] } {
  const missing: string[] = []
  const foreign: string[] = []
  const values = new Set<string>()
  const t = normPath(target)
  const blocked = t === '' || /(?:^|\/)\.git(?:\/|$)/i.test(t)
  const out = text.replace(/\[REDACTED:([0-9a-f]{8})\]/g, (m, id: string) => {
    const en = vault.get(id)
    if (en === undefined) {
      missing.push(m)
      return m
    }
    if (blocked || !en.sources.has(t)) {
      foreign.push(m)
      return m
    }
    values.add(en.value)
    return en.value
  })
  return { text: out, missing, foreign, values: [...values] }
}

/**
 * A restored value may only land where it already was: each place it appears in the new
 * text, the text around it on its line must be part of a line of `source` (the replaced
 * text, or the file as it is), no more often than there. So a value can be kept, or its
 * line trimmed, but never moved into a new line such as `curl https://...?t=<value>`.
 * Returns the values that would land somewhere new.
 */
export function movedValues(text: string, source: string, values: readonly string[]): string[] {
  const moved: string[] = []
  for (const v of values) {
    const need = new Map<string, number>()
    for (let i = text.indexOf(v); i !== -1; i = text.indexOf(v, i + v.length)) {
      const start = text.lastIndexOf('\n', i - 1) + 1
      const endNl = text.indexOf('\n', i + v.length)
      const span = text.slice(start, endNl === -1 ? text.length : endNl)
      need.set(span, (need.get(span) ?? 0) + 1)
    }
    const sourceLines = source.split('\n')
    const isMultiLine = v.includes('\n')
    for (const [span, n] of need) {
      const have = isMultiLine
        ? source.split(span).length - 1
        : sourceLines.reduce((k, line) => k + (line.split(span).length - 1), 0)
      if (have < n) {
        moved.push(v)
        break
      }
    }
  }
  return moved
}

/** A value that was restored into a file is masked in every later output, whatever it looks like. */
export function pinRestored(text: string): void {
  for (const m of text.matchAll(/\[REDACTED:([0-9a-f]{8})\]/g)) {
    const v = vault.get(m[1]!)?.value
    if (v === undefined || v.length < 3 || pinned.has(v)) continue
    if (v.length < 8) pinnedShort.add(v)
    for (const x of [v, b64(v), b64(v, true).replace(/=+$/, ''), encodeURIComponent(v)]) if (x.length >= 3) pinned.add(x)
    knownSorted = undefined
  }
}

// ---------------------------------------------------------------------------
// Values that are obviously not secrets: placeholders, templates, examples.
const PLACEHOLDER_WORDS =
  /^(?:password|passwd|passw0rd|changeme|change_me|changeit|example|sample|dummy|test|testing|redacted|secret|token|placeholder|none|null|empty|undefined|default|admin|admin123|root|letmein|qwerty|123456|12345678|todo|tbd|fixme|foo|bar|baz|xxx+|\*+|\.+|-+)$/i
const TEMPLATE =
  /^(?:\$\w+|\$\{[^}]*\}|\$\{\{[^}]*\}\}|\{\{[^}]*\}\}|%\w+%|@\w+@|<[^>]*>|\{\d{0,2}\}|%[+\-# 0]?[a-zA-Z]|\$\(.*\))$/
const REPEATED = /^(.)\1*$/
// `your_api_key`, `<insert-token>`-style prose: never with a digit (`my_db_pw7` is a value)
const PLACEHOLDER_PREFIX = /^(?:your|my|insert|enter)[_-]?[A-Za-z_]+$/i
// In a secret file every value is real unless it is unmistakably a stand-in:
// `admin123` or `password` there is a weak password, not an example.
const PLACEHOLDER_STRICT =
  /^(?:changeme|change_me|changeit|example|sample|dummy|redacted|placeholder|none|null|empty|undefined|todo|tbd|fixme|xxx+|\*+|\.+|-+)$/i

export function isPlaceholderValue(v: string, strict = false): boolean {
  const t = v.trim().replace(/^["'`]|["'`]$/g, '')
  if (t === '' || TEMPLATE.test(t) || REPEATED.test(t)) return true
  return strict ? PLACEHOLDER_STRICT.test(t) : PLACEHOLDER_WORDS.test(t) || PLACEHOLDER_PREFIX.test(t)
}

// ---------------------------------------------------------------------------
// Layer 0: known values, with encoded variants.
const known = new Set<string>()
const pinned = new Set<string>() // restored into a file: masked always (pinRestored)
const pinnedShort = new Set<string>() // short ones: masked as whole words only, not inside other words
let knownSorted: string[] | undefined
// Seeds and values learned while working have budgets of their own, so a repository
// full of planted values cannot crowd out what is learned later.
const MAX_KNOWN = 2000
const MAX_SEEDED = 500
let seeded = 0

function b64(s: string, url = false): string {
  const bytes = new TextEncoder().encode(s)
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' + (url ? '-_' : '+/')
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0)
    out += A[(n >> 18) & 63]! + A[(n >> 12) & 63]!
    out += i + 1 < bytes.length ? A[(n >> 6) & 63]! : url ? '' : '='
    out += i + 2 < bytes.length ? A[n & 63]! : url ? '' : '='
  }
  return out
}

/**
 * Only distinctive values are remembered: a plain word would mask too much, and a
 * cloned repo could plant decoys. A value that reads like a code identifier
 * (`useEffect`) or a plain URL with no credentials is not taken.
 */
function isDistinctive(v: string): boolean {
  if (v.length < 8 || v.length > 4096 || v.includes(MASK) || isPlaceholderValue(v)) return false
  if (/^[A-Za-z_][A-Za-z_]*$/.test(v)) return false // an identifier, no digits
  if (/^https?:\/\/[^\s:@\/]+(?:[\/?#][^\s@]*)?$/.test(v) && !/[?&](?:sig|token|key|secret|code)=/i.test(v)) return false // a plain URL
  const hasDigit = /\d/.test(v)
  const mixedCase = /[a-z]/.test(v) && /[A-Z]/.test(v)
  const hasSymbol = /[^A-Za-z0-9\s]/.test(v)
  return (hasDigit && /[A-Za-z]/.test(v)) || mixedCase || (hasSymbol && v.length >= 12)
}

/** Remembers a secret value (and its base64 / URL-encoded forms) to mask everywhere. */
export function remember(value: string): void {
  const v = value.trim()
  if (known.size >= MAX_KNOWN + MAX_SEEDED * 4 || !isDistinctive(v)) return
  const variants = [v, b64(v), b64(v, true).replace(/=+$/, ''), encodeURIComponent(v)]
  for (const x of variants) if (x.length >= 8 && !known.has(x)) known.add(x)
  knownSorted = undefined
}

/** Only the known-values layer: for binary payloads, where any other rule could corrupt bytes. */
export function maskKnownOnly(text: string): { text: string; count: number } {
  return maskKnown(text)
}

function maskKnown(text: string): { text: string; count: number } {
  if (known.size === 0 && pinned.size === 0) return { text, count: 0 }
  knownSorted ??= [...new Set([...known, ...pinned])].sort((a, b) => b.length - a.length)
  let count = 0
  let out = text
  for (const v of knownSorted) {
    if (!out.includes(v)) continue
    if (pinnedShort.has(v)) {
      const re = new RegExp(`(?<![A-Za-z0-9])${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`, 'g')
      const before = out
      out = out.replace(re, () => mask(v, false))
      if (out !== before) (count++, hit('known'))
      continue
    }
    out = out.split(v).join(mask(v, false))
    count++
    hit('known')
  }
  return { text: out, count }
}

// ---------------------------------------------------------------------------
// Layer 1a: our own known formats (the whole match is masked).
const WHOLE: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g,
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g, // Anthropic
  /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, // OpenAI
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b/g, // AWS
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g, // GitLab
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack
  /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google
  /\bya29\.[0-9A-Za-z_-]{20,}/g, // Google OAuth
  /\b[sr]k_(?:live|test|prod)_[A-Za-z0-9]{10,}\b/g, // Stripe
  /\bwhsec_[A-Za-z0-9]{24,}\b/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g, // npm
  /\bpypi-[A-Za-z0-9_-]{50,}/g, // PyPI
  /\bhf_[A-Za-z0-9]{30,}\b/g, // Hugging Face
  /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, // SendGrid
  /\bkey-[0-9a-f]{32}\b/g, // Mailgun
  /\bdop_v1_[a-f0-9]{64}\b/g, // DigitalOcean
  /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, // Shopify
  /\b[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}/g, // Azure AD client secret
  /\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b/g, // Telegram bot
  /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g, // Firebase FCM server key
  /\b[A-Za-z0-9+\/]{86}==/g, // Azure storage account key
  /\b(?=[a-z2-7]*[2-7])(?=[a-z2-7]*[a-z])[a-z2-7]{52}\b/g, // Azure DevOps PAT (classic, base32)
  /\b[A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4}\b/g, // Azure DevOps PAT (new format)
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWT
  /\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}/g, // bcrypt hash
]

// ---------------------------------------------------------------------------
// Layer 1b: gitleaks' ruleset (hooks/gitleaks-rules.ts, generated).
type Compiled = { id: string; re: RegExp; path?: RegExp; keywords?: string[]; entropy?: number; group?: number; allow: { target: string; res: RegExp[]; stop: string[] }[] }

function compile(s: Src, global: boolean): RegExp | undefined {
  const g = global ? 'g' : ''
  try {
    return new RegExp(s.src, s.flags + g)
  } catch {
    if (!s.fb) return undefined
    try {
      return new RegExp(s.fb.src, s.fb.flags + g)
    } catch {
      return undefined
    }
  }
}

let gitleaks: Compiled[] | undefined
let globalAllow: RegExp[] = []
export let gitleaksSkipped: string[] = []

function compiledGitleaks(): Compiled[] {
  if (gitleaks) return gitleaks
  globalAllow = GITLEAKS_GLOBAL_ALLOW.regexes.map(r => compile(r, false)).filter((r): r is RegExp => !!r)
  gitleaks = []
  gitleaksSkipped = []
  for (const r of GITLEAKS_RULES) {
    const re = compile(r, true)
    if (!re) {
      gitleaksSkipped.push(r.id)
      continue
    }
    const allow = (r.allow ?? []).map(a => ({
      target: a.target,
      res: (a.regexes ?? []).map(x => compile(x, false)).filter((x): x is RegExp => !!x),
      stop: a.stopwords ?? [],
    }))
    const path = r.path ? compile(r.path, false) : undefined
    if (r.path && !path) {
      gitleaksSkipped.push(r.id)
      continue
    }
    gitleaks.push({ id: r.id, re, path, keywords: r.keywords, entropy: r.entropy, group: r.secretGroup, allow })
  }
  return gitleaks
}

function gitleaksAllowed(rule: Compiled, secret: string, match: string): boolean {
  const low = secret.toLowerCase()
  if (globalAllow.some(re => re.test(secret)) || GITLEAKS_GLOBAL_ALLOW.stopwords.some(w => low.includes(w))) return true
  for (const a of rule.allow) {
    const target = a.target === 'match' || a.target === 'line' ? match : secret
    if (a.res.some(re => re.test(target))) return true
    if (a.stop.some(w => low.includes(w))) return true
  }
  return false
}

function applyGitleaks(text: string, paths: readonly string[]): { text: string; count: number } {
  let count = 0
  let out = text
  let low = out.toLowerCase()
  for (const rule of compiledGitleaks()) {
    checkBudget()
    if (rule.path && !paths.some(p => rule.path!.test(p))) continue // a path-scoped rule needs its file
    if (rule.keywords && !rule.keywords.some(k => low.includes(k))) continue
    let changed = false
    const apply = (s: string) => s.replace(rule.re, (...args: unknown[]) => {
      const match = args[0] as string
      const hasNamed = typeof args[args.length - 1] === 'object'
      const groups = args.slice(1, hasNamed ? -3 : -2) as (string | undefined)[]
      const secret = rule.group ? groups[rule.group - 1] : (groups.find(g => g) ?? match)
      if (!secret || secret.includes(MASK) || isPlaceholderValue(secret)) return match
      if (rule.entropy && entropy(secret) < rule.entropy) return match
      if (gitleaksAllowed(rule, secret, match)) return match
      count++
      changed = true
      hit(`gitleaks:${rule.id}`)
      return match.replace(secret, mask(secret))
    })
    const windows = rule.keywords ? keywordWindows(low, rule.keywords) : undefined
    if (!windows) out = apply(out)
    else {
      // only the text around each keyword: a rule's lazy prefix is costly on a long text
      const parts: string[] = []
      let pos = 0
      for (const [a, b] of windows) {
        parts.push(out.slice(pos, a), apply(out.slice(a, b)))
        pos = b
      }
      parts.push(out.slice(pos))
      out = parts.join('')
    }
    if (changed) low = out.toLowerCase()
  }
  return { text: out, count }
}

// Spans of `low` around each keyword hit, merged, snapped to line starts; undefined for a
// short text, or one with so many hits that windows would not help.
const WIN_BEFORE = 160
const WIN_AFTER = 512
const WIN_MAX = 8192 // a span ends at the first space or quote past WIN_AFTER: a secret holds none
function keywordWindows(low: string, keywords: readonly string[]): [number, number][] | undefined {
  if (low.length < 8192) return undefined
  const hits: number[] = []
  for (const k of keywords) {
    for (let i = low.indexOf(k); i !== -1; i = low.indexOf(k, i + k.length)) {
      hits.push(i)
      if (hits.length > 4096) return undefined
    }
  }
  hits.sort((x, y) => x - y)
  const out: [number, number][] = []
  for (const i of hits) {
    let a = Math.max(0, i - WIN_BEFORE)
    const nl = low.lastIndexOf('\n', i)
    if (nl >= a) a = nl + 1
    let b = Math.min(low.length, i + WIN_AFTER)
    const stop = low.slice(b, Math.min(low.length, i + WIN_MAX)).search(/[\s"'`]/)
    b = stop === -1 ? Math.min(low.length, i + WIN_MAX) : b + stop
    const last = out[out.length - 1]
    if (last && a <= last[1]) last[1] = Math.max(last[1], b)
    else out.push([a, b])
  }
  return out
}

// ---------------------------------------------------------------------------
// Layer 2: secret-named fields. The name stays, the value is masked.
// The name's last word decides: dbPassword, SENDGRID_API_KEY, clientSecret, ...
const SECRET_LAST = new Set([
  'password', 'passwd', 'pwd', 'passphrase', 'secret', 'secrets', 'token', 'pat', 'credential',
  'credentials', 'dsn', 'sig', 'signature', 'apikey', 'accesskey', 'secretkey', 'privatekey',
  'accesstoken', 'refreshtoken', 'idtoken', 'authtoken', 'apitoken', 'apisecret', 'clientsecret',
  'connectionstring', 'connstr', 'sastoken', 'webhooksecret', 'authorization',
])
const KEY_QUALIFIER = new Set([
  'api', 'secret', 'private', 'access', 'account', 'signing', 'encryption', 'enc', 'jwt', 'client',
  'master', 'license', 'sas', 'storage', 'subscription', 'shared', 'auth', 'app', 'server', 'service',
  'webhook', 'consumer', 'merchant', 'hmac', 'aes', 'rsa', 'ssh', 'gpg', 'deploy', 'admin', 'maps',
])
const NOT_SECRET_TOKEN = new Set(['cancellation', 'continuation', 'next', 'page', 'lexer', 'sync', 'i18n', 'design', 'csrf', 'xsrf'])

function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[\s_.\-:]+/)
    .map(w => w.toLowerCase())
    .filter(Boolean)
}

export function isSecretName(name: string): boolean {
  const w = words(name)
  const last = w.at(-1) ?? ''
  const prev = w.at(-2) ?? ''
  if (last === 'token' && NOT_SECRET_TOKEN.has(prev)) return false
  if (SECRET_LAST.has(last)) return true
  if (SECRET_LAST.has(prev + last)) return true // api_key, access_token
  if (last === 'key' && KEY_QUALIFIER.has(prev)) return true
  if (last === 'string' && prev === 'connection') return true
  if (last === 'pass' && w.length <= 2) return true
  return false
}

// Is the value a code expression (variable, call, type) rather than a literal?
const CODE_TYPE = /^(?:string|number|boolean|any|unknown|null|undefined|void|never|true|false|[A-Z][A-Za-z]*(?:<.*>)?(?:\[\])?\??)[,;)]?$/
const CODE_EXPR = /^(?:[$@{[(]|new\b|await\b|this\b|[A-Za-z_][\w]*(?:\.[\w]+)*\s*[([]|[a-z_][\w]*\.[\w.]+$)/
const CONSTANT_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/
// Quoted values that are not secrets: a URL path ("/api/user/change-password"), a CONSTANT_NAME
const QUOTED_NOT_SECRET = /^(?:\/[\w\-\/{}:.]*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$/
// A value that spells its own name is an enum / error code: INVALID_REFRESH_TOKEN = "invalid_refresh_token"
const spellsName = (name: string, v: string) => words(name).join('') === words(v).join('')

// name, separator, value: quoted or not
const ASSIGN = /(["']?)\b([A-Za-z_][A-Za-z0-9_.-]{0,63})\1(\s*)(:|=)(?!=)(\s*)(?:(["'`])([^"'`\n]*)\6|([^\s"'`,;<>)]+))/g

function assignments(text: string, depth = 0): { text: string; count: number } {
  let count = 0
  const out = text.replace(ASSIGN, (m, q1, name: string, sp1: string, op: string, sp2: string, quote?: string, qval?: string, uval?: string) => {
    const head = `${q1}${name}${q1}${sp1}${op}${sp2}`
    if (quote !== undefined) {
      const v = qval ?? ''
      if (isSecretName(name) && v.length >= 4 && !v.includes(MASK) && !/^[a-z]{1,7}$/i.test(v) && !QUOTED_NOT_SECRET.test(v) && !spellsName(name, v) && !isPlaceholderValue(v)) {
        count++
        hit('field')
        return head + quote + mask(v) + quote
      }
      // a name that is not secret may still hold one inside: "Default": "Server=..;Password=..;"
      if (depth < 2 && /[=:]/.test(v)) {
        const r = assignments(v, depth + 1)
        count += r.count
        return head + quote + r.text + quote
      }
      return m
    }
    const v = uval ?? ''
    if (!isSecretName(name) || v.length < 4 || v.includes(MASK) || isPlaceholderValue(v)) return m
    if (/^(?:Bearer|Basic|Token)$/i.test(v)) return m // the header rule below masks it
    if (CODE_EXPR.test(v) || CONSTANT_NAME.test(v) || /^(?:async|function|[a-z]+[A-Z][A-Za-z]*)$/.test(v)) return m // code
    if (op === '=' && (sp1 || sp2)) return m // `token = foo`: a code assignment
    if (op === ':' && CODE_TYPE.test(v)) return m // `token: CancellationToken`
    // an unquoted plain word (`api-key: entropy`) is prose, not a secret
    if (v.length < 16 && /^[a-z]+$/i.test(v)) return m
    count++
    hit('field')
    return head + mask(v)
  })
  return { text: out, count }
}

const KEEP_NAME: RegExp[] = [
  /((?:\b[Bb]earer|\bBasic|Authorization:\s*Token)\s+)(?=\S*\d)([A-Za-z0-9._~+\/=-]{16,})/g, // Authorization header
  /((?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:\/@]{0,256}:)([^\s@\/]+)(?=@)/gi, // scheme://user:pass@host
  /(\/\/[^\s\/]+\/:_authToken=)(\S+)/g, // .npmrc
  /([?&](?:token|access_token|api[_-]?key|key|sig|signature|code|password|secret)=)([^&\s"'#]{8,})/gi, // URL query
  /(\bdiscord(?:app)?\.com\/api\/webhooks\/\d+\/)([\w-]{20,})/g, // Discord webhook
  /("auth"\s*:\s*")([A-Za-z0-9+\/]{20,}={0,2})(?=")/g, // docker config.json
]

// ---------------------------------------------------------------------------
// Layer 3: entropy, for long random-looking tokens with no known format or label.
const CANDIDATE = /[A-Za-z0-9_\-+=.~]{24,}/g
const HASH_CONTEXT = /integrity|contenthash|sha\d+[-.:]|checksum|digest|"hash"|\bcommit\b|revision|etag|\bh1:|;base64,/i

function entropy(s: string): number {
  const freq = new Map<string, number>()
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

function cls(c: string): number {
  if (c >= 'a' && c <= 'z') return 0
  if (c >= 'A' && c <= 'Z') return 1
  if (c >= '0' && c <= '9') return 2
  return 3
}

export function looksRandom(tok: string): boolean {
  const t = tok.replace(/^[._~=-]+|[._~=-]+$/g, '')
  if (t.length < 24) return false
  if (/^[0-9a-f]+$/i.test(t)) return false // git SHA, hex hash
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return false // UUID
  if (/^[A-Z0-9_]+$/.test(t) && t.includes('_')) return false // ENV_VAR_NAME
  if (t.includes('.') && /^[a-z0-9.-]+$/i.test(t) && /\.[a-z]{2,}$/i.test(t)) return false // domain, file name
  // no piece mixes letters and digits: words and dates joined (a migration name)
  if (!t.split(/[_.\-+=~]/).some(p => /[A-Za-z]/.test(p) && /[0-9]/.test(p))) return false
  // mostly readable words: a code identifier (StatusCodes.Status401Unauthorized)
  const wordChars = (t.match(/[A-Z]?[a-z]{3,}/g) ?? []).reduce((n, w) => n + w.length, 0)
  if (/[A-Z]/.test(t) && wordChars >= t.length * 0.5) return false
  // URL slug / kebab-case: most dash-separated pieces are plain words or numbers
  const pieces = t.split(/[-_.]/)
  const plain = pieces.filter(p => /^(?:[a-z]{2,}|[0-9]+)$/i.test(p)).reduce((n, p) => n + p.length, 0)
  if (pieces.length >= 3 && plain >= t.length * 0.55) return false
  const digits = (t.match(/[0-9]/g) ?? []).length
  const letters = (t.match(/[A-Za-z]/g) ?? []).length
  if (digits < (t.length >= 32 ? 2 : 3) || letters < 6) return false
  let changes = 0
  for (let i = 1; i < t.length; i++) if (cls(t[i]!) !== cls(t[i - 1]!)) changes++
  if (changes < t.length * 0.12) return false
  return entropy(t) >= 3.7
}

// ---------------------------------------------------------------------------
// Env mode: every value.
const ENV_LINE = /^(\s*(?:export\s+)?["']?[A-Za-z_][A-Za-z0-9_.-]*["']?\s*(?:=|:\s))(.*\S.*)$/
const ENV_SAFE_NAME =
  /^(?:PATH|HOME|SHELL|USER|LOGNAME|PWD|OLDPWD|LANG|LC_\w+|TERM|TERM_\w+|TMPDIR|SHLVL|EDITOR|COLORTERM|_|NODE_ENV|ASPNETCORE_ENVIRONMENT|PORT)$/
const ENV_SAFE_VALUE = /^["']?(?:true|false|null|yes|no|on|off|\d+(?:\.\d+)?)?["']?$/i

// Secret files that are not KEY=value: .pgpass (host:port:db:user:password), .netrc
const PGPASS_LINE = /^(?![^:]*=)((?:[^:\s#]|\\:)+:(?:[^:\s]|\\:)+:(?:[^:\s]|\\:)+:(?:[^:\s]|\\:)+:)(\S.*)$/
const NETRC_PASSWORD = /(\b(?:password|passwd|account)\s+)(\S+)/g

function envLine(line: string): { line: string; hit: boolean } {
  const pg = PGPASS_LINE.exec(line)
  if (pg && !isPlaceholderValue(pg[2]!, true) && !pg[2]!.includes(MASK)) {
    hit('env')
    return { line: pg[1] + mask(pg[2]!), hit: true }
  }
  if (/^\s*(?:machine|default)\b/.test(line) || /^\s*(?:login|password)\s/.test(line)) {
    let n = 0
    const out = line.replace(NETRC_PASSWORD, (m, head: string, v: string) => (v.includes(MASK) || isPlaceholderValue(v, true) ? m : (n++, head + mask(v))))
    if (n > 0) {
      hit('env')
      return { line: out, hit: true }
    }
  }
  const m = ENV_LINE.exec(line)
  if (!m) return { line, hit: false }
  const name = m[1]!.replace(/^\s*(?:export\s+)?["']?|["']?\s*(?:=|:\s)$/g, '')
  const value = m[2]!.trim()
  if (ENV_SAFE_NAME.test(name) || ENV_SAFE_VALUE.test(value) || value.includes(MASK) || isPlaceholderValue(value, true)) {
    return { line, hit: false }
  }
  hit('env')
  return { line: m[1] + mask(m[2]!), hit: true }
}

/**
 * Seeds layer 0 from a .env-style file's text: each value is remembered, so it is
 * masked wherever it shows up later (logs, stack traces, base64 in a config dump).
 * What is taken follows `remember`'s rules (no identifiers, no plain URLs).
 */
// A seeded value that reads like code is a decoy a cloned repository could plant to hide
// that code (`exec(req.query.cmd)`, `isAdmin || true`): real values do not look like this.
const CODE_LIKE = /\s|[A-Za-z_$][\w$.]*\(|\|\||&&|=>|\bthis\.|\breturn\b|[{}]/
const MAX_SEED_PER_FILE = 100

export function seedEnvText(text: string): number {
  let n = 0
  let tried = 0
  for (const line of text.split('\n')) {
    if (seeded >= MAX_SEEDED || tried >= MAX_SEED_PER_FILE) break
    if (/^\s*#/.test(line)) continue
    const m = ENV_LINE.exec(line)
    if (!m) continue
    const name = m[1]!.replace(/^\s*(?:export\s+)?["']?|["']?\s*(?:=|:\s)$/g, '')
    let v = m[2]!.trim()
    const q = /^(["'])(.*)\1$/.exec(v)
    v = q ? q[2]! : v.replace(/\s+#.*$/, '')
    if (ENV_SAFE_NAME.test(name) || ENV_SAFE_VALUE.test(v) || isPlaceholderValue(v) || CODE_LIKE.test(v)) continue
    tried++
    const before = known.size
    remember(v)
    if (known.size > before) {
      n++
      seeded++
    }
  }
  return n
}

/** .env-style files: every value in them is treated as a secret. */
export const ENV_FILE =
  /(?:^|[\/\s"'=])(?:\.env(?:\.[\w-]+)*|[\w-]+\.env|\.npmrc|\.yarnrc(?:\.yml)?|\.netrc|\.pgpass|\.pypirc|\.git-credentials|credentials(?:\.json)?|secrets?\.(?:json|ya?ml|env)|\.dev\.vars|local\.settings\.json)(?=$|[\s"':;|&)>])/i

const isTemplateEnvFile = (path: string) => /\.(?:example|sample|template|dist|defaults?)$/i.test(path)
export const isEnvFile = (path: string) => ENV_FILE.test(path) && !isTemplateEnvFile(path.trim())

// grep output "path:line:text" / "path:text": split at the first ':' or '-' where
// the path so far is an env file (the path itself may contain '-').
function grepSplit(line: string): { head: string; rest: string } | undefined {
  for (let i = 0; i < Math.min(line.length, 512); i++) {
    const c = line[i]
    if (c !== ':' && c !== '-') continue
    const path = line.slice(0, i)
    if (/\s/.test(path)) return undefined
    if (!isEnvFile(path)) continue
    const num = /^(\d+[:-])?/.exec(line.slice(i + 1))![0]
    return { head: line.slice(0, i + 1) + num, rest: line.slice(i + 1 + num.length) }
  }
  return undefined
}

// ---------------------------------------------------------------------------
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07/g
const MAX_LINE = 20000

/**
 * `paths`: the files the output may have come from (path-scoped gitleaks rules need them).
 * `sources`: the files the output certainly is the content of (a Read's file): values masked
 * in it may be restored into these files, and only these.
 */
export type Options = { envMode?: boolean; paths?: readonly string[]; sources?: readonly string[] }

function redactLine(line: string, opts: Options): { line: string; count: number } {
  let count = 0
  const g = grepSplit(line)
  if (g) {
    const r = envLine(g.rest)
    if (r.hit) {
      count++
      line = g.head + r.line
    }
  } else if (opts.envMode) {
    const r = envLine(line)
    if (r.hit) count++
    line = r.line
  }
  if (!HASH_CONTEXT.test(line)) line = line.replace(CANDIDATE, tok => (looksRandom(tok) ? (count++, hit('entropy'), mask(tok, false)) : tok))
  return { line, count }
}

export function redact(text: string, opts: Options = {}): { text: string; count: number } {
  currentSources = opts.sources ?? []
  try {
    return redactAll(text, opts)
  } finally {
    currentSources = []
  }
}

function redactAll(text: string, opts: Options): { text: string; count: number } {
  let count = 0
  let out = text.includes('\x1b') ? text.replace(ANSI, '') : text

  const k = maskKnown(out)
  out = k.text
  count += k.count

  for (const re of WHOLE) out = out.replace(re, (m: string) => (count++, hit('format'), mask(m)))

  const gl = applyGitleaks(out, opts.paths ?? [])
  out = gl.text
  count += gl.count

  const a = assignments(out)
  out = a.text
  count += a.count

  for (const re of KEEP_NAME) {
    out = out.replace(re, (m, name: string, value: string) => {
      if (value.startsWith(MASK) || isPlaceholderValue(value)) return m
      count++
      hit('header-url')
      return name + mask(value)
    })
  }

  // per line; a very long line (minified code, a blob) is handled in pieces
  checkBudget()
  out = out
    .split('\n')
    .map((line, i) => {
      if (i % 512 === 0) checkBudget()
      if (line.length <= MAX_LINE) {
        const r = redactLine(line, opts)
        count += r.count
        return r.line
      }
      let joined = ''
      for (let i = 0; i < line.length; i += MAX_LINE) {
        const r = redactLine(line.slice(i, i + MAX_LINE), { envMode: false })
        count += r.count
        joined += r.line
      }
      return joined
    })
    .join('\n')

  return { text: out, count }
}
