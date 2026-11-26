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
// into real values.
export const MASK = '[REDACTED'
const PLACEHOLDER = /\[REDACTED:[0-9a-f]{8}\]/
const vault = new Map<string, string>()

function fnv(s: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

/**
 * Masks a value. `learn`: also mask it wherever it shows up later. Off for the
 * entropy layer, a guess: one false positive there must not spread.
 */
export function mask(value: string, learn = true): string {
  let id = fnv(value)
  while (vault.has(id) && vault.get(id) !== value) id = fnv(id + value)
  vault.set(id, value)
  if (learn) remember(value)
  return `${MASK}:${id}]`
}

export const hasPlaceholder = (text: string) => PLACEHOLDER.test(text)

/** Hits per layer / rule (`gitleaks:<id>`, `field`, `entropy`, ...): for tests and tuning. */
export const hits = new Map<string, number>()
const hit = (k: string) => hits.set(k, (hits.get(k) ?? 0) + 1)

/** Turns placeholders back into real values; lists the ones it does not know. */
export function restore(text: string): { text: string; missing: string[] } {
  const missing: string[] = []
  const out = text.replace(/\[REDACTED:([0-9a-f]{8})\]/g, (m, id: string) => {
    const v = vault.get(id)
    if (v === undefined) {
      missing.push(m)
      return m
    }
    return v
  })
  return { text: out, missing }
}

// ---------------------------------------------------------------------------
// Values that are obviously not secrets: placeholders, templates, examples.
const PLACEHOLDER_WORDS =
  /^(?:password|passwd|passw0rd|changeme|change_me|changeit|example|sample|dummy|test|testing|redacted|secret|token|placeholder|none|null|empty|undefined|default|admin|admin123|root|letmein|qwerty|123456|12345678|your[_-]?\w+|my[_-]?\w+|insert[_-]?\w+|enter[_-]?\w+|todo|tbd|fixme|foo|bar|baz|xxx+|\*+|\.+|-+)$/i
const TEMPLATE =
  /^(?:\$\w+|\$\{[^}]*\}|\$\{\{[^}]*\}\}|\{\{[^}]*\}\}|%\w+%|@\w+@|<[^>]*>|\{\d{0,2}\}|%[+\-# 0]?[a-zA-Z]|\$\(.*\))$/
const REPEATED = /^(.)\1*$/

export function isPlaceholderValue(v: string): boolean {
  const t = v.trim().replace(/^["'`]|["'`]$/g, '')
  return t === '' || PLACEHOLDER_WORDS.test(t) || TEMPLATE.test(t) || REPEATED.test(t)
}

// ---------------------------------------------------------------------------
// Layer 0: known values, with encoded variants.
const known = new Set<string>()
let knownSorted: string[] | undefined
const MAX_KNOWN = 2000

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
  if (known.size >= MAX_KNOWN || !isDistinctive(v)) return
  const variants = [v, b64(v), b64(v, true).replace(/=+$/, ''), encodeURIComponent(v)]
  for (const x of variants) if (x.length >= 8 && !known.has(x)) known.add(x)
  knownSorted = undefined
}

function maskKnown(text: string): { text: string; count: number } {
  if (known.size === 0) return { text, count: 0 }
  knownSorted ??= [...known].sort((a, b) => b.length - a.length)
  let count = 0
  let out = text
  for (const v of knownSorted) {
    if (!out.includes(v)) continue
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
    if (rule.path && !paths.some(p => rule.path!.test(p))) continue // a path-scoped rule needs its file
    if (rule.keywords && !rule.keywords.some(k => low.includes(k))) continue
    let changed = false
    out = out.replace(rule.re, (...args: unknown[]) => {
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
    if (changed) low = out.toLowerCase()
  }
  return { text: out, count }
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
const ASSIGN = /(["']?)\b([A-Za-z_][A-Za-z0-9_.-]*)\1(\s*)(:|=)(?!=)(\s*)(?:(["'`])([^"'`\n]*)\6|([^\s"'`,;<>)]+))/g

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
  /([a-z][a-z0-9+.-]*:\/\/[^\s:\/@]*:)([^\s@\/]+)(?=@)/gi, // scheme://user:pass@host
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

function envLine(line: string): { line: string; hit: boolean } {
  const m = ENV_LINE.exec(line)
  if (!m) return { line, hit: false }
  const name = m[1]!.replace(/^\s*(?:export\s+)?["']?|["']?\s*(?:=|:\s)$/g, '')
  const value = m[2]!.trim()
  if (ENV_SAFE_NAME.test(name) || ENV_SAFE_VALUE.test(value) || value.includes(MASK) || isPlaceholderValue(value)) {
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
export function seedEnvText(text: string): number {
  let n = 0
  for (const line of text.split('\n')) {
    if (/^\s*#/.test(line)) continue
    const m = ENV_LINE.exec(line)
    if (!m) continue
    const name = m[1]!.replace(/^\s*(?:export\s+)?["']?|["']?\s*(?:=|:\s)$/g, '')
    let v = m[2]!.trim()
    const q = /^(["'])(.*)\1$/.exec(v)
    v = q ? q[2]! : v.replace(/\s+#.*$/, '')
    if (ENV_SAFE_NAME.test(name) || ENV_SAFE_VALUE.test(v) || isPlaceholderValue(v)) continue
    const before = known.size
    remember(v)
    if (known.size > before) n++
  }
  return n
}

/** .env-style files: every value in them is treated as a secret. */
export const ENV_FILE =
  /(?:^|[\/\s"'=])(?:\.env(?:\.[\w-]+)*|[\w-]+\.env|\.npmrc|\.yarnrc(?:\.yml)?|\.netrc|\.pgpass|\.pypirc|\.git-credentials|credentials(?:\.json)?|secrets?\.(?:json|ya?ml|env)|\.dev\.vars|local\.settings\.json)(?=$|[\s"':;|&)>])/

const isTemplateEnvFile = (path: string) => /\.(?:example|sample|template|dist|defaults?)$/i.test(path)
export const isEnvFile = (path: string) => ENV_FILE.test(path) && !isTemplateEnvFile(path.trim())

// grep output "path:line:text" / "path:text": split at the first ':' or '-' where
// the path so far is an env file (the path itself may contain '-').
function grepSplit(line: string): { head: string; rest: string } | undefined {
  for (let i = 0; i < line.length; i++) {
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

/** `paths`: the files the output came from, when known (path-scoped gitleaks rules need them). */
export type Options = { envMode?: boolean; paths?: readonly string[] }

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
  out = out
    .split('\n')
    .map(line => {
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
