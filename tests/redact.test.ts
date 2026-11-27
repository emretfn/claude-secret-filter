// Unit tests for hooks/redact.ts: what must be masked, what must be left alone.
// Every secret here is generated at run time: no real-looking token is committed
// (it would trip secret scanners), and prefixes are split for the same reason.
// A placeholder literal is built at run time too: the mod refuses to write one it does not know.
import { expect, test } from 'claude-code/testing'
import { GITLEAKS_RULES } from '../hooks/gitleaks-rules'
import { gitleaksSkipped, hasPlaceholder, isSecretName, looksRandom, redact, remember, restore, seedEnvText, sha256hex, withBudget } from '../hooks/redact'

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
const rnd = (n: number, alphabet = ALNUM) => Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('')
const masked = (s: string, opts = {}) => redact(s, opts).count > 0
const kept = (s: string, opts = {}) => redact(s, opts).count === 0
const unknownPlaceholder = '[REDACTED' + ':deadbeef]'

// --- known formats ----------------------------------------------------------
test('known provider formats are masked', () => {
  const cases: Record<string, string> = {
    anthropic: 'sk-' + 'ant-api03-' + rnd(40),
    openai: 'sk-' + 'proj-' + rnd(48),
    aws: 'AKIA' + rnd(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
    github: 'gh' + 'p_' + rnd(36),
    gitlab: 'glp' + 'at-' + rnd(20),
    slack: 'xo' + 'xb-' + rnd(10, '0123456789') + '-' + rnd(24),
    stripe: 'sk' + '_live_' + rnd(24),
    npm: 'np' + 'm_' + rnd(36),
    huggingface: 'h' + 'f_' + rnd(34),
    azureDevOpsPat: rnd(52, B32).replace(/^./, 'a').replace(/.$/, '7'),
    jwt: 'ey' + 'J' + rnd(20) + '.ey' + 'J' + rnd(30) + '.' + rnd(43),
    privateKey: '-----BEGIN ' + 'PRIVATE KEY-----\n' + rnd(64) + '\n-----END ' + 'PRIVATE KEY-----',
  }
  for (const [name, secret] of Object.entries(cases)) {
    const r = redact(`value: ${secret} end`)
    expect([name, r.text.includes(secret)]).toEqual([name, false])
    expect([name, hasPlaceholder(r.text)]).toEqual([name, true])
  }
})

test('every gitleaks rule compiles (natively or through its fallback)', () => {
  redact('warm up') // compiles the ruleset
  expect(gitleaksSkipped).toEqual([])
  expect(GITLEAKS_RULES.length).toBeGreaterThan(200)
})

test('gitleaks rules mask provider tokens we have no own rule for', () => {
  const cases: Record<string, string> = {
    sentry: 'sntr' + 'yu_' + rnd(64, '0123456789abcdef'),
    doppler: 'dp.' + 'pt.' + rnd(43),
    linear: 'lin_' + 'api_' + rnd(40),
    postman: 'PM' + 'AK-' + rnd(24, '0123456789abcdef') + '-' + rnd(34, '0123456789abcdef'),
  }
  for (const [name, secret] of Object.entries(cases)) {
    expect([name, redact(`token ${secret}`).text.includes(secret)]).toEqual([name, false])
  }
})

test('path-scoped gitleaks rules run only on their own files', () => {
  const nuget = `<add key="ClearTextPassword" value="${rnd(16)}9" />`
  expect(masked(nuget, { paths: ['/repo/NuGet.Config'] })).toBe(true)
  // the same kind of rule must not fire on C# constants when no matching file is involved
  expect(kept('public const string FORGET_PASSWORD = "forget-password";')).toBe(true)
})

// --- named fields -----------------------------------------------------------
test('secret-named fields are masked, the name is kept', () => {
  const pw = rnd(14) + '7x'
  const cases = [
    `"ConnectionStrings": { "Default": "Server=db;Database=app;User Id=sa;Password=${pw};" }`,
    `password: ${pw}`,
    `docker login --password=${pw}`,
    `"clientSecret": "${pw}"`,
    `"JwtKey": "my-super-long-signing-secret"`,
    `https://user:${pw}@example.com/repo.git`,
    `Authorization: Bearer ${rnd(32)}`,
    `https://x.blob.core.windows.net/c?sv=2020&sig=${rnd(20)}`,
  ]
  for (const c of cases) expect([c, masked(c)]).toEqual([c, true])
  expect(redact(`"clientSecret": "${pw}"`).text.startsWith('"clientSecret": "')).toBe(true)
})

test('isSecretName reads the last word of the name', () => {
  for (const n of ['dbPassword', 'SENDGRID_API_KEY', 'clientSecret', 'access_token', 'privateKey', 'ConnectionString']) {
    expect([n, isSecretName(n)]).toEqual([n, true])
  }
  for (const n of ['cancellationToken', 'i18nKey', 'savedProfileKey', 'pathname', 'passwordPolicy', 'tokenCount']) {
    expect([n, isSecretName(n)]).toEqual([n, false])
  }
})

// --- false positives: code, docs and data that must stay readable ------------
test('code, docs and data stay readable', () => {
  const lines = [
    'commit 3f8a9c1d2e4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c',
    'id: 550e8400-e29b-41d4-a716-446655440000',
    '20240315123456_AddUserProfilesTable.cs',
    'const getCustomerOrderHistoryByUserId = 1',
    '/Users/me/projects/app/src/Api/Program.cs',
    'NODE_ENV=production',
    '"key": "settings.profile.title"',
    '"contentHash": "Kh7Sd3+qJf8mL2pQ9rT4vX6yZ1aB3cD5eF7gH9iJ0kL="',
    'used token count is 5 and password policy',
    '@react-navigation/native-stack@6.9.17',
    'Task Handle(Command request, CancellationToken cancellationToken)',
    'var signature = ComputeHmac(payload, key);',
    'token: CancellationToken,',
    'router.push({ pathname: "/checkout/payment" })',
    '<Trans i18nKey="auth.register.title" />',
    'StatusCode = StatusCodes.Status401Unauthorized',
    'fetch(url, { credentials: "include" })',
    'ChangePassword: "/api/user/change-password",',
    'INVALID_REFRESH_TOKEN = "invalid_refresh_token"',
    '"private_key": PEM_RE,',
    'generic-api-key: entropy 3.5',
    'GH_TOKEN=<keychain-reference>',
    'DATABASE_URL=postgres://user:password@localhost:5432/db',
    'API_KEY=${API_KEY}',
    'secret: ${{ secrets.DEPLOY_KEY }}',
    'golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=',
    'https://dev.to/someone/how-we-built-it-in-2024-part-2-ab12',
    'https://dev.to/someone/stop-sending-your-env-to-openai-a-privacy-layer-for-opencode-3kc3',
  ]
  for (const l of lines) expect([l, redact(l).text]).toEqual([l, l])
})

// --- entropy ----------------------------------------------------------------
test('entropy layer catches most unknown random tokens', () => {
  for (const [len, maxMiss] of [[40, 0.05], [52, 0.03]] as const) {
    let miss = 0
    for (let i = 0; i < 500; i++) if (!looksRandom(rnd(len))) miss++
    expect([len, miss / 500 <= maxMiss]).toEqual([len, true])
  }
})

test('an entropy guess does not spread to other outputs', () => {
  const tok = rnd(40)
  redact(`opaque ${tok}`)
  // the guessed token is not learned: a short, word-like reuse of it stays visible
  expect(redact(`pool: ${tok.slice(0, 20)}`).count).toBe(0)
})

// --- env mode, grep ---------------------------------------------------------
test('env mode masks every value except safe ones', () => {
  const text = ['NODE_ENV=development', 'PORT=3000', 'DATABASE_HOST=db.internal.example', 'SMTP_USER=mailer@example.com', 'FEATURE_FLAG=true'].join('\n')
  const lines = redact(text, { envMode: true }).text.split('\n')
  expect(lines[0]).toBe('NODE_ENV=development')
  expect(lines[1]).toBe('PORT=3000')
  expect(lines[2]).toMatch(/^DATABASE_HOST=\[REDACTED:[0-9a-f]{8}\]$/)
  expect(lines[3]).toMatch(/^SMTP_USER=\[REDACTED:[0-9a-f]{8}\]$/)
  expect(lines[4]).toBe('FEATURE_FLAG=true')
})

test('grep lines from env files are masked, other files are not', () => {
  expect(masked('/private/tmp/a-b/-Users-x/.env.test:4:SMTP_USER=mailer@example.com')).toBe(true)
  expect(masked('apps/web/.env.production:API_BASE=https://api.example.com')).toBe(true)
  expect(kept('apps/web/.env.example:API_BASE=https://api.example.com')).toBe(true)
  expect(kept('src/app.ts:12:const PORT_NAME=hello')).toBe(true)
})

// --- known values, placeholders ---------------------------------------------
test('a remembered value is masked anywhere, also base64 and URL-encoded', () => {
  const v = 'S3cret!' + rnd(12)
  remember(v)
  expect(redact(`log: connecting with ${v}`).text.includes(v)).toBe(false)
  const b64 = btoa(v)
  expect(redact(`config dump ${b64}`).text.includes(b64)).toBe(false)
  const enc = encodeURIComponent(v)
  expect(redact(`GET /cb?state=${enc}`).text.includes(enc)).toBe(false)
})

test('seeding from a secret file learns real values, not decoys', () => {
  const key = 'Zq' + rnd(20) + '4'
  const host = 'db-' + rnd(6).toLowerCase() + '7.internal'
  const n = seedEnvText([
    '# comment',
    `API_KEY="${key}"`,
    `DB_HOST=${host}  # inline comment`,
    'NODE_ENV=production',
    'PUBLIC_URL=https://www.example.com/app',
    'HOOK_NAME=useLayoutEffect',
    'PASSWORD=changeme',
  ].join('\n'))
  expect(n).toBe(2)
  expect(redact(`Error: auth failed for key ${key}`).text.includes(key)).toBe(false)
  expect(redact(`connecting to ${host}:5432`).text.includes(host)).toBe(false)
  expect(kept('see https://www.example.com/app for docs')).toBe(true)
  expect(kept('useLayoutEffect(() => {}, [])')).toBe(true)
})

test('plain words are never remembered (decoy protection)', () => {
  remember('useEffect')
  expect(kept('import { useEffect } from "react"')).toBe(true)
})

test('placeholders round-trip: masked for the model, restored for the write', () => {
  const pw = rnd(16) + '9'
  const pat = rnd(52, B32).replace(/^./, 'a').replace(/.$/, '7')
  const file = `{\n  "Db": "Server=db;Password=${pw};",\n  "Pat": "${pat}",\n  "LogLevel": "Information"\n}`
  const seen = redact(file, { sources: ['/app/appsettings.json'] }).text
  expect(seen.includes(pw) || seen.includes(pat)).toBe(false)
  const oldS = seen.split('\n').slice(1, 4).join('\n')
  const back = restore(oldS, '/app/appsettings.json')
  expect(back.missing).toEqual([])
  expect(back.foreign).toEqual([])
  expect(file.includes(back.text)).toBe(true)
  // only into the file it was read from
  expect(restore(oldS, '/app/other.json').foreign.length).toBeGreaterThan(0)
  expect(restore(unknownPlaceholder, '/app/appsettings.json').missing).toEqual([unknownPlaceholder])
})

test('the same value always gets the same placeholder', () => {
  const v = `Password=${rnd(16)}1;`
  expect(redact(v).text).toBe(redact(v).text)
})

// --- robustness -------------------------------------------------------------
test('ANSI colour codes do not split a token', () => {
  const tok = 'gh' + 'p_' + rnd(36)
  const colored = `\x1b[31m${tok}\x1b[0m`
  expect(redact(colored).text.includes(tok)).toBe(false)
})

test('a large output is redacted quickly', () => {
  const big = Array.from({ length: 5000 }, (_, i) => `line ${i}: const value${i} = compute(${i}) // ${rnd(20)}`).join('\n')
  const t0 = Date.now()
  redact(big)
  expect(Date.now() - t0).toBeLessThan(5000)
})

// --- hostile input ------------------------------------------------------------
test('adversarial long lines are redacted in linear time', () => {
  const cases = ['a.'.repeat(80000), 'a'.repeat(160000), 'a-'.repeat(80000), '-'.repeat(160000), 'x:'.repeat(80000), 'Bearer 1'.repeat(20000)]
  for (const c of cases) {
    const t0 = Date.now()
    redact(c)
    expect(Date.now() - t0).toBeLessThan(1500)
  }
})

test('seeding skips values that read like code (decoys)', () => {
  const n = seedEnvText(['CMD=exec(req.query.cmd)', 'CHECK=isAdmin||true', 'FN=x=>x', 'OK=' + 'Zq' + rnd(18) + '4'].join('\n'))
  expect(n).toBe(1)
  expect(kept('const out = exec(req.query.cmd)')).toBe(true)
  expect(kept('if (isAdmin||true) allow()')).toBe(true)
})

test('placeholder ids do not reveal the value (keyed per session)', () => {
  // the id of a known value is not its plain hash: offline guessing needs the session key
  const v = 'Password=' + rnd(12) + '1;'
  const id = /\[REDACTED:([0-9a-f]{8})\]/.exec(redact(v).text)![1]!
  expect(id).not.toBe(sha256hex(v.slice(9, -1)).slice(0, 8))
  expect(sha256hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
})

test('rules keyed to words run around those words: a long text full of them stays fast', () => {
  const kws = [...new Set(GITLEAKS_RULES.flatMap(r => r.keywords ?? []))].join(' ')
  for (const c of [kws + ' ' + 'a'.repeat(200000), (kws + ' ').repeat(20) + 'ab1_'.repeat(50000)]) {
    const t0 = Date.now()
    redact(c)
    expect(Date.now() - t0).toBeLessThan(2000)
  }
})

test('past its budget, redaction throws (the hook then withholds the output)', () => {
  const big = Array.from({ length: 20000 }, (_, i) => `line ${i} token=${rnd(30)}`).join('\n')
  expect(() => withBudget(1, () => redact(big))).toThrow()
})

test('a secret kept in place in a gitleaks keyword window is still masked', () => {
  const tok = 'gh' + 'p_' + rnd(36)
  const text = 'x '.repeat(10000) + `github token ${tok} ` + 'y '.repeat(10000)
  expect(redact(text).text.includes(tok)).toBe(false)
})

test('non-ASCII text before a secret does not shift the keyword spans', () => {
  const tok = 'gh' + 'p_' + rnd(36)
  const text = 'İ'.repeat(700) + ' ' + 'x '.repeat(5000) + `github token ${tok} ` + 'y '.repeat(5000)
  expect(redact(text).text.includes(tok)).toBe(false)
})

test('PEM keys: masked whole, and a text of BEGIN lines with no END is quick', () => {
  const body = Array.from({ length: 10 }, () => rnd(64)).join('\n')
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`
  expect(redact(`key:\n${pem}\nafter`).text).toMatch(/^key:\n\[REDACTED:[0-9a-f]{8}\]\nafter$/)
  const hostile = '-----BEGIN RSA PRIVATE KEY-----\n'.repeat(30000)
  const t0 = Date.now()
  redact(hostile)
  expect(Date.now() - t0 < 2000).toBe(true)
})
