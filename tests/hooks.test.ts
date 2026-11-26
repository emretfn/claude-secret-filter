// Integration tests through the engine: the test's own tool.call hooks stand for the
// tools (they answer with a fake output), the mod's hooks sit above them.
import { expect, test } from 'claude-code/testing'

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const rnd = (n: number) => Array.from({ length: n }, () => ALNUM[Math.floor(Math.random() * ALNUM.length)]).join('')
const ghToken = () => 'gh' + 'p_' + rnd(36)
const PH = /\[REDACTED:[0-9a-f]{8}\]/
const bashOut = (stdout: string) => ({ result: { stdout, stderr: '', interrupted: false, isImage: false } }) as never
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
  on('tool.call', { tool: 'Bash' }, () => bashOut(`TOKEN=${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => {
    written = e.new_string
    return { result: { filePath: e.file_path, oldString: e.old_string, newString: e.new_string, originalFile: '', structuredPatch: [], userModified: false, replaceAll: false } } as never
  })
  const read = await $.tool.call({ tool: 'Bash', command: 'cat settings.ini' })
  const placeholder = PH.exec(textOf(read))?.[0]
  expect(placeholder).toBeDefined()

  const edit = await $.tool.call({ tool: 'Edit', file_path: '/app/settings.ini', old_string: 'TOKEN=x', new_string: `TOKEN=${placeholder}` })
  expect(written).toBe(`TOKEN=${secret}`)
  // and what comes back to the model is masked again
  expect(textOf(edit).includes(secret)).toBe(false)
})

test('a failed Edit that echoes its input does not leak the restored value', async ($, on) => {
  const secret = ghToken()
  on('tool.call', { tool: 'Bash' }, () => bashOut(`TOKEN=${secret}`))
  on('tool.call', { tool: 'Edit' }, (_$, e) => {
    const msg = `String to replace not found in file.\nString: ${e.old_string}`
    return { isError: true, result: msg, text: msg } as never
  })
  const read = await $.tool.call({ tool: 'Bash', command: 'cat settings.ini' })
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
