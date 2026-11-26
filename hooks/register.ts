import type { Register } from 'claude-code'
import { MASK, hasPlaceholder, isEnvFile, pinRestored, redact, restore, seedEnvText, type Options } from './redact'

// Tools whose output is filtered here, with what is known of the call (its files, env
// mode): those that read files, commands or the web, and every MCP tool. Every other row
// the conversation keeps (other tools, notifications, attachments) is filtered at
// `session.append` (grep/rg run through Bash)
const TOOLS = ['Bash', 'Read', 'WebFetch', 'WebSearch', 'ReadMcpResourceTool', /^mcp__/] as const

// Writing tools: placeholders in their input are turned back into real values
const WRITERS = ['Edit', 'Write', 'NotebookEdit'] as const
const WRITE_FIELDS = ['old_string', 'new_string', 'content', 'new_source'] as const

const handledHere = (tool: string) =>
  tool.startsWith('mcp__') || (TOOLS as readonly unknown[]).includes(tool) || (WRITERS as readonly unknown[]).includes(tool)

// Commands whose whole output is environment content
const ENV_COMMAND =
  /(?:^|[|;&(]\s*|\$\(\s*)(?:env|printenv|export\s+-p|declare\s+-p?x|set)\s*(?:$|[|;&)>])|\b(?:vercel|eas|netlify|railway|fly|heroku)\s+(?:env|secrets?|config)\b/

type Loose = { tool: string; [k: string]: unknown }
const str = (e: Loose, k: string) => (typeof e[k] === 'string' ? (e[k] as string) : '')
const target = (e: Loose) => str(e, 'file_path') || str(e, 'notebook_path')

// The files an output may have come from: path-scoped gitleaks rules run only on their own files.
function paths(e: Loose): string[] {
  if (e.tool === 'Bash') {
    return str(e, 'command')
      .split(/[\s"'`|;&<>()=]+/)
      .filter(t => /[\w-]\.[\w]+$|\/[\w.-]+$/.test(t) || isEnvFile(t))
  }
  const p = target(e)
  return p ? [p] : []
}

// The file an output is the content of, for sure: a value masked in it may be restored there.
// A command's output names no file for sure (`cat a b`), so nothing is restored from it.
function sources(e: Loose): string[] {
  if (e.tool === 'Bash') return []
  const p = target(e)
  return p ? [p] : []
}

function envMode(e: Loose): boolean {
  switch (e.tool) {
    case 'Read':
    case 'Edit':
    case 'Write':
      return isEnvFile(str(e, 'file_path'))
    case 'Bash':
      return paths(e).some(isEnvFile) || ENV_COMMAND.test(str(e, 'command'))
    default:
      return false
  }
}

const options = (e: Loose): Options => ({ envMode: envMode(e), paths: paths(e), sources: sources(e) })

// Binary content (an image or PDF the Read tool returns, an MCP image block) is left
// alone: masking its base64 would corrupt it, and text rules cannot hide a secret in it.
// Anything else that only claims to be binary (a `.env` served as octet-stream, a
// base64 blob of text) is decoded and filtered as text.
const MEDIA_TYPE = /^(?:image|audio|video|pdf|document)$/
const MEDIA_MIME = /^(?:image|audio|video|font)\/|^application\/(?:pdf|zip|gzip|x-tar|x-7z-compressed)$/i
const BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/
const BINARY_KEYS = new Set(['base64', 'data', 'blob'])

function isMedia(o: Record<string, unknown>): boolean {
  const type = typeof o.type === 'string' ? o.type : ''
  const mime = [o.mimeType, o.media_type, o.mediaType, o.type].find(m => typeof m === 'string' && m.includes('/')) as string | undefined
  const src = o.source as Record<string, unknown> | undefined
  if (type === 'document' && src && typeof src === 'object' && src.type === 'text') return false // a text document
  return MEDIA_TYPE.test(type) || (mime !== undefined && MEDIA_MIME.test(mime))
}

// A base64 string that decodes to text: filtered as that text, re-encoded when masked
function walkBase64(s: string, opts: Options, tally: { n: number }): string {
  let text: string
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0))
    text = new TextDecoder('utf-8').decode(bytes)
  } catch {
    return s
  }
  if (/[\x00-\x08\x0e-\x1f\ufffd]/.test(text)) return s // not text: binary
  const r = redact(text, opts)
  if (r.count === 0) return s
  tally.n += r.count
  const enc = new TextEncoder().encode(r.text)
  return btoa(Array.from(enc, b => String.fromCharCode(b)).join(''))
}

// Masks every string inside a result, keeping its shape
function walk(v: unknown, opts: Options, tally: { n: number }): unknown {
  if (typeof v === 'string') {
    const r = redact(v, opts)
    tally.n += r.count
    return r.text
  }
  if (Array.isArray(v)) return v.map(x => walk(x, opts, tally))
  if (v && typeof v === 'object') {
    const src = v as Record<string, unknown>
    if (isMedia(src)) return v
    const o: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(src)) {
      if (BINARY_KEYS.has(k) && typeof x === 'string' && x.length > 256 && BASE64.test(x.replace(/\s+/g, ''))) {
        o[k] = walkBase64(x.replace(/\s+/g, ''), opts, tally)
      } else {
        o[k] = walk(x, opts, tally)
      }
    }
    return o
  }
  return v
}

const NOTE = (n: number) =>
  `secret-filter masked ${n} secret-looking value(s) in this output as ${MASK}:<id>]. ` +
  `Do not try to recover them. To keep such a value when editing this same file, copy its placeholder exactly into Edit/Write: ` +
  `it is restored to the real value on write, in the file it was read from only.`

// A text that may hold real values (a deny or an error from beneath): masked, or itself
function masked(text: string, opts: Options): { text: string; count: number } {
  const r = redact(text, opts)
  return r.count === 0 ? { text, count: 0 } : { text: `${r.text}\n\n${NOTE(r.count)}`, count: r.count }
}

// ---------------------------------------------------------------------------
// Seeding: the project's own secret files, found at session start. In a git repository
// only files git ignores are read: a secret file committed to a cloned repository is
// someone else's, and could plant values that hide ordinary code.
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'bin', 'obj', 'dist', 'build', 'out', '.next', '.expo', '.turbo', 'coverage',
  'Pods', 'DerivedData', '.gradle', 'vendor', '.venv', 'venv', '__pycache__', '.cache', 'target',
])
const MAX_DEPTH = 4
const MAX_FILES = 50
const MAX_DIRS = 2000
const MAX_BYTES = 1024 * 1024

type Ignore = { base: string; re: RegExp; negate: boolean; dirOnly: boolean }

function globToRe(glob: string): string {
  let out = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!
    if (c === '*' && glob[i + 1] === '*') {
      out += '.*'
      i++
      if (glob[i + 1] === '/') i++
    } else if (c === '*') out += '[^/]*'
    else if (c === '?') out += '[^/]'
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return out
}

export function parseGitignore(text: string, base: string): Ignore[] {
  const rules: Ignore[] = []
  for (const raw of text.split('\n')) {
    let line = raw.replace(/\r$/, '').replace(/(?<!\\)\s+$/, '')
    if (line === '' || line.startsWith('#')) continue
    const negate = line.startsWith('!')
    if (negate) line = line.slice(1)
    const dirOnly = line.endsWith('/')
    if (dirOnly) line = line.slice(0, -1)
    const anchored = line.includes('/')
    if (line.startsWith('/')) line = line.slice(1)
    const body = globToRe(line)
    rules.push({ base, negate, dirOnly, re: new RegExp(anchored ? `^${body}$` : `(?:^|/)${body}$`) })
  }
  return rules
}

/** Whether git ignores `path` (relative parts under each rule's base), by the rules in order. */
export function isIgnored(rules: readonly Ignore[], path: string): boolean {
  let ignored = false
  for (const r of rules) {
    if (!path.startsWith(r.base + '/')) continue
    const parts = path.slice(r.base.length + 1).split('/')
    // the file itself, or one of its directories
    for (let i = parts.length; i >= 1; i--) {
      if (r.dirOnly && i === parts.length) continue
      if (r.re.test(parts.slice(0, i).join('/'))) {
        ignored = !r.negate
        break
      }
    }
  }
  return ignored
}

type List = (dir: string) => Promise<{ name: string; kind: string; size: number }[]>
type ReadText = (path: string) => Promise<string>

/** Secret files under `root`, nearest first (the project's own `.env` before a sub-folder's). */
export async function findSecretFiles(list: List, read: ReadText, root: string): Promise<string[]> {
  const out: string[] = []
  const rules: Ignore[] = []
  let isRepo = false
  let queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }]
  let dirs = 0
  while (queue.length > 0 && out.length < MAX_FILES && dirs < MAX_DIRS) {
    const next: typeof queue = []
    for (const { dir, depth } of queue) {
      if (++dirs > MAX_DIRS) break
      const entries = await list(dir).catch(() => [])
      if (depth === 0) isRepo = entries.some(en => en.name === '.git')
      if (isRepo && entries.some(en => en.name === '.gitignore' && en.kind === 'file')) {
        rules.push(...parseGitignore(await read(`${dir}/.gitignore`).catch(() => ''), dir))
      }
      for (const en of entries) {
        const path = `${dir}/${en.name}`
        if (en.kind === 'dir' && !SKIP_DIRS.has(en.name) && depth < MAX_DEPTH) next.push({ dir: path, depth: depth + 1 })
        else if (en.kind === 'file' && en.size <= MAX_BYTES && isEnvFile(path) && (!isRepo || isIgnored(rules, path))) {
          if (out.length < MAX_FILES) out.push(path)
        }
      }
    }
    queue = next
  }
  return out
}

// ---------------------------------------------------------------------------
// The rows the conversation keeps, filtered whatever made them: the tools not hooked
// above (Monitor, MCP resources, background tasks, subagents' reports...), notifications,
// attachments. The person's own prompt and the model's response are theirs, left as written.
const APPEND_SKIP_DOORS = new Set(['prompt', 'response', 'compaction'])
const PERSON = new Set(['composer', 'bridge', 'sdk'])

type Block = { type: string; [k: string]: unknown }

function scrubBlocks(blocks: readonly Block[], tally: { n: number }): Block[] {
  return blocks.map(b => {
    if (b.type === 'text' && typeof b.text === 'string') {
      const r = redact(b.text)
      tally.n += r.count
      return r.count ? { ...b, text: r.text } : b
    }
    if (b.type === 'tool_result') {
      if (typeof b.content === 'string') {
        const r = redact(b.content)
        tally.n += r.count
        return r.count ? { ...b, content: r.text } : b
      }
      if (Array.isArray(b.content)) {
        const before = tally.n
        const content = scrubBlocks(b.content as Block[], tally)
        return tally.n > before ? { ...b, content } : b
      }
    }
    return b
  })
}

export const register: Register = on => {
  // Writes whose input now holds real values: auto mode's classifier is not asked about them
  const restoredCalls = new Set<string>()

  // 0) Session start: learn the values in the project's secret files (.env*, .npmrc, ...),
  //    so they are masked wherever they show up, also base64 / URL-encoded.
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    const seed = async () => {
      const files = await findSecretFiles(dir => $.fs.list(dir), path => $.fs.read(path), e.cwd)
      let n = 0
      for (const f of files) n += seedEnvText(await $.fs.read(f).catch(() => ''))
      if (n > 0) $.ui.toast(`secret-filter: learned ${n} value(s) from ${files.length} secret file(s)`)
    }
    void seed().catch(() => undefined)
    return started
  })

  // 1) Reading: mask the output. A Bash command holding a placeholder is refused
  //    (sed or a heredoc would write the placeholder itself into a file).
  on('tool.call', { tool: TOOLS }, async ($, e, next) => {
    const loose = e as unknown as Loose
    if (loose.tool === 'Bash' && hasPlaceholder(str(loose, 'command'))) {
      return {
        deny:
          `secret-filter: this command contains a ${MASK}:<id>] placeholder. Placeholders are only restored in Edit/Write/NotebookEdit; ` +
          `in a shell command it would be written or sent literally. Use Edit/Write, or leave the masked value out of the command.`,
      }
    }

    const ran = await next(e)
    const opts = options(loose)
    if (ran.deny !== undefined) {
      // a deny from beneath (another plugin, a scanner) may quote the output
      const r = masked(ran.deny, opts)
      return r.count === 0 ? ran : { deny: r.text }
    }
    if (ran.isError === true) {
      // a failed call's output (non-zero exit) is masked too; the model reads it as the deny text
      const r = masked(ran.text ?? '', opts)
      if (r.count === 0) return ran
      $.ui.toast(`secret-filter: masked ${r.count} value(s) in ${e.tool} error output`)
      return { deny: r.text }
    }

    const tally = { n: 0 }
    const result = walk(ran.result, opts, tally)
    if (tally.n === 0) return ran

    $.ui.toast(`secret-filter: masked ${tally.n} value(s) in ${e.tool} output`)
    return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; output withheld.' } : next(e)))

  // 2) Writing: turn placeholders back into real values, in the file they were read from
  //    only, then mask the result (file content, diff) again.
  on('tool.call', { tool: WRITERS }, async ($, e, next) => {
    const loose = e as unknown as Loose
    const file = target(loose)
    const rewritten: Record<string, string> = {}
    const missing: string[] = []
    const foreign: string[] = []
    for (const k of WRITE_FIELDS) {
      if (typeof loose[k] !== 'string') continue
      const r = restore(loose[k] as string, file)
      rewritten[k] = r.text
      missing.push(...r.missing)
      foreign.push(...r.foreign)
    }
    if (missing.length > 0) {
      return {
        deny:
          `secret-filter: ${missing.length} placeholder(s) are unknown: the filter was reloaded since the file was read, ` +
          `or the text is not a placeholder the filter made. Read the file again to get fresh placeholders, then retry.`,
      }
    }
    if (foreign.length > 0) {
      return {
        deny:
          `secret-filter: ${foreign.length} placeholder(s) were not read from ${file || 'this file'}. A masked value is only ` +
          `restored into the file it was read from (and never under .git/), so it cannot be carried into another file, a script or a URL. ` +
          `To put a secret somewhere new, ask the user to add it themselves.`,
      }
    }

    const restoredAny = WRITE_FIELDS.some(k => typeof loose[k] === 'string' && rewritten[k] !== loose[k])
    if (restoredAny) {
      for (const k of WRITE_FIELDS) if (typeof loose[k] === 'string') pinRestored(loose[k] as string)
      if (e.tool_use_id) restoredCalls.add(e.tool_use_id)
    }

    const opts = options(loose)
    try {
      const ran = await next({ ...e, ...rewritten } as typeof e)
      if (ran.deny !== undefined) {
        const r = masked(ran.deny, opts)
        return r.count === 0 ? ran : { deny: r.text }
      }
      if (ran.isError === true) {
        // an error may echo the input, where placeholders are now real values: mask it
        const r = masked(ran.text ?? '', opts)
        return r.count === 0 ? ran : { deny: r.text }
      }

      const tally = { n: 0 }
      const result = walk(ran.result, opts, tally)
      if (tally.n === 0) return ran
      return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
    } finally {
      if (e.tool_use_id) restoredCalls.delete(e.tool_use_id)
    }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; write result withheld.' } : next(e)))

  // 3) Auto mode: a write that now holds real values is put to the person, not to the
  //    classifier, which would read (and may send) its input.
  on('tool.judge', { tool: WRITERS }, ($, e, next) =>
    e.tool_use_id && restoredCalls.has(e.tool_use_id)
      ? { decision: 'ask' as const, reason: 'secret-filter: this edit restores masked secret values; confirm it yourself.' }
      : next(e),
  ).catch(() => ({ decision: 'ask' as const }))

  // 4) Every other row the conversation keeps, before the model or the transcript reads it.
  on('session.append', async ($, e, next) => {
    if (APPEND_SKIP_DOORS.has(e.door)) return next(e)
    const origin = (e.origin ?? {}) as { kind?: string; tool?: string }
    if (origin.kind && PERSON.has(origin.kind)) return next(e)
    if (e.door === 'tool-result' && origin.kind === 'tool' && origin.tool && handledHere(origin.tool)) return next(e)
    const tally = { n: 0 }
    const content = scrubBlocks(e.message.content as Block[], tally)
    if (tally.n === 0) return next(e)
    return next({ ...e, message: { ...e.message, content } })
  }).catch((_$, e, next) => {
    // the filter failed on this row: its text is withheld rather than kept unfiltered
    if (next.called) return undefined as never
    const withheld = { type: 'text', text: 'secret-filter failed on this row; its text is withheld.' }
    const content = (e.message.content as Block[]).map(b => (b.type === 'text' ? withheld : b.type === 'tool_result' ? { ...b, content: withheld.text } : b))
    return next({ ...e, message: { ...e.message, content } })
  })
}
