import type { Register } from 'claude-code'
import {
  MASK, hasPlaceholder, isEnvFile, maskKnownOnly, movedValues, pinRestored, redact, restore, seedEnvText, withBudget,
  type Options,
} from './redact'

// Redaction of one result may take this long; past it the output is withheld.
const BUDGET_MS = 6000

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
// (`env` also after `sudo`, a path, or `docker exec <c>`; `printenv NAME` prints one value)
const ENV_COMMAND =
  /(?:^|[\s|;&(/]|\$\()(?:env(?:\s+-[-\w]+)*|export(?:\s+-p)?|declare\s+-p?x|set|compgen\s+-[ev])\s*(?:$|[|;&)>])|\bprintenv\b|\/proc\/[\w$]+\/environ\b|\b(?:vercel|eas|netlify|railway|fly|heroku)\s+(?:env|secrets?|config)\b/

type Loose = { tool: string; [k: string]: unknown }
const str = (e: Loose, k: string) => (typeof e[k] === 'string' ? (e[k] as string) : '')
const target = (e: Loose) => str(e, 'file_path') || str(e, 'notebook_path')
// Paths an MCP tool or a resource read names (`path`, `uri`): a secret file there turns env mode on
const mcpPaths = (e: Loose) => ['path', 'file_path', 'uri'].map(k => str(e, k).replace(/^file:\/\//, '')).filter(Boolean)

// The files an output may have come from: path-scoped gitleaks rules run only on their own files.
function paths(e: Loose): string[] {
  if (e.tool === 'Bash') {
    return str(e, 'command')
      .split(/[\s"'`|;&<>()=]+/)
      .map(t => t.replace(/[*?[\]{}]+$/, '').replace(/\*/g, 'x')) // `.env*`, `*.env`: a glob may name an env file
      .filter(t => /[\w-]\.[\w]+$|\/[\w.-]+$/.test(t) || isEnvFile(t))
  }
  const p = target(e)
  if (p) return [p]
  return e.tool === 'ReadMcpResourceTool' || e.tool.startsWith('mcp__') ? mcpPaths(e) : []
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
      return paths(e).some(isEnvFile)
  }
}

// `printenv NAME`: the output is the bare values, with no names to go by
const PRINTENV_NAMES = /^\s*(?:sudo\s+)?(?:\S*\/)?printenv(?:\s+\w+)+\s*$/
const options = (e: Loose): Options => ({
  envMode: envMode(e),
  paths: paths(e),
  sources: sources(e),
  bareValues: e.tool === 'Bash' && PRINTENV_NAMES.test(str(e, 'command')),
})

// Binary payloads (the base64 of an image or PDF the Read tool returns, an MCP image
// block's data) are not run through the text rules: masking random base64 would corrupt
// it. Only payload fields are treated so, never a `text` field, whatever type or mime
// type the block claims. A payload that decodes to text (a `.env` served as
// octet-stream) is filtered as that text; one that decodes to binary still gets the
// known-values layer.
const BASE64 = /^[A-Za-z0-9+/_-]+={0,2}$/
const BINARY_KEYS = new Set(['base64', 'data', 'blob'])

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
  if (/[\x00-\x08\x0e-\x1f\ufffd]/.test(text)) {
    // binary: only values already known, which cannot corrupt it by chance
    const k = maskKnownOnly(s)
    tally.n += k.count
    return k.text
  }
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
    const o: Record<string, unknown> = {}
    for (const [key, x] of Object.entries(src)) {
      // a key can hold a secret too ({"<token>": ...}): masked like a value
      let k = key
      if (/\d/.test(key) || key.length > 64) {
        const rk = redact(key, opts)
        tally.n += rk.count
        k = rk.text
      }
      // base64 may be wrapped in lines, never spaced: a text with spaces is filtered as text
      if (BINARY_KEYS.has(k) && typeof x === 'string' && x.length > 256 && BASE64.test(x.replace(/\r?\n/g, ''))) {
        o[k] = walkBase64(x.replace(/\r?\n/g, ''), opts, tally)
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

// A result already masked where the tool ran still needs the note for the model
const PH_ALL = /\[REDACTED:[0-9a-f]{8}\]/g
function withNote<R extends { result?: unknown; context?: readonly string[] }>(ran: R): R {
  const n = (JSON.stringify(ran.result ?? '').match(PH_ALL) ?? []).length
  if (n === 0 || (ran.context ?? []).some(c => c.startsWith('secret-filter masked'))) return ran
  return { ...ran, context: [...(ran.context ?? []), NOTE(n)] }
}

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

/**
 * Whether git tracks `rel` in this index text (`.git/index`, read as text). An entry's
 * path is preceded by its flags, whose low byte is the path's length (or 0 with the
 * extended flags of index v3), and followed by a NUL.
 */
export function isTracked(index: string, rel: string): boolean {
  for (let i = index.indexOf(rel + '\0'); i !== -1; i = index.indexOf(rel + '\0', i + 1)) {
    const prev = i > 0 ? index.charCodeAt(i - 1) : -1
    if (prev === (rel.length & 0xff) || prev === 0) return true
  }
  return false
}

type Repo = { root: string; rules: Ignore[]; index: string }

/**
 * Secret files under `root`, nearest first (the project's own `.env` before a sub-folder's).
 * Inside a git repository (each one its own, nested ones too) a file is taken only when
 * git ignores it and does not track it: a committed one is the repository's, not yours.
 */
export async function findSecretFiles(list: List, read: ReadText, root: string): Promise<string[]> {
  const out: string[] = []
  let queue: { dir: string; depth: number; repo?: Repo }[] = [{ dir: root, depth: 0 }]
  let dirs = 0
  while (queue.length > 0 && out.length < MAX_FILES && dirs < MAX_DIRS) {
    const level: typeof queue = []
    for (const item of queue) {
      if (++dirs > MAX_DIRS) break
      const { dir, depth } = item
      const entries = await list(dir).catch(() => [])
      let repo = item.repo
      if (entries.some(en => en.name === '.git')) {
        repo = { root: dir, rules: [], index: await read(`${dir}/.git/index`).catch(() => '') }
      }
      if (repo && entries.some(en => en.name === '.gitignore' && en.kind === 'file')) {
        repo.rules.push(...parseGitignore(await read(`${dir}/.gitignore`).catch(() => ''), dir))
      }
      for (const en of entries) {
        const path = `${dir}/${en.name}`
        if (en.kind === 'dir' && !SKIP_DIRS.has(en.name) && depth < MAX_DEPTH) level.push({ dir: path, depth: depth + 1, repo })
        else if (en.kind === 'file' && en.size <= MAX_BYTES && isEnvFile(path) && out.length < MAX_FILES) {
          const rel = repo ? path.slice(repo.root.length + 1) : ''
          if (!repo || (isIgnored(repo.rules, path) && !isTracked(repo.index, rel))) out.push(path)
        }
      }
    }
    queue = level
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

// A row that shows a secret file's content (an attachment naming its `file_path`) is in env mode
const FILE_PATH = /"?(?:file_path|filePath|path)"?\s*[:=]\s*"([^"\n]+)"/g
const rowOptions = (text: string): Options => ({ envMode: [...text.matchAll(FILE_PATH)].some(m => isEnvFile(m[1]!)) })

export function scrubBlocks(blocks: readonly Block[], tally: { n: number }): Block[] {
  return blocks.map(b => {
    if (b.type === 'text' && typeof b.text === 'string') {
      const r = redact(b.text, rowOptions(b.text))
      tally.n += r.count
      return r.count ? { ...b, text: r.text } : b
    }
    if (b.type === 'document') {
      // a document's text (its `source.data`, or base64 of it) and its title
      const before = tally.n
      const doc = walk(b, rowOptions(JSON.stringify(b).slice(0, 4096)), tally) as Block
      return tally.n > before ? doc : b
    }
    if (b.type === 'search_result') {
      const before = tally.n
      const sr = walk(b, rowOptions(''), tally) as Block
      return tally.n > before ? sr : b
    }
    if (b.type === 'tool_result') {
      if (typeof b.content === 'string') {
        const r = redact(b.content, rowOptions(b.content))
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

  // @-mentions: no tool.call is raised for them, so a secret file is not read that way;
  // Claude can Read it, masked. Every other attachment's text is masked.
  on('prompt.mention', ($, e, next) =>
    isEnvFile(String((e as unknown as { path?: string }).path ?? ''))
      ? { deny: 'secret-filter: secret files are not attached through @-mentions; ask Claude to Read the file (its values are masked).' }
      : next(e),
  ).catch((_$, e, next) => (next.called ? next(e) : { deny: 'secret-filter failed; mention not read.' }))

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
      const r = withBudget(BUDGET_MS, () => masked(ran.deny, opts))
      return r.count === 0 ? ran : { deny: r.text }
    }
    if (ran.isError === true) {
      // a failed call's output (non-zero exit) is masked too; the model reads it as the deny text
      const r = withBudget(BUDGET_MS, () => masked(ran.text ?? '', opts))
      if (r.count === 0) return ran
      $.ui.toast(`secret-filter: masked ${r.count} value(s) in ${e.tool} error output`)
      return { deny: r.text }
    }

    const tally = { n: 0 }
    const result = withBudget(BUDGET_MS, () => walk(ran.result, opts, tally))
    if (tally.n === 0) return withNote(ran) // masked beneath (tool.run): its note does not come up

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

    // ... and only where it already was in that file: on its own line, unchanged
    const values = [...new Set(WRITE_FIELDS.flatMap(k => (typeof loose[k] === 'string' ? restore(loose[k] as string, file).values : [])))]
    if (values.length > 0) {
      if (loose.tool === 'NotebookEdit') {
        return {
          deny:
            `secret-filter: placeholders are not restored in notebooks. Leave the cell that holds a masked value as it is, ` +
            `or ask the user to make this change.`,
        }
      }
      const before = await $.fs.read(file).catch(() => '')
      let after: string
      if (loose.tool === 'Edit') {
        const old = rewritten.old_string ?? ''
        if (old === '' || !before.includes(old)) {
          return {
            deny:
              `secret-filter: the text to replace was not found as it is in ${file}, so the placement of its masked values ` +
              `cannot be checked. Read the file again and copy the lines exactly.`,
          }
        }
        const neu = rewritten.new_string ?? ''
        after = loose.replace_all === true ? before.split(old).join(neu) : before.replace(old, () => neu)
      } else {
        after = rewritten.content ?? ''
      }
      const moved = movedValues(after, before, values)
      if (moved.length > 0) {
        return {
          deny:
            `secret-filter: ${moved.length} masked value(s) would be written to a new or changed line in ${file}. A placeholder is ` +
            `only restored on a line kept exactly as it is in the file, so a value cannot be moved, copied or edited into a new ` +
            `line, command or URL. Keep each line that holds a placeholder unchanged (edit the lines around it), or ask the user ` +
            `to make this change.`,
        }
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
        const r = withBudget(BUDGET_MS, () => masked(ran.deny, opts))
        return r.count === 0 ? ran : { deny: r.text }
      }
      if (ran.isError === true) {
        // an error may echo the input, where placeholders are now real values: mask it
        const r = withBudget(BUDGET_MS, () => masked(ran.text ?? '', opts))
        return r.count === 0 ? ran : { deny: r.text }
      }

      const tally = { n: 0 }
      const result = withBudget(BUDGET_MS, () => walk(ran.result, opts, tally))
      if (tally.n === 0) return withNote(ran) // masked beneath (tool.run): its note does not come up
      return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
    } finally {
      if (e.tool_use_id) restoredCalls.delete(e.tool_use_id)
    }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; write result withheld.' } : next(e)))

  // 2b) Where the tool runs: mask its result there too, so what runs beneath and after this
  //     mod (PostToolUse hooks, plugins below) sees placeholders. The tool.call hooks above
  //     mask again: a plugin beneath may answer a call without running a tool.
  on('tool.run', { tool: [...TOOLS, ...WRITERS] }, async ($, e, next) => {
    const ran = await next(e)
    if (ran.deny !== undefined) return ran
    const opts = options(e as unknown as Loose)
    if (ran.isError === true) {
      // an error keeps its shape: its text, and what the transcript stores, masked
      const tally = { n: 0 }
      const text = withBudget(BUDGET_MS, () => masked(ran.text ?? '', opts))
      const result = withBudget(BUDGET_MS, () => walk(ran.result, opts, tally))
      if (text.count === 0 && tally.n === 0) return ran
      $.ui.toast(`secret-filter: masked ${Math.max(text.count, tally.n)} value(s) in ${e.tool} error output`)
      const { ref: _ref, ...rest } = ran
      return { ...rest, text: text.text, result }
    }
    const tally = { n: 0 }
    const result = withBudget(BUDGET_MS, () => walk(ran.result, opts, tally))
    if (tally.n === 0) return ran
    $.ui.toast(`secret-filter: masked ${tally.n} value(s) in ${e.tool} output`)
    return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; output withheld.' } : next(e)))

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
    const content = withBudget(BUDGET_MS, () => scrubBlocks(e.message.content as Block[], tally))
    if (tally.n === 0) return next(e)
    return next({ ...e, message: { ...e.message, content } })
  }).catch((_$, e, next) => {
    // the filter failed on this row: its text is withheld rather than kept unfiltered
    if (next.called) return undefined as never
    const withheld = { type: 'text', text: 'secret-filter failed on this row; its text is withheld.' }
    const content = (e.message.content as Block[]).map(b =>
      b.type === 'text' || b.type === 'search_result' ? withheld : b.type === 'tool_result' ? { ...b, content: withheld.text } : b,
    )
    return next({ ...e, message: { ...e.message, content } })
  })
}
