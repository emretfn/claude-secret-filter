import type { Register } from 'claude-code'
import { MASK, hasPlaceholder, isEnvFile, redact, restore, seedEnvText, type Options } from './redact'

// Tools whose output is filtered: those that read files, commands or the web, and every MCP tool
// (grep/rg run through Bash)
const TOOLS = ['Bash', 'Read', 'WebFetch', 'WebSearch', /^mcp__/] as const

// Writing tools: placeholders in their input are turned back into real values
const WRITERS = ['Edit', 'Write', 'NotebookEdit'] as const
const WRITE_FIELDS = ['old_string', 'new_string', 'content', 'new_source'] as const

// Commands whose whole output is environment content
const ENV_COMMAND =
  /(?:^|[|;&(]\s*|\$\(\s*)(?:env|printenv|export\s+-p|declare\s+-p?x|set)\s*(?:$|[|;&)>])|\b(?:vercel|eas|netlify|railway|fly|heroku)\s+(?:env|secrets?|config)\b/

type Loose = { tool: string; [k: string]: unknown }
const str = (e: Loose, k: string) => (typeof e[k] === 'string' ? (e[k] as string) : '')

// The files an output came from: path-scoped gitleaks rules run only on their own files.
function paths(e: Loose): string[] {
  if (e.tool === 'Bash') return str(e, 'command').split(/[\s"'`|;&<>()=]+/).filter(t => /[\w-]\.[\w]+$|\/[\w.-]+$/.test(t))
  const p = str(e, 'file_path') || str(e, 'notebook_path')
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

// Binary content (an image or PDF the Read tool returns, an MCP image block) is left
// alone: masking its base64 would corrupt it, and text rules cannot hide a secret in it.
const BINARY_KEYS = new Set(['base64', 'data', 'blob'])
function isBinary(o: Record<string, unknown>): boolean {
  const type = typeof o.type === 'string' ? o.type : ''
  const mime = [o.mimeType, o.media_type, o.mediaType].find(m => typeof m === 'string') as string | undefined
  return type === 'image' || type === 'pdf' || type === 'audio' || typeof o.base64 === 'string' ||
    (mime !== undefined && !/^(?:text\/|application\/(?:json|xml|javascript|x-yaml|yaml|toml))/i.test(mime))
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
    if (isBinary(src)) return v
    const o: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(src)) {
      o[k] = BINARY_KEYS.has(k) && typeof x === 'string' && x.length > 256 && !/\s/.test(x.slice(0, 256)) ? x : walk(x, opts, tally)
    }
    return o
  }
  return v
}

const NOTE = (n: number) =>
  `secret-filter masked ${n} secret-looking value(s) in this output as ${MASK}:<id>]. ` +
  `Do not try to recover them. To keep such a value when editing, copy its placeholder exactly into Edit/Write: it is restored to the real value on write.`

// Seeding: the project's own secret files, found at session start
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'bin', 'obj', 'dist', 'build', 'out', '.next', '.expo', '.turbo', 'coverage',
  'Pods', 'DerivedData', '.gradle', 'vendor', '.venv', 'venv', '__pycache__', '.cache', 'target',
])
const MAX_DEPTH = 4
const MAX_FILES = 50
const MAX_BYTES = 1024 * 1024

type List = (dir: string) => Promise<{ name: string; kind: string; size: number }[]>
async function findSecretFiles(list: List, dir: string, depth: number, out: string[]): Promise<void> {
  if (depth > MAX_DEPTH || out.length >= MAX_FILES) return
  const entries = await list(dir).catch(() => [])
  for (const en of entries) {
    if (out.length >= MAX_FILES) return
    const path = `${dir}/${en.name}`
    if (en.kind === 'dir' && !SKIP_DIRS.has(en.name)) await findSecretFiles(list, path, depth + 1, out)
    else if (en.kind === 'file' && en.size <= MAX_BYTES && isEnvFile(path)) out.push(path)
  }
}

export const register: Register = on => {
  // 0) Session start: learn the values in the project's secret files (.env*, .npmrc, ...),
  //    so they are masked wherever they show up, also base64 / URL-encoded.
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    const seed = async () => {
      const files: string[] = []
      await findSecretFiles(dir => $.fs.list(dir), e.cwd, 0, files)
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
    if (ran.deny !== undefined) return ran
    if (ran.isError === true) {
      // a failed call's output (non-zero exit) is masked too; the model reads it as the deny text
      const r = redact(ran.text ?? '', { envMode: envMode(loose), paths: paths(loose) })
      if (r.count === 0) return ran
      $.ui.toast(`secret-filter: masked ${r.count} value(s) in ${e.tool} error output`)
      return { deny: `${r.text}\n\n${NOTE(r.count)}` }
    }

    const tally = { n: 0 }
    const result = walk(ran.result, { envMode: envMode(loose), paths: paths(loose) }, tally)
    if (tally.n === 0) return ran

    $.ui.toast(`secret-filter: masked ${tally.n} value(s) in ${e.tool} output`)
    return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; output withheld.' } : next(e)))

  // 2) Writing: turn placeholders back into real values, then mask the result (file content, diff) again.
  on('tool.call', { tool: WRITERS }, async ($, e, next) => {
    const loose = e as unknown as Loose
    const rewritten: Record<string, string> = {}
    const missing: string[] = []
    for (const k of WRITE_FIELDS) {
      if (typeof loose[k] !== 'string') continue
      const r = restore(loose[k] as string)
      rewritten[k] = r.text
      missing.push(...r.missing)
    }
    if (missing.length > 0) {
      return {
        deny:
          `secret-filter: ${missing.length} placeholder(s) are unknown: the filter was reloaded since the file was read, ` +
          `or the text is not a placeholder the filter made. Read the file again to get fresh placeholders, then retry.`,
      }
    }

    const ran = await next({ ...e, ...rewritten } as typeof e)
    if (ran.deny !== undefined) return ran
    if (ran.isError === true) {
      // an error may echo the input, where placeholders are now real values: mask it
      const r = redact(ran.text ?? '', { envMode: envMode(loose), paths: paths(loose) })
      return r.count === 0 ? ran : { deny: `${r.text}\n\n${NOTE(r.count)}` }
    }

    const tally = { n: 0 }
    const result = walk(ran.result, { envMode: envMode(loose), paths: paths(loose) }, tally)
    if (tally.n === 0) return ran
    return { result: result as typeof ran.result, context: [...(ran.context ?? []), NOTE(tally.n)] }
  }).catch((_$, e, next) => (next.called ? { deny: 'secret-filter failed; write result withheld.' } : next(e)))
}
