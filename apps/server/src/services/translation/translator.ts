/**
 * Output Translation Layer (spec §8.3). Turns raw agent output into audience-appropriate
 * text:
 *  - Simple mode: jargon stripped — no file paths (replaced by human area labels), code,
 *    stack traces, shell commands, diff markers, internal URLs or secrets. Every Simple
 *    string passes `leakCheck` (offending lines are dropped as a last resort).
 *  - Pro mode: verbatim, but still secret-scrubbed.
 *
 * `Translator` is pluggable; v1 ships `RuleBasedTranslator`. Output styles (Concise /
 * Explanatory / Executive / Learning, spec §8.17) are accepted as a hook and currently
 * only affect length.
 */
import {
  areasForFiles,
  humanAreaFallback,
  labelForPath,
  normalizeWorkspacePath,
  REDACTED,
  scrubSecrets,
  type AgentState,
  type ApprovalGate,
  type Mode,
} from '@loose/shared';
import { leakCheck, normalizeForLeakCheck } from './leakCheck';

export type OutputStyle = 'concise' | 'explanatory' | 'executive' | 'learning';

export interface TranslationContext {
  /** Project `componentLabels` (glob → human label). */
  componentLabels?: Readonly<Record<string, string>> | null;
  /** Exact values to redact (project secrets, the session's API key). */
  secrets: readonly string[];
  /** Absolute workspace dir, so absolute paths inside it map to areas. */
  workspaceDir?: string;
  outputStyle?: OutputStyle;
}

export interface ToolStatus {
  state: AgentState;
  label: string;
}

export interface Streamer {
  /** Feed a raw delta; returns the text to emit now ('' = nothing yet). */
  push(delta: string): string;
  /** End of the message: remaining text to emit. */
  flush(): string;
}

export interface ChangeSummaryInput {
  /** Final assistant text of the turn (raw). */
  text: string;
  /** Workspace-relative paths changed this turn. */
  files: readonly string[];
  interrupted?: boolean;
  /** Error code when the turn ended in a blocking error. */
  errorCode?: string;
  /** Catalog user message for errorCode (Simple mode). */
  errorUserMessage?: string;
}

export interface Translator {
  assistantText(text: string, mode: Mode, c: TranslationContext): string;
  toolStatus(
    tool: { name: string; input: Record<string, unknown> },
    mode: Mode,
    c: TranslationContext,
  ): ToolStatus;
  /** A tool failed (Simple: hidden behind "Hit a snag…"). */
  toolErrorStatus(mode: Mode, summary: string, c: TranslationContext): ToolStatus;
  approvalText(
    a: { tool: string; input: Record<string, unknown>; gate?: ApprovalGate | null; reason: string },
    mode: Mode,
    c: TranslationContext,
  ): { summary: string; reason: string };
  changeSummary(input: ChangeSummaryInput, mode: Mode, c: TranslationContext): string;
  areas(files: readonly string[], c: TranslationContext): string[];
  streamer(mode: Mode, c: TranslationContext): Streamer;
}

// ---- helpers --------------------------------------------------------------------------

const CODE_EXT =
  'tsx?|jsx?|mjs|cjs|css|scss|sass|less|styl|html?|vue|svelte|astro|json|jsonc|ya?ml|toml|ini|md|mdx|py|rb|go|rs|java|kt|kts|swift|php|cs|cpp|cc|c|h|hpp|sql|sh|bash|zsh|ps1|env|lock|lockb|prisma|graphql|gql|xml|txt|csv|cfg|conf|log|map|wasm|ejs|hbs|pug|tf|dockerfile';

const FRAMEWORK_RE =
  /^(?:Node|Next|Nuxt|Vue|React|Express|Three|D3|Chart|Ember|Backbone|Alpine|Solid|Deno|Bun|Socket|Moment|Day|Pixi|Anime|Video|Ext)\.js$/i;

/** Path-like tokens (global). */
const PATH_TOKEN_RE = new RegExp(
  [
    String.raw`(?:\.{1,2}\/|~\/|\/)?(?:[\w@-][\w@.-]*\/)+[\w@.\-[\]]*`,
    String.raw`(?:\.{1,2}\/|~\/)[\w@.-]+`,
    String.raw`[A-Za-z]:\\[\w\\.-]+`,
    String.raw`\b[\w-]*\w\.(?:${CODE_EXT})\b`,
    String.raw`(?<![\w])\.(?:env|git|github|vscode|npmrc|eslintrc|prettierrc)[\w.-]*`,
  ].join('|'),
  'gi',
);

const URL_RE = /\b(?:https?|wss?|file):\/\/[^\s)<>\]]+/gi;
const MD_LINK_RE = /\[([^\]]*)\]\(([^)]*)\)/g;
const MD_IMAGE_RE = /!\[[^\]]*\]\([^)]*\)/g;
const INLINE_CODE_RE = /`+([^`]*)`+/g;
const FENCE_BLOCK_RE = /(```|~~~)[^\n]*\n?[\s\S]*?(?:\1|$)/g;
const MARKUP_RE = /<\/?[A-Za-z][\w.-]*(?:\s[^<>]*)?\/?>/g;
const CALL_RE = /\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\((?!s\))[^()]*\)/g;
const IDENT_RE =
  /\b[a-z]{2,}(?:[A-Z][a-z0-9]+)+\b|\b[a-z]+_[a-z0-9_]+\b|\b[A-Z][A-Z0-9]+_[A-Z0-9_]+\b/g;

/** Whole-line kinds: a line that matches is dropped, not rewritten. */
const DROP_LINE_KINDS = new Set(['stack_trace', 'command', 'diff']);

function scrub(text: string, c: TranslationContext): string {
  return scrubSecrets(text, c.secrets);
}

/** Human area for a path (component label → heuristic fallback). Never the raw path. */
export function areaForPath(path: string, c: TranslationContext): string {
  const rel =
    normalizeWorkspacePath(path.replace(/[),.;:!?]+$/, ''), c.workspaceDir) ??
    path.replace(/^.*[\\/]/, '');
  return labelForPath(rel, c.componentLabels) ?? humanAreaFallback(rel || path);
}

function joinList(items: readonly string[], max = 4): string {
  const list = items.slice(0, max);
  const rest = items.length - list.length;
  if (rest > 0) list.push(rest === 1 ? 'one other part' : 'a few other parts');
  if (list.length <= 1) return list[0] ?? '';
  return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

function cleanupSpacing(s: string): string {
  return s
    .replace(/[ \t]+/g, ' ')
    .replace(/\s+([,.;:!?])/g, '$1')
    .replace(/\(\s*\)/g, '')
    .replace(/([,;:])(?:\s*[,;:])+/g, '$1')
    .replace(/\b(the|a|an|to|in|of|and|or|for|on|at|from|with)\s+([,.;:!?]|$)/gi, '$2')
    .replace(/\s+([,.;:!?])/g, '$1')
    .trim();
}

function maxCharsFor(c: TranslationContext): number {
  switch (c.outputStyle) {
    case 'concise':
    case 'executive':
      return 400;
    case 'explanatory':
    case 'learning':
      return 1200;
    default:
      return 700;
  }
}

function shorten(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const end = Math.max(
    cut.lastIndexOf('. '),
    cut.lastIndexOf('! '),
    cut.lastIndexOf('? '),
    cut.lastIndexOf('\n'),
  );
  return end > max * 0.4 ? cut.slice(0, end + 1).trim() : `${cut.trimEnd()}…`;
}

/** Simple-mode rewrite of ONE line of prose ('' when the line must be dropped). */
export function simplifyLine(line: string, c: TranslationContext): string {
  let s = scrub(normalizeForLeakCheck(line), c).split(REDACTED).join('a hidden value');
  s = s.replace(/\t/g, ' ').replace(/ {2,}/g, ' ');
  // Markdown decoration.
  s = s
    .replace(/^\s*#{1,6}\s+/, '')
    .replace(/^\s*>\s?/, '')
    .replace(/\*\*|__/g, '')
    .replace(/^\s*[*•]\s+/, '- ')
    .replace(/^\s*(\d+)[.)]\s+/, '$1. ');
  if (!s.trim()) return '';
  // Whole lines that are commands, stack traces or diff hunks are dropped.
  if (leakCheck(s).some((v) => DROP_LINE_KINDS.has(v.kind))) {
    const withoutCode = s.replace(INLINE_CODE_RE, ' ');
    if (leakCheck(withoutCode).some((v) => DROP_LINE_KINDS.has(v.kind))) return '';
  }
  s = s.replace(MD_IMAGE_RE, '');
  s = s.replace(MD_LINK_RE, (_m, text: string) => text);
  s = s.replace(URL_RE, (u) =>
    /localhost|127\.0\.0\.1|\.e2b\.|\.fake\.sandbox|\.internal\b|\.local\b/i.test(u)
      ? 'the preview'
      : '',
  );
  s = s.replace(INLINE_CODE_RE, (_m, inner: string) => {
    const t = inner.trim();
    if (!t) return '';
    if (/[\\/]/.test(t) || new RegExp(`\\.(?:${CODE_EXT})$`, 'i').test(t) || /^\.\w/.test(t)) {
      return areaForPath(t, c);
    }
    return leakCheck(t).some((v) => v.kind === 'command') ? 'some checks' : '';
  });
  s = s.replace(PATH_TOKEN_RE, (tok) => {
    if (FRAMEWORK_RE.test(tok)) return tok;
    const trail = /[.,;:!?)\]]+$/.exec(tok)?.[0] ?? '';
    return `${areaForPath(tok.slice(0, tok.length - trail.length), c)}${trail}`;
  });
  s = s.replace(MARKUP_RE, '');
  s = s.replace(CALL_RE, '');
  s = s.replace(IDENT_RE, '');
  s = s.replace(/=>|===|!==|\+=|::|&&|\|\||[{}]/g, ' ');
  s = s.replace(/;\s*$/, '.');
  s = cleanupSpacing(s);
  if (!/[A-Za-z]{2,}/.test(s) || /^-\s*$/.test(s)) return '';
  // Last line of defence.
  if (leakCheck(s, c.secrets).length) return '';
  return s;
}

/** Simple-mode rewrite of a whole text ('' when nothing usable is left). */
export function simplifyText(
  text: string,
  c: TranslationContext,
  maxChars = maxCharsFor(c),
): string {
  if (!text?.trim()) return '';
  const noFences = scrub(normalizeForLeakCheck(text), c).replace(FENCE_BLOCK_RE, '\n');
  const out: string[] = [];
  for (const raw of noFences.split(/\r?\n/)) {
    const line = simplifyLine(raw, c);
    if (line && out[out.length - 1] !== line) out.push(line);
  }
  const joined = shorten(out.join('\n').trim(), maxChars);
  return leakCheck(joined, c.secrets).length ? '' : joined;
}

const PEM_BEGIN_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const PEM_BEGIN_PREFIX_RE = /-----BEGIN/;
const PEM_END_RE = /-----END [A-Z0-9 ]*PRIVATE KEY-----/;

class SimpleStreamer implements Streamer {
  #buf = '';
  #inFence = false;
  #inPem = false;
  constructor(private readonly c: TranslationContext) {}

  #line(line: string): string {
    // A private key block is dropped whole, like a code fence (its base64 body lines
    // look like harmless words line-by-line).
    if (this.#inPem) {
      if (PEM_END_RE.test(line)) this.#inPem = false;
      return '';
    }
    if (PEM_BEGIN_RE.test(line)) {
      this.#inPem = !PEM_END_RE.test(line);
      return '';
    }
    if (/^\s*(```|~~~)/.test(line)) {
      this.#inFence = !this.#inFence;
      return '';
    }
    if (this.#inFence) return '';
    const s = simplifyLine(line, this.c);
    return s ? `${s}\n` : '';
  }

  push(delta: string): string {
    this.#buf += delta;
    let out = '';
    let i = this.#buf.indexOf('\n');
    while (i >= 0) {
      out += this.#line(this.#buf.slice(0, i));
      this.#buf = this.#buf.slice(i + 1);
      i = this.#buf.indexOf('\n');
    }
    return out;
  }

  flush(): string {
    const rest = this.#buf;
    this.#buf = '';
    return rest ? this.#line(rest) : '';
  }
}

/**
 * Pro: verbatim, scrubbed. Secrets may span whitespace ("Bearer <token>",
 * `password = "…"`) or lines (PEM blocks), so each line is scrubbed as a WHOLE every
 * time and only the new suffix of the scrubbed line is emitted; the trailing partial
 * word is held back. Private key blocks are held until complete and emitted as one
 * redaction marker.
 */
class ProStreamer implements Streamer {
  /** Raw text of the current (incomplete) line. */
  #line = '';
  /** Scrubbed text already emitted for the current line. */
  #emitted = '';
  #inPem = false;
  constructor(private readonly c: TranslationContext) {}

  /** Emit the not-yet-emitted part of scrub(raw); '' when the prefix no longer matches. */
  #suffix(raw: string): string {
    const scrubbed = scrub(raw, this.c);
    if (!scrubbed.startsWith(this.#emitted)) return '';
    const out = scrubbed.slice(this.#emitted.length);
    this.#emitted = scrubbed;
    return out;
  }

  #completeLine(line: string): string {
    if (this.#inPem) {
      const end = PEM_END_RE.exec(line);
      if (!end) return '';
      this.#inPem = false;
      const after = line.slice(end.index + end[0].length);
      this.#emitted = '';
      return `${scrub(after, this.c)}\n`;
    }
    const begin = PEM_BEGIN_RE.exec(line);
    if (begin && !PEM_END_RE.test(line.slice(begin.index))) {
      // Block starts here and continues on later lines.
      const out = `${this.#suffix(line.slice(0, begin.index))}${REDACTED}`;
      this.#inPem = true;
      this.#emitted = '';
      return out;
    }
    const out = `${this.#suffix(line)}\n`;
    this.#emitted = '';
    return out;
  }

  push(delta: string): string {
    this.#line += delta;
    let out = '';
    let i = this.#line.indexOf('\n');
    while (i >= 0) {
      out += this.#completeLine(this.#line.slice(0, i));
      this.#line = this.#line.slice(i + 1);
      i = this.#line.indexOf('\n');
    }
    if (this.#inPem) return out;
    // Partial line: never emit from a (possible) private key header onwards, nor the
    // trailing partial word.
    let ready = this.#line;
    const pem = PEM_BEGIN_PREFIX_RE.exec(ready) ?? /-{1,5}$/.exec(ready);
    if (pem) ready = ready.slice(0, pem.index);
    const ws = Math.max(ready.lastIndexOf(' '), ready.lastIndexOf('\t'));
    if (ws < 0) return out;
    return out + this.#suffix(ready.slice(0, ws + 1));
  }

  flush(): string {
    const rest = this.#line;
    this.#line = '';
    if (this.#inPem) {
      this.#inPem = false;
      this.#emitted = '';
      return '';
    }
    const out = rest ? this.#suffix(rest) : '';
    this.#emitted = '';
    return out;
  }
}

const READ_TOOLS = new Set(['Read', 'Grep', 'Glob', 'LS', 'NotebookRead']);
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);

function inputPath(input: Record<string, unknown>): string | undefined {
  for (const k of ['file_path', 'path', 'notebook_path']) {
    const v = input[k];
    if (typeof v === 'string' && v) return v;
  }
  return undefined;
}

function short(s: string, n = 120): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n - 1)}…` : one;
}

export class RuleBasedTranslator implements Translator {
  assistantText(text: string, mode: Mode, c: TranslationContext): string {
    return mode === 'PRO' ? scrub(text, c) : simplifyText(text, c);
  }

  areas(files: readonly string[], c: TranslationContext): string[] {
    const rel = files
      .map((f) => normalizeWorkspacePath(f, c.workspaceDir))
      .filter((f): f is string => !!f);
    return areasForFiles(rel, c.componentLabels);
  }

  toolStatus(
    tool: { name: string; input: Record<string, unknown> },
    mode: Mode,
    c: TranslationContext,
  ): ToolStatus {
    const { name, input } = tool;
    const path = inputPath(input);
    if (mode === 'PRO') {
      const cmd = typeof input.command === 'string' ? input.command : '';
      const pattern = typeof input.pattern === 'string' ? input.pattern : '';
      let label: string;
      if (READ_TOOLS.has(name))
        label = path ? `${name} ${path}` : pattern ? `${name} "${pattern}"` : name;
      else if (EDIT_TOOLS.has(name)) label = `${name} ${path ?? ''}`.trim();
      else if (name === 'Bash') label = `Running: ${short(cmd)}`;
      else label = `Using ${name}`;
      return {
        state: READ_TOOLS.has(name)
          ? 'reading'
          : EDIT_TOOLS.has(name)
            ? 'editing'
            : name === 'Bash'
              ? 'running'
              : 'thinking',
        label: scrub(short(label, 160), c),
      };
    }
    if (READ_TOOLS.has(name)) return { state: 'reading', label: 'Looking through the project…' };
    if (EDIT_TOOLS.has(name)) {
      const area = path ? areaForPath(path, c) : 'the project';
      return { state: 'editing', label: `Updating ${area}…` };
    }
    if (name === 'Bash') return { state: 'running', label: 'Running checks…' };
    if (name === 'WebFetch' || name === 'WebSearch')
      return { state: 'reading', label: 'Looking something up…' };
    if (name === 'TodoWrite') return { state: 'thinking', label: 'Planning the steps…' };
    if (name === 'Task') return { state: 'thinking', label: 'Working on part of this…' };
    return { state: 'thinking', label: 'Working on it…' };
  }

  toolErrorStatus(mode: Mode, summary: string, c: TranslationContext): ToolStatus {
    return mode === 'PRO'
      ? { state: 'thinking', label: scrub(short(`Tool error: ${summary}`, 160), c) }
      : { state: 'thinking', label: 'Hit a snag, fixing it…' };
  }

  approvalText(
    a: { tool: string; input: Record<string, unknown>; gate?: ApprovalGate | null; reason: string },
    mode: Mode,
    c: TranslationContext,
  ): { summary: string; reason: string } {
    if (mode === 'PRO') {
      const cmd = typeof a.input.command === 'string' ? a.input.command : undefined;
      const path = inputPath(a.input);
      const what = cmd ?? path ?? JSON.stringify(a.input);
      return { summary: scrub(short(`${a.tool}: ${what}`, 200), c), reason: scrub(a.reason, c) };
    }
    const path = inputPath(a.input);
    switch (a.gate) {
      case 'dependencies':
        return {
          summary: 'Add or change a software package the app uses',
          reason: 'Changing the project’s dependencies needs a human OK first.',
        };
      case 'migrations':
        return {
          summary: 'Change how the app stores its data',
          reason: 'Database changes need a human OK first.',
        };
      case 'deletes':
        return {
          summary: path ? `Delete files in ${areaForPath(path, c)}` : 'Delete some files',
          reason: 'Deleting files needs a human OK first.',
        };
      default:
        return {
          summary: path ? `Change ${areaForPath(path, c)}` : 'Run a project command',
          reason: 'This step needs a human OK first.',
        };
    }
  }

  changeSummary(input: ChangeSummaryInput, mode: Mode, c: TranslationContext): string {
    const areas = this.areas(input.files, c);
    if (mode === 'PRO') {
      const text = scrub(input.text.trim(), c);
      if (text) return text;
      if (input.errorCode) return `Turn ended with ${input.errorCode}.`;
      if (input.interrupted) return 'Interrupted.';
      return input.files.length ? `Changed ${input.files.length} file(s).` : 'Done.';
    }
    const text = simplifyText(input.text, c);
    if (input.errorCode && input.errorUserMessage) return input.errorUserMessage;
    if (text && text.length >= 12) return text;
    if (areas.length) {
      const verb = input.interrupted ? 'I started updating' : 'I updated';
      return `${verb} ${joinList(areas)}.`;
    }
    if (input.interrupted) return 'Stopped. Nothing was changed.';
    return text || 'Done — no changes were needed.';
  }

  streamer(mode: Mode, c: TranslationContext): Streamer {
    return mode === 'PRO' ? new ProStreamer(c) : new SimpleStreamer(c);
  }
}

export const defaultTranslator: Translator = new RuleBasedTranslator();
