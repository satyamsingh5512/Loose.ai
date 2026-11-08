/**
 * Simple-mode leak detection (spec §8.3, §21.6). `leakCheck(text)` lists everything a
 * non-technical viewer must never see: file paths, code fences / inline code, code-like
 * calls or markup, stack traces, shell commands, diff markers, internal URLs and secrets.
 * The Simple-mode translator runs it as a final gate (offending lines are dropped), and
 * the golden tests assert that translated output always passes.
 */
import { SECRET_PATTERNS, scrubSecrets } from '@loose/shared';

export type LeakKind =
  | 'code_fence'
  | 'inline_code'
  | 'path'
  | 'stack_trace'
  | 'command'
  | 'diff'
  | 'internal_url'
  | 'secret'
  | 'code';

export interface LeakViolation {
  kind: LeakKind;
  /** The offending fragment (truncated); for secrets only the pattern name. */
  match: string;
}

const CODE_EXT =
  'tsx?|jsx?|mjs|cjs|css|scss|sass|less|styl|html?|vue|svelte|astro|json|jsonc|ya?ml|toml|ini|md|mdx|py|rb|go|rs|java|kt|kts|swift|php|cs|cpp|cc|c|h|hpp|sql|sh|bash|zsh|ps1|env|lock|lockb|prisma|graphql|gql|xml|txt|csv|cfg|conf|log|map|wasm|ejs|hbs|pug|tf|dockerfile';

/** Framework names that look like file names but are plain English in context. */
const FRAMEWORK_WORDS =
  /\b(?:Node|Next|Nuxt|Vue|React|Express|Three|D3|Chart|Ember|Backbone|Alpine|Solid|Deno|Bun|Socket|Moment|Day|Pixi|Anime|Video|Ext)\.js\b/gi;

export const LEAK_PATTERNS: readonly { kind: LeakKind; re: RegExp }[] = [
  { kind: 'code_fence', re: /```|~~~/ },
  { kind: 'inline_code', re: /`/ },
  // a/b/c.ext, ./x, ../x, /abs/path, ~/x, C:\x
  {
    kind: 'path',
    re: /(?:^|[^\w/.-])(?:\.{1,2}\/|~\/|\/)?(?:[\w@-][\w@.-]*\/)+[\w@.-]*\.[A-Za-z][A-Za-z0-9]{0,9}\b/,
  },
  { kind: 'path', re: /(?:^|[\s("'=:])(?:\.{1,2}\/|~\/)[\w@.-]+/ },
  { kind: 'path', re: /(?:^|[\s("'=:])\/(?:[\w@.-]+\/)+[\w@.-]*/ },
  { kind: 'path', re: /\b[A-Za-z]:\\[\w\\. -]+/ },
  {
    kind: 'path',
    re: /\b(?:src|app|apps|lib|libs|pages|components|public|packages|tests?|scripts|config|styles|server|client|dist|build|node_modules|prisma|migrations|routes|api|utils|hooks|assets)\/[\w@.[\]()-]*/,
  },
  { kind: 'path', re: new RegExp(`(?:^|[^\\w.-])[\\w-]*[\\w]\\.(?:${CODE_EXT})\\b`, 'i') },
  { kind: 'path', re: /(?:^|[^\w])\.(?:env|git|github|vscode|npmrc|eslintrc|prettierrc)[\w.-]*/ },
  { kind: 'stack_trace', re: /^\s*at\s+(?:async\s+)?[\w$.<>[\]]+\s*\(?.*:\d+(?::\d+)?\)?\s*$/m },
  { kind: 'stack_trace', re: /Traceback \(most recent call last\)|File "[^"]+", line \d+/ },
  { kind: 'stack_trace', re: /\b[A-Z]\w*(?:Error|Exception)\b:/ },
  { kind: 'stack_trace', re: /\w:\d+:\d+\b/ },
  { kind: 'stack_trace', re: /\bat line \d+|\bline \d+, column \d+|\(\d+,\d+\)/ },
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)(?:sudo\s+)?(?:npm|npx|yarn|pnpm|pnpx|bun|bunx)\s+(?:-\S+|install|i|ci|add|remove|rm|run|test|exec|dlx|dev|build|start|lint|update|upgrade|audit|init|create|x)\b/i,
  },
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)git\s+(?:-\S+|status|diff|commit|push|pull|checkout|switch|add|reset|log|clone|merge|rebase|stash|fetch|branch|show|restore|rm|mv|tag|cherry-pick|revert|init|remote|config)\b/i,
  },
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)(?:pip3?|pipx|poetry|uv)\s+(?:install|add|remove|uninstall|run|sync)\b/i,
  },
  { kind: 'command', re: /(?:^|\s|\$|>)(?:sudo|chmod|chown|mkdir\s+-|rm\s+-|curl\s+-|wget\s+)\S*/ },
  { kind: 'command', re: /(?:^|\s|\$|>)curl\s+https?:/i },
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)(?:docker|kubectl|make|cargo|go|deno|python3?|node|tsc|vitest|jest|eslint|prettier|prisma|rails|bundle|composer|mvn|gradle)\s+(?:-{1,2}[\w-]+|run|build|test|exec|compose|apply|install|migrate|generate|push|db:\w+|[\w./-]+\.(?:js|ts|py|mjs|cjs))\b/i,
  },
  { kind: 'command', re: /^\s*\$\s+\w/m },
  // Generic POSIX tools followed by a flag, a path-like argument or a FILENAME.
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)(?:ls|cat|cd|grep|rg|cp|mv|rm|touch|find|sed|awk|head|tail|echo|chmod|tar|unzip|ssh|scp|rsync|ps|kill|pkill|which|export|less)\s+-{1,2}[A-Za-z]/,
  },
  {
    kind: 'command',
    re: /(?:^|\s|\$|>)(?:ls|cat|cd|cp|mv|rm|touch|grep|head|tail|sed|awk)\s+(?:[\w~-]*[/.][\w./~-]+|[A-Z][A-Z0-9_]{3,}(?:\.\w+)?\b)/,
  },
  // Raw SQL.
  {
    kind: 'code',
    re: /\b(?:SELECT\s+(?:\*|[\w.,\s]+?)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+(?:TABLE|INDEX|DATABASE|VIEW)|ALTER\s+TABLE|DROP\s+(?:TABLE|DATABASE|INDEX))\b/,
  },
  {
    kind: 'code',
    re: /\bselect\s+\*\s+from\b|\binsert\s+into\s+\w+\s*\(|\bdelete\s+from\s+\w+\s+where\b|\bwhere\s+\w+\s*(?:=|<>|!=)\s*['\d]/i,
  },
  { kind: 'command', re: /\s(?:&&|\|\|)\s|\|\s*(?:sh|bash|grep|xargs|tee)\b|2>&1|>\s*\/dev\/null/ },
  { kind: 'diff', re: /^(?:@@|\+\+\+ |--- a\/|diff --git|index [0-9a-f]{7,})/m },
  { kind: 'diff', re: /^[+-][{}();<>=[\]]|^[+-]\s{2,}\S/m },
  {
    kind: 'internal_url',
    re: /\b(?:https?|wss?):\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[?::1\]?|[\w.-]+\.(?:internal|local|lan|localhost|e2b\.app|e2b\.dev|fake\.sandbox))\b/i,
  },
  { kind: 'internal_url', re: /\blocalhost:\d+|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b/i },
  {
    kind: 'code',
    re: /\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\((?!s\))[^()\s]*(?:\s*,\s*[^()\s]*)*\)/,
  },
  { kind: 'code', re: /=>|===|!==|\+=|::|&&|\|\||;\s*$|^\s*[{}]\s*$/m },
  { kind: 'code', re: /<\/?[A-Za-z][\w.-]*(?:\s[^<>]*)?\/?>/ },
  {
    kind: 'code',
    re: /\b(?:const|let|var|function|import|export|return|class|interface|async|await|def|lambda)\s+[\w${]/,
  },
  {
    kind: 'code',
    re: /\b[a-z]{2,}(?:[A-Z][a-z0-9]+)+\b|\b[a-z]+_[a-z0-9_]+\b|\b[A-Z][A-Z0-9]+_[A-Z0-9_]+\b/,
  },
];

const HTML_ENTITIES: Readonly<Record<string, string>> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  sol: '/',
  bsol: '\\',
  grave: '`',
  colon: ':',
  period: '.',
  lpar: '(',
  rpar: ')',
  lbrace: '{',
  rbrace: '}',
  dollar: '$',
};

/**
 * Undo encodings that would let paths/code/commands slip past the patterns: NFKC
 * (full-width letters, ／), slash look-alikes (∕ ⁄ ⧸ ⟋ …), HTML entities and
 * percent-encoding. Applied before checking AND before Simple-mode rewriting.
 */
export function normalizeForLeakCheck(text: string): string {
  let s = text.normalize('NFKC');
  s = s.replace(/[\u2044\u2215\u29F8\u27CB\u2571\u244A\u1735]/g, '/');
  s = s.replace(/[\u2216\u29F5\u29F9\u27CD\u2572]/g, '\\');
  s = s.replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');
  for (let i = 0; i < 2 && /&(?:#\d+|#x[0-9a-f]+|[a-z]+);/i.test(s); i++) {
    s = s.replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (m, e: string) => {
      if (e[0] === '#') {
        const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1));
        return Number.isFinite(code) && code > 0 && code < 0x110000
          ? String.fromCodePoint(code)
          : m;
      }
      return HTML_ENTITIES[e.toLowerCase()] ?? m;
    });
  }
  for (let i = 0; i < 2 && /%[0-9a-f]{2}/i.test(s); i++) {
    s = s.replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
  }
  return s;
}

function preprocess(text: string): string {
  return normalizeForLeakCheck(text).replace(FRAMEWORK_WORDS, 'framework');
}

/** Violations a Simple-mode viewer must never see. Empty array = safe. */
export function leakCheck(text: string, extraSecrets: readonly string[] = []): LeakViolation[] {
  if (!text) return [];
  const out: LeakViolation[] = [];
  const t = preprocess(text);
  for (const p of LEAK_PATTERNS) {
    const m = p.re.exec(t);
    if (m) out.push({ kind: p.kind, match: m[0].trim().slice(0, 80) });
  }
  for (const p of SECRET_PATTERNS) {
    const hit = (s: string) => {
      p.regex.lastIndex = 0;
      const r = p.regex.test(s);
      p.regex.lastIndex = 0;
      return r;
    };
    if (hit(text) || (t !== text && hit(t))) out.push({ kind: 'secret', match: p.name });
  }
  // Long mixed-case alphanumeric runs (key material, base64 key bodies, hashes).
  const blob = /[A-Za-z0-9+/_=-]{40,}/.exec(t);
  if (blob && /[a-z]/.test(blob[0]) && /[A-Z]/.test(blob[0]) && /\d/.test(blob[0]))
    out.push({ kind: 'secret', match: 'high-entropy' });
  if (extraSecrets.length && scrubSecrets(text, extraSecrets) !== text) {
    // Pattern secrets already counted; this catches exact project values.
    const patternOnly = scrubSecrets(text);
    if (scrubSecrets(text, extraSecrets) !== patternOnly)
      out.push({ kind: 'secret', match: 'project-secret' });
  }
  return out;
}

export function isSimpleSafe(text: string, extraSecrets: readonly string[] = []): boolean {
  return leakCheck(text, extraSecrets).length === 0;
}
