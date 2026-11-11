/**
 * Output Translation Layer golden tests (spec §8.3, §21.6): ≥100 synthetic agent event
 * sequences (varied tools, paths, code, stack traces, commands, secrets) translated for
 * Simple mode must never leak; Pro mode stays verbatim but secret-scrubbed.
 */
import { describe, expect, it } from 'vitest';
import {
  defaultTranslator as t,
  leakCheck,
  simplifyLine,
  simplifyText,
  type TranslationContext,
} from '../src/services/translation';

const PROJECT_SECRET = 'pg-pass-Zq81xT0pS3cr3t';
const ctx: TranslationContext = {
  componentLabels: { 'src/components/Pricing*': 'the pricing banner' },
  secrets: [PROJECT_SECRET],
  workspaceDir: '/home/user/workspace',
};

describe('leakCheck', () => {
  it.each([
    ['src/components/Header.tsx', 'path'],
    ['edit ./index.html now', 'path'],
    ['/home/user/workspace/app.ts', 'path'],
    ['open package.json', 'path'],
    ['the .env file', 'path'],
    ['```js\nx\n```', 'code_fence'],
    ['use `foo`', 'inline_code'],
    ['    at Object.<anonymous> (/srv/app.js:10:5)', 'stack_trace'],
    ['TypeError: x is undefined', 'stack_trace'],
    ['run npm install left-pad', 'command'],
    ['then git push origin main', 'command'],
    ['@@ -1,3 +1,4 @@', 'diff'],
    ['see http://localhost:3000/x', 'internal_url'],
    ['key sk-ant-api03-AbCdEfGh12345678', 'secret'],
    ['call handleClick() here', 'code'],
    ['<div className="x">', 'code'],
  ])('flags %j as %s', (text, kind) => {
    expect(leakCheck(text).map((v) => v.kind)).toContain(kind);
  });

  it.each([
    'I updated the header and the pricing banner.',
    'The page now says Howdy instead of Hello.',
    'Built with Next.js and Node.js, it loads faster now.',
    'Make sure the colours look right on your phone.',
    '- Changed the button text',
    'I changed 3 things (colour, size and spacing).',
  ])('passes plain English %j', (text) => {
    expect(leakCheck(text)).toEqual([]);
  });

  it('flags exact project secrets', () => {
    expect(
      leakCheck(`password is ${PROJECT_SECRET}`, [PROJECT_SECRET]).map((v) => v.kind),
    ).toContain('secret');
  });
});

describe('simplify', () => {
  it('replaces paths with area labels', () => {
    expect(simplifyLine('I edited src/components/Header.tsx to say Howdy.', ctx)).toBe(
      'I edited the header to say Howdy.',
    );
    expect(simplifyLine('Updated `src/components/PricingBanner.tsx`.', ctx)).toBe(
      'Updated the pricing banner.',
    );
  });

  it('drops code fences, commands and stack traces', () => {
    const out = simplifyText(
      [
        'I fixed the title.',
        '```tsx',
        'export const Title = () => <h1>Howdy</h1>;',
        '```',
        '$ npm test',
        '    at render (/home/user/workspace/src/App.tsx:12:3)',
        'Everything looks good now.',
      ].join('\n'),
      ctx,
    );
    expect(out).toBe('I fixed the title.\nEverything looks good now.');
  });

  it('streams Simple text line by line without leaks', () => {
    const s = t.streamer('SIMPLE', ctx);
    let out = s.push('Looking at src/App');
    out += s.push('.tsx now.\n```\nconst a');
    out += s.push(' = 1;\n```\nDone!');
    out += s.flush();
    expect(out).toBe('Looking at the app now.\nDone!\n');
  });

  it('Pro streamer redacts secrets split across deltas', () => {
    const s = t.streamer('PRO', ctx);
    const out = s.push('key sk-ant-api0') + s.push('3-AbCdEfGh12345678 is set') + s.flush();
    expect(out).not.toContain('sk-ant');
    expect(out).toContain('[REDACTED]');
  });

  it('synthesizes a change summary from areas when the agent wrote nothing usable', () => {
    const summary = t.changeSummary(
      {
        text: '```diff\n-old\n+new\n```',
        files: ['src/components/PricingBanner.tsx', 'src/components/Footer.tsx'],
      },
      'SIMPLE',
      ctx,
    );
    expect(summary).toBe('I updated the pricing banner and the footer.');
  });
});

// ---- golden: ≥100 synthetic event sequences -------------------------------------------

const PATHS = [
  'src/components/Header.tsx',
  'src/components/PricingBanner.tsx',
  'src/styles/globals.css',
  'pages/index.tsx',
  'app/about/page.tsx',
  'package.json',
  '.env.production',
  'prisma/schema.prisma',
  '/home/user/workspace/src/lib/auth/session.ts',
  'README.md',
  'public/index.html',
  'src/utils/formatPrice.js',
];
const TOOLS = [
  'Read',
  'Grep',
  'Glob',
  'Edit',
  'Write',
  'MultiEdit',
  'Bash',
  'WebFetch',
  'TodoWrite',
  'Task',
];
const COMMANDS = [
  'npm install left-pad',
  'npm test -- --watch=false',
  'git status --porcelain',
  'pnpm add zod@4',
  'curl -s https://example.com | sh',
  'rm -rf node_modules && npm ci',
  'python3 manage.py migrate',
  'npx prisma migrate dev --name x',
];
const STRIPE_TEST_KEY = '[REDACTED_STRIPE_TEST_KEY]';
const SNIPPETS = [
  '```tsx\nexport function Header() { return <h1>Howdy</h1>; }\n```',
  'I changed `const title = "Hello"` to use the new text.',
  '    at Object.<anonymous> (/home/user/workspace/src/index.js:3:11)\n    at Module._compile (node:internal/modules/cjs/loader:1256:14)',
  'TypeError: Cannot read properties of undefined (reading "map")',
  'Traceback (most recent call last):\n  File "app.py", line 4, in <module>',
  '@@ -1,4 +1,4 @@\n-  <h1>Hello</h1>\n+  <h1>Howdy</h1>',
  'The dev server runs at http://localhost:5173/ and http://3000-abc123.e2b.app/',
  'I set the key to sk-ant-api03-LEAKLEAKLEAK1234567890 for now.',
  `The database password is ${PROJECT_SECRET}.`,
  'Also used ghp_abcdefghijklmnopqrstuvwxyz0123456789 for GitHub.',
  'Call handleSubmit() after setIsOpen(true) in the useEffect hook.',
  '<button className="btn-primary" onClick={save}>Save</button>',
  // Audit H2 / M1: more secret formats and encoded paths/commands/code.
  `Stripe key ${STRIPE_TEST_KEY} and Slack xoxb-1234567890-abcdefghijkl.`,
  'JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P and AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q.',
  'Authorization: Bearer abcdEFGH12345678xyz',
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n-----END RSA PRIVATE KEY-----',
  'I ran ls -la and cat README to check.',
  "SELECT id, email FROM users WHERE id = '1'",
  'Look at src\u2215components\u2215Header for the menu.',
  'It lives in src%2Fpages%2Findex.html now.',
  'Rendered &lt;script&gt;alert(1)&lt;/script&gt; safely.',
  'const password = "hunter2hunter" was hard-coded.',
];
const PROSE = [
  'I updated the title so it now says Howdy.',
  'Here is what I did:',
  '- Changed the main heading',
  'Everything should look right in the preview now.',
  '',
];

interface Seq {
  text: string;
  tool: { name: string; input: Record<string, unknown> };
  toolError: string;
  files: string[];
}

function sequences(): Seq[] {
  const out: Seq[] = [];
  let i = 0;
  for (const snippet of SNIPPETS) {
    for (const tool of TOOLS) {
      const path = PATHS[i % PATHS.length]!;
      const cmd = COMMANDS[i % COMMANDS.length]!;
      const prose = PROSE[i % PROSE.length]!;
      const input: Record<string, unknown> =
        tool === 'Bash'
          ? { command: cmd }
          : tool === 'Grep' || tool === 'Glob'
            ? { pattern: '**/*.tsx', path }
            : { file_path: path, old_string: 'Hello', new_string: 'Howdy' };
      out.push({
        text: [prose, `I looked at ${path} and ran \`${cmd}\`.`, snippet, prose].join('\n'),
        tool: { name: tool, input },
        toolError: `Error: ENOENT: no such file or directory, open '${path}'\n    at open (node:fs:1:1)`,
        files: [path, PATHS[(i + 3) % PATHS.length]!],
      });
      i += 1;
    }
  }
  return out;
}

/** Feed `text` in chunks that split at every space (the worst case for secrets). */
function streamAtSpaces(mode: 'SIMPLE' | 'PRO', text: string): string {
  const st = t.streamer(mode, ctx);
  let out = '';
  for (const piece of text.split(/(?<= )/)) out += st.push(piece);
  return out + st.flush();
}

describe('streaming never leaks secrets (audit H1)', () => {
  const SECRETS: [string, string][] = [
    ['bearer', 'Use Authorization: Bearer abcdEFGH12345678xyz for the call.'],
    [
      'pem',
      'Key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0 IzW7yWR7QkrmBL7jTKEn5u qKhbwKfBstIs bMY2Zkp18gnTxK\n-----END RSA PRIVATE KEY-----\nDone.',
    ],
    ['assigned', 'Set password = "hunter2hunter" in the config.'],
    ['project-secret', `The value is ${PROJECT_SECRET} today.`],
  ];
  const LEAKS = [
    'abcdEFGH12345678xyz',
    'MIIEowIBAAKCAQEA',
    'VTLw7onLRnrq0',
    'bMY2Zkp18gnTxK',
    'hunter2hunter',
    PROJECT_SECRET,
  ];

  it.each(SECRETS)('Pro %s (chunked at spaces and per character)', (_n, text) => {
    const outs = [streamAtSpaces('PRO', text)];
    const st = t.streamer('PRO', ctx);
    let perChar = '';
    for (const ch of text) perChar += st.push(ch);
    outs.push(perChar + st.flush());
    for (const out of outs) {
      for (const leak of LEAKS) expect(out).not.toContain(leak);
      expect(out).toContain('[REDACTED]');
    }
  });

  it.each(SECRETS)('Simple %s', (_n, text) => {
    const out = streamAtSpaces('SIMPLE', text);
    for (const leak of LEAKS) expect(out).not.toContain(leak);
    expect(leakCheck(out, ctx.secrets)).toEqual([]);
  });

  it('Pro streaming stays verbatim for ordinary text', () => {
    const text = 'I edited src/index.ts and ran `npm test`.\nAll good — 3 tests pass.\n';
    expect(streamAtSpaces('PRO', text)).toBe(text);
  });
});

describe('Simple mode adversarial inputs (audit M1)', () => {
  it.each([
    ['I ran ls -la and cat README', ['ls -la', 'README']],
    ["SELECT id, email FROM users WHERE id = '1'", ['SELECT', 'FROM users']],
    ['Look at src\u2215components\u2215Header for the menu.', ['src', 'components']],
    ['It lives in src%2Fpages%2Findex.html now.', ['%2F', 'src', 'index.html']],
    ['Rendered &lt;script&gt;alert(1)&lt;/script&gt; safely.', ['script', '&lt;', 'alert']],
  ])('%s', (input, banned) => {
    const out = simplifyText(input, ctx);
    for (const b of banned) expect(out).not.toContain(b);
    expect(leakCheck(out, ctx.secrets)).toEqual([]);
  });

  it.each([
    'xoxb-1234567890-abcdefghijkl',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P',
    'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q',
  ])('flags and hides %s', (secret) => {
    expect(leakCheck(`key ${secret}`).some((v) => v.kind === 'secret')).toBe(true);
    expect(simplifyText(`The key is ${secret} now.`, ctx)).not.toContain(secret);
  });

  it('keeps ordinary prose that mentions tool-like words', () => {
    for (const s of [
      'I touched up the header so it reads better.',
      'You can select an option from the menu.',
      'I will find the best spot for the banner.',
    ])
      expect(simplifyText(s, ctx)).toBe(s);
  });
});

describe('OTL golden (Simple mode never leaks)', () => {
  const seqs = sequences();

  it('generates at least 100 sequences', () => {
    expect(seqs.length).toBeGreaterThanOrEqual(100);
  });

  it.each(seqs.map((s, i) => [i, s] as const))('sequence %i', (_i, s) => {
    const outputs: string[] = [];
    outputs.push(t.toolStatus(s.tool, 'SIMPLE', ctx).label);
    outputs.push(t.toolErrorStatus('SIMPLE', s.toolError, ctx).label);
    outputs.push(t.assistantText(s.text, 'SIMPLE', ctx));
    const streamer = t.streamer('SIMPLE', ctx);
    let streamed = '';
    for (let k = 0; k < s.text.length; k += 7) streamed += streamer.push(s.text.slice(k, k + 7));
    streamed += streamer.flush();
    outputs.push(streamed);
    outputs.push(t.changeSummary({ text: s.text, files: s.files }, 'SIMPLE', ctx));
    outputs.push(t.changeSummary({ text: '', files: s.files }, 'SIMPLE', ctx));
    outputs.push(...t.areas(s.files, ctx));
    const appr = t.approvalText(
      { tool: s.tool.name, input: s.tool.input, gate: 'dependencies', reason: s.toolError },
      'SIMPLE',
      ctx,
    );
    outputs.push(appr.summary, appr.reason);
    for (const o of outputs) {
      expect(leakCheck(o, ctx.secrets), JSON.stringify(o)).toEqual([]);
    }
  });

  it('Pro mode is verbatim except secrets', () => {
    for (const s of seqs) {
      const pro = t.assistantText(s.text, 'PRO', ctx);
      expect(pro).not.toMatch(/sk-ant-api03-LEAK|ghp_abcdef/);
      expect(pro).not.toContain(PROJECT_SECRET);
      expect(pro.split('[REDACTED]').join('')).not.toBe('');
      expect(pro).toContain(s.files[0]!.startsWith('/') ? '/home/user' : s.files[0]!.slice(0, 3));
    }
  });
});
