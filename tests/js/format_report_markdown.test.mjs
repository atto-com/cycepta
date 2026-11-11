// Extracts formatReportMarkdown() and its escaping helpers from the inline
// dashboard script and checks the trusted report subset. Run with:
// node --test tests/js/*.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const html = readFileSync(
  join(root, 'ThreatDetector/src/ThreatDetector.Api/wwwroot/index.html'),
  'utf8',
);

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name}() is missing from index.html`);

  let depth = 0;
  let opened = false;
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '{') {
      depth += 1;
      opened = true;
    } else if (ch === '}') {
      depth -= 1;
      if (opened && depth === 0) {
        return source.slice(start, i + 1);
      }
    }
  }
  throw new Error(`unbalanced braces in ${name}()`);
}

const escHtml = extractFunction(html, 'escHtml');
const formatInlineEscaped = extractFunction(html, 'formatInlineEscaped');
const formatReportMarkdown = extractFunction(html, 'formatReportMarkdown');
const format = new Function(
  `${escHtml}; ${formatInlineEscaped}; ${formatReportMarkdown}; return formatReportMarkdown;`,
)();

test('renders report headings and metadata paragraphs', () => {
  const out = format(
    '# Security Updates\n\n**Generated:** 2026-11-05 10:00 UTC\n\n' +
    '## Security News (Breaches & Incidents)',
  );
  assert.match(out, /<h1>Security Updates<\/h1>/);
  assert.match(out, /<p><strong>Generated:<\/strong> 2026-11-05 10:00 UTC<\/p>/);
  assert.match(out, /<h2>Security News \(Breaches &amp; Incidents\)<\/h2>/);
});

test('renders numbered items as one ordered list', () => {
  const out = format(
    '## Security Research\n\n1. **CVE-2026-1234** - A flaw. [cisa.gov]\n' +
    '2. **CVE-2026-5678** - Another flaw. [nvd.nist.gov]\n',
  );
  assert.equal(
    out,
    '<h2>Security Research</h2>' +
    '<ol>' +
    '<li><strong>CVE-2026-1234</strong> - A flaw. [cisa.gov]</li>' +
    '<li><strong>CVE-2026-5678</strong> - Another flaw. [nvd.nist.gov]</li>' +
    '</ol>',
  );
});

test('renders horizontal rules between sections', () => {
  assert.match(format('---'), /^<hr>$/);
  assert.match(format('text\n\n---\n\n## Summary'), /<p>text<\/p><hr><h2>Summary<\/h2>/);
});

test('renders the summary table and skips the separator row', () => {
  const out = format(
    '## Summary\n\n| Section | Items | Top item |\n' +
    '| --- | --- | --- |\n' +
    '| News | 11 | Trezor breach |\n' +
    '| Research | 11 | CVE-2026-1234 |\n',
  );
  assert.match(out, /<table>/);
  assert.match(out, /<th>Section<\/th><th>Items<\/th><th>Top item<\/th>/);
  assert.match(out, /<td>News<\/td><td>11<\/td><td>Trezor breach<\/td>/);
  assert.equal((out.match(/<tr>/g) || []).length, 3);
});

test('escapes raw markup before rendering', () => {
  const out = format(
    '# Security Updates\n\n1. **<script>alert(1)</script>** - <img src=x onerror=alert(1)>',
  );
  assert.ok(!out.includes('<script>'));
  assert.ok(!out.includes('<img'));
  assert.match(out, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('renders inline code inside items', () => {
  assert.match(
    format('1. Patch `CVE-2026-1234` now.'),
    /<li>Patch <code>CVE-2026-1234<\/code> now\.<\/li>/,
  );
});

test('keeps escaped pipes inside table cells', () => {
  const out = format('| Section | Top item |\n| --- | --- |\n| News | A \\| B |');
  assert.match(out, /<td>A \| B<\/td>/);
});
