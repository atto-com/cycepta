// Extracts formatLlmText() (and its escHtml() dependency) from the inline
// dashboard script and checks the trusted Markdown subset. Run with:
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
const formatLlmText = extractFunction(html, 'formatLlmText');
const format = new Function(`${escHtml}; ${formatLlmText}; return formatLlmText;`)();

test('renders bold markers as elements', () => {
  assert.equal(format('**Overall picture**'), '<strong>Overall picture</strong>');
  assert.equal(format('text **bold** tail'), 'text <strong>bold</strong> tail');
});

test('renders inline code', () => {
  assert.equal(format('see `CVE-2026-0001`'), 'see <code>CVE-2026-0001</code>');
});

test('escapes markup before formatting', () => {
  assert.equal(format('<img src=x onerror=alert(1)>'),
    '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(format('**<script>alert(1)</script>**'),
    '<strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong>');
});

test('leaves plain text untouched', () => {
  assert.equal(format('no markup here'), 'no markup here');
  assert.equal(format('5 * 3 = 15'), '5 * 3 = 15');
});
