// Extracts safeUrl() from the inline dashboard script and checks that only
// http(s) URLs can reach an href. Run with: node --test tests/js/*.test.mjs
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

const body = extractFunction(html, 'safeUrl');
const fakeWindow = { location: { origin: 'http://localhost:5001' } };
const safeUrl = new Function('window', `${body}; return safeUrl;`)(fakeWindow);

test('keeps absolute http(s) urls', () => {
  assert.equal(safeUrl('https://example.test/advisory'), 'https://example.test/advisory');
  assert.equal(safeUrl('http://example.test/'), 'http://example.test/');
});

test('rejects relative source urls instead of pointing at the dashboard', () => {
  assert.equal(safeUrl('/api/v1/health'), '');
  assert.equal(safeUrl('CVE-2026-119264'), '');
  assert.equal(safeUrl('//example.test/advisory'), '');
});

test('rejects executable and data urls', () => {
  assert.equal(safeUrl('javascript:alert(1)'), '');
  assert.equal(safeUrl(' JaVaScRiPt:alert(1) '), '');
  assert.equal(safeUrl('data:text/html,<script>alert(1)</script>'), '');
  assert.equal(safeUrl('vbscript:msgbox(1)'), '');
});

test('rejects empty input instead of returning the page origin', () => {
  assert.equal(safeUrl(''), '');
  assert.equal(safeUrl(null), '');
  assert.equal(safeUrl(undefined), '');
});
