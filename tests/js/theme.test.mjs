// Extracts the theme helpers from the inline dashboard script and checks the
// three-way mode contract: system follows prefers-color-scheme, while explicit
// light/dark always win. Run with: node --test tests/js/*.test.mjs
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

const normalizeThemeMode = new Function(
  `${extractFunction(html, 'normalizeThemeMode')}; return normalizeThemeMode;`,
)();
const resolveThemeDark = new Function(
  `${extractFunction(html, 'resolveThemeDark')}; return resolveThemeDark;`,
)();

test('defaults missing or unknown stored values to system', () => {
  assert.equal(normalizeThemeMode('system'), 'system');
  assert.equal(normalizeThemeMode(null), 'system');
  assert.equal(normalizeThemeMode(undefined), 'system');
  assert.equal(normalizeThemeMode(''), 'system');
  assert.equal(normalizeThemeMode('sepia'), 'system');
});

test('keeps stored light and dark choices for compatibility', () => {
  assert.equal(normalizeThemeMode('light'), 'light');
  assert.equal(normalizeThemeMode('dark'), 'dark');
});

test('explicit modes ignore the operating-system preference', () => {
  assert.equal(resolveThemeDark('light', true), false);
  assert.equal(resolveThemeDark('light', false), false);
  assert.equal(resolveThemeDark('dark', true), true);
  assert.equal(resolveThemeDark('dark', false), true);
});

test('system mode follows prefers-color-scheme', () => {
  assert.equal(resolveThemeDark('system', true), true);
  assert.equal(resolveThemeDark('system', false), false);
});
