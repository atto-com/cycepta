// Generate Summaries must show how large the local model is: the measured
// safetensors size when the weights are on disk, and the approximate download
// size otherwise. Run with: node --test tests/js/*.test.mjs
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

const localWeightLabel = new Function(
  `${extractFunction(html, 'localWeightLabel')}; return localWeightLabel;`,
)();

test('shows the measured size when the weights are on disk', () => {
  assert.equal(
    localWeightLabel({ available: true, size_human: '3.3 GB' }),
    '3.3 GB on disk',
  );
});

test('falls back to a presence label without a measured size', () => {
  assert.equal(
    localWeightLabel({ available: true, size_human: '' }),
    'weights present',
  );
});

test('shows the approximate download size when weights are absent', () => {
  assert.equal(
    localWeightLabel({ available: false, size_hint: '~3.3 GB' }),
    '~3.3 GB download; not on disk',
  );
});

test('reports missing weights when no hint is configured', () => {
  assert.equal(
    localWeightLabel({ available: false, size_hint: '' }),
    'weights not found',
  );
});

test('handles a missing registry entry', () => {
  assert.equal(localWeightLabel(null), '');
  assert.equal(localWeightLabel(undefined), '');
});
