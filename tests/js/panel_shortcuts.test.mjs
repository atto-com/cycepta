// Panel keyboard shortcuts: A toggles the left panel, D the right panel.
// The helper must work on any keyboard layout and must not fire while the
// user is typing into a form control. Run with: node --test tests/js/*.test.mjs
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

const panelShortcutSide = new Function(
  `${extractFunction(html, 'panelShortcutSide')}; return panelShortcutSide;`,
)();

function keyEvent(overrides = {}) {
  return {
    code: '',
    key: '',
    ctrlKey: false,
    metaKey: false,
    altKey: false,
    repeat: false,
    target: null,
    ...overrides,
  };
}

test('A toggles the left panel and D the right panel', () => {
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a' })), 'left');
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyD', key: 'd' })), 'right');
});

test('shortcuts follow the physical keys on a non-Latin layout', () => {
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'ф' })), 'left');
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyD', key: 'в' })), 'right');
});

test('key values still work when the browser omits code', () => {
  assert.equal(panelShortcutSide(keyEvent({ key: 'a' })), 'left');
  assert.equal(panelShortcutSide(keyEvent({ key: 'A' })), 'left');
  assert.equal(panelShortcutSide(keyEvent({ key: 'd' })), 'right');
  assert.equal(panelShortcutSide(keyEvent({ key: 'Ф' })), 'left');
  assert.equal(panelShortcutSide(keyEvent({ key: 'В' })), 'right');
});

test('other keys are ignored', () => {
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyS', key: 's' })), '');
  assert.equal(panelShortcutSide(keyEvent({ code: 'Escape', key: 'Escape' })), '');
  assert.equal(panelShortcutSide(null), '');
});

test('modifier chords and key repeat are ignored', () => {
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a', ctrlKey: true })), '');
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a', metaKey: true })), '');
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a', altKey: true })), '');
  assert.equal(panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a', repeat: true })), '');
});

test('typing in form controls and editable content does not toggle panels', () => {
  for (const tagName of ['INPUT', 'TEXTAREA', 'SELECT']) {
    assert.equal(
      panelShortcutSide(keyEvent({ code: 'KeyA', key: 'a', target: { tagName } })),
      '',
    );
  }
  assert.equal(
    panelShortcutSide(keyEvent({ code: 'KeyD', key: 'd', target: { isContentEditable: true } })),
    '',
  );
});

test('index.html wires the helper to the panel state', () => {
  assert.match(
    html,
    /document\.addEventListener\('keydown', \(event\) => \{\s*const side = panelShortcutSide\(event\);/,
  );
  assert.match(
    html,
    /setPanel\(side, !container\.classList\.contains\(side \+ '-collapsed'\)\);/,
  );
});
