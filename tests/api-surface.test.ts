import {describe, it, expect, beforeAll, beforeEach, afterEach, afterAll} from 'vitest';
import certkit from '../src/presentation/index.js';
import fs from 'node:fs';
import path from 'node:path';
const snapshotPath = path.join(import.meta.dirname, 'api-surface.snapshot.json');
const expected = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));

const MAX_DEPTH = 12;
const seen = new WeakSet();

function walk(value, prefix, depth, out) {
  if (depth > MAX_DEPTH) {
    return;
  }
  if (value === null || value === undefined) {
    out[prefix] = {type: String(value)};
    return;
  }
  const t = typeof value;
  if (t === 'function') {
    out[prefix] = {type: 'function', length: value.length};
    return;
  }
  if (t !== 'object') {
    out[prefix] = {type: t};
    return;
  }
  if (prefix === 'certkit.util.globalScope') {
    out[prefix] = {type: 'object', opaque: true};
    return;
  }
  if (seen.has(value)) {
    out[prefix] = {type: 'object', circular: true};
    return;
  }
  seen.add(value);
  out[prefix] = {type: 'object'};
  const keys = Object.keys(value).sort();
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    try {
      walk(value[key], prefix ? prefix + '.' + key : key, depth + 1, out);
    } catch (err) {
      out[prefix + '.' + key] = {type: 'error', message: String(err.message)};
    }
  }
}

function diffSnapshots(a, b) {
  const added = [];
  const removed = [];
  const changed = [];
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  allKeys.forEach(function(key) {
    if (!(key in a)) {
      added.push(key);
    } else if (!(key in b)) {
      removed.push(key);
    } else if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) {
      changed.push({key, expected: a[key], actual: b[key]});
    }
  });
  return {added, removed, changed};
}

describe('API surface snapshot', function() {
  it('matches the committed snapshot', (ctx) => {
    const actual = {};
    walk(certkit, 'certkit', 0, actual);
    const diff = diffSnapshots(expected, actual);
    if (diff.added.length || diff.removed.length || diff.changed.length) {
      const msg = [];
      if (diff.added.length) {
        msg.push('Added paths: ' + diff.added.slice(0, 20).join(', '));
      }
      if (diff.removed.length) {
        msg.push('Removed paths: ' + diff.removed.slice(0, 20).join(', '));
      }
      if (diff.changed.length) {
        msg.push('Changed paths: ' + diff.changed.slice(0, 10).map(function(c) {
          return c.key;
        }).join(', '));
      }
      expect.fail(msg.join('\n'));
    }
  });
});
