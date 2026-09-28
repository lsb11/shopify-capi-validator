'use strict';

/**
 * Zero-dependency test runner. Asserts the validator flags the right things
 * on hand-built good/bad payloads. Run with: node test/run.js
 */

const assert = require('assert');
const crypto = require('crypto');
const { validatePayload, normalizeForMeta } = require('../lib/validator');

const sha256 = (s) => crypto.createHash('sha256').update(s.trim().toLowerCase()).digest('hex');
const now = Math.floor(Date.now() / 1000);

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}\n      ${e.message}`); }
}

const levels = (res) => res.events.flatMap((e) => e.findings.map((f) => f.level));
const msgs = (res) => res.events.flatMap((e) => e.findings.map((f) => f.msg));
const hasFail = (res, substr) =>
  res.events.some((e) => e.findings.some((f) => f.level === 'fail' && f.msg.includes(substr)));
const hasLevel = (res, level, substr) =>
  res.events.some((e) => e.findings.some((f) => f.level === level && f.msg.includes(substr)));
const hasPass = (res, substr) =>
  res.events.some((e) => e.findings.some((f) => f.level === 'pass' && f.msg.includes(substr)));

// ── Meta: a fully correct Purchase event ─────────────────────────────────
test('Meta: valid hashed Purchase passes with zero failures', () => {
  const payload = {
    data: [{
      event_name: 'Purchase',
      event_time: now - 60,
      action_source: 'website',
      event_source_url: 'https://shop.example.com/checkout/thank_you',
      event_id: 'order_12345',
      user_data: {
        em: sha256('Buyer@Example.com'),
        ph: sha256('+15551234567'),
        client_ip_address: '203.0.113.5',
        client_user_agent: 'Mozilla/5.0',
        fbp: 'fb.1.1700000000000.AbCdEf',
      },
      custom_data: { value: 49.99, currency: 'USD' },
    }],
  };
  const res = validatePayload(payload);
  assert.strictEqual(res.platform, 'meta', 'should auto-detect meta');
  assert.ok(!levels(res).includes('fail'), 'expected no failures, got: ' + JSON.stringify(msgs(res)));
  assert.ok(hasPass(res, 'em is SHA-256 hashed'));
});

// ── Meta: raw email is caught ────────────────────────────────────────────
test('Meta: RAW email is flagged as failure', () => {
  const payload = { data: [{
    event_name: 'Purchase', event_time: now - 60, action_source: 'website', event_id: 'x',
    user_data: { em: 'buyer@example.com' },
    custom_data: { value: 10, currency: 'USD' },
  }] };
  const res = validatePayload(payload);
  assert.ok(hasFail(res, 'RAW email'), 'should flag raw email');
});

// ── Meta: hashed IP (should be raw) is caught ────────────────────────────
test('Meta: hashed client_ip_address is flagged', () => {
  const payload = { data: [{
    event_name: 'Lead', event_time: now - 60, event_id: 'x',
    user_data: { em: sha256('a@b.com'), client_ip_address: sha256('203.0.113.5') },
  }] };
  const res = validatePayload(payload);
  assert.ok(hasFail(res, 'client_ip_address appears to be hashed'));
});

// ── Meta: milliseconds timestamp is caught ───────────────────────────────
test('Meta: millisecond event_time is flagged', () => {
  const payload = { data: [{
    event_name: 'Purchase', event_time: Date.now(), event_id: 'x',
    user_data: { em: sha256('a@b.com') }, custom_data: { value: 5, currency: 'USD' },
  }] };
  const res = validatePayload(payload);
  assert.ok(hasFail(res, 'event_time looks like milliseconds'));
});

// ── Meta: missing event_id is caught ─────────────────────────────────────
test('Meta: missing event_id is a warning, not a failure (Meta marks it optional)', () => {
  const payload = { data: [{
    event_name: 'Purchase', event_time: now - 60, action_source: 'system_generated',
    user_data: { em: sha256('a@b.com') }, custom_data: { value: 5, currency: 'USD' },
  }] };
  const res = validatePayload(payload);
  assert.ok(!hasFail(res, 'event_id'));
  assert.ok(hasLevel(res, 'warn', 'event_id missing'));
});

// ── Meta: Purchase without currency is caught ────────────────────────────
test('Meta: Purchase missing currency is flagged', () => {
  const payload = { data: [{
    event_name: 'Purchase', event_time: now - 60, event_id: 'x',
    user_data: { em: sha256('a@b.com') }, custom_data: { value: 5 },
  }] };
  const res = validatePayload(payload);
  assert.ok(hasFail(res, 'currency missing'));
});

// ── Meta: no identifier at all is caught ─────────────────────────────────
test('Meta: no customer information parameter is flagged', () => {
  const payload = { data: [{
    event_name: 'PageView', event_time: now - 60, event_id: 'x', user_data: {},
  }] };
  const res = validatePayload(payload);
  assert.ok(hasLevel(res, 'warn', 'no customer information parameter'));
});

test('Meta: missing user_data and action_source fail (both required)', () => {
  const res = validatePayload({ data: [{ event_name: 'Lead', event_time: now - 60, event_id: 'x' }] });
  assert.ok(hasFail(res, 'user_data missing'));
  assert.ok(hasFail(res, 'action_source missing'));
});

test('Meta: website events need event_source_url and client_user_agent', () => {
  const res = validatePayload({ data: [{
    event_name: 'Purchase', event_time: now - 60, action_source: 'website', event_id: 'x',
    user_data: { em: sha256('a@b.com') }, custom_data: { value: 5, currency: 'USD' },
  }] });
  assert.ok(hasFail(res, 'event_source_url missing'));
  assert.ok(hasFail(res, 'client_user_agent missing'));
});

test('Meta: event older than 7 days fails the whole request', () => {
  const res = validatePayload({ data: [{
    event_name: 'Lead', event_time: now - 8 * 24 * 3600, action_source: 'system_generated', event_id: 'x',
    user_data: { em: sha256('a@b.com') },
  }] });
  assert.ok(hasFail(res, 'older than 7 days'));
});

test('Meta: unhashed external_id is a warning (hashing recommended, not required)', () => {
  const res = validatePayload({ data: [{
    event_name: 'Lead', event_time: now - 60, action_source: 'system_generated', event_id: 'x',
    user_data: { em: sha256('a@b.com'), external_id: 'customer-123' },
  }] });
  assert.ok(!hasFail(res, 'external_id'));
  assert.ok(hasLevel(res, 'warn', 'external_id is not hashed'));
});

test('normalizeForMeta follows Meta\'s rules', () => {
  assert.strictEqual(normalizeForMeta('em', '  Buyer@Example.com '), 'buyer@example.com');
  assert.strictEqual(normalizeForMeta('ph', '+1 (650) 555-1212'), '16505551212');
  assert.strictEqual(normalizeForMeta('ct', 'San Francisco'), 'sanfrancisco');
  assert.strictEqual(normalizeForMeta('zp', '94035-1234'), '940351234');
  assert.strictEqual(normalizeForMeta('fn', "O'Brien"), 'obrien');
  assert.strictEqual(normalizeForMeta('country', 'GB'), 'gb');
  assert.throws(() => normalizeForMeta('client_ip_address', '1.2.3.4'));
});

// ── TikTok: valid CompletePayment passes ─────────────────────────────────
test('TikTok: valid hashed CompletePayment passes', () => {
  const payload = {
    event: 'CompletePayment',
    event_time: now - 30,
    event_id: 'evt_1',
    user: { email: sha256('a@b.com'), phone: sha256('+15551234567'), ip: '203.0.113.5', user_agent: 'UA' },
    properties: { value: 25, currency: 'USD' },
  };
  const res = validatePayload(payload, { platform: 'tiktok' });
  assert.strictEqual(res.platform, 'tiktok');
  assert.ok(!levels(res).includes('fail'), 'expected no failures, got: ' + JSON.stringify(msgs(res)));
});

// ── TikTok: raw email caught ─────────────────────────────────────────────
test('TikTok: RAW email is flagged', () => {
  const payload = {
    event: 'CompletePayment', event_time: now - 30, event_id: 'e',
    user: { email: 'a@b.com' }, properties: { value: 1, currency: 'USD' },
  };
  const res = validatePayload(payload);
  assert.strictEqual(res.platform, 'tiktok', 'should auto-detect tiktok from user/event shape');
  assert.ok(hasFail(res, 'RAW email'));
});

// ── auto-detect: meta shape ──────────────────────────────────────────────
test('auto-detect picks meta from user_data', () => {
  const res = validatePayload({ data: [{ event_name: 'X', event_time: now, user_data: { em: sha256('a@b.com') } }] });
  assert.strictEqual(res.platform, 'meta');
});

console.log('');
console.log(`  ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
