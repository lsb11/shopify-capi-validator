'use strict';

/**
 * Validation rules for Meta Conversions API and TikTok Events API payloads.
 *
 * Every rule here is derived from the official platform specifications
 * (Meta Conversions API parameters, TikTok Events API 2.0). The most common
 * silent failure these platforms have is that they DO NOT warn you when PII
 * is sent unhashed — the event is simply never matched. This validator exists
 * to catch those failures locally, before you waste hours in Events Manager.
 *
 * Reference: https://stackarchitect.xyz/capi-shield/
 */

const SHA256_RE = /^[a-f0-9]{64}$/;          // a SHA-256 hex digest is exactly 64 lowercase hex chars
const E164_RE = /^\+?[1-9]\d{6,14}$/;        // E.164 phone (pre-hash sanity, only when raw)
const FBP_FBC_RE = /^fb\.\d\.\d{13}\./;      // fb.1.<13-digit-ts>.<value>

const ok = (msg) => ({ level: 'pass', msg });
const warn = (msg, hint) => ({ level: 'warn', msg, hint });
const err = (msg, hint) => ({ level: 'fail', msg, hint });

/** True if a value looks like a SHA-256 digest. */
function looksHashed(v) {
  return typeof v === 'string' && SHA256_RE.test(v.trim());
}

/** True if a value looks like raw (un-hashed) text where a hash was expected. */
function looksRaw(v) {
  if (typeof v !== 'string') return true;
  return !SHA256_RE.test(v.trim());
}

/**
 * Validate a single Meta CAPI event object (one element of the `data` array,
 * or a bare event object).
 * Returns an array of { level, msg, hint } findings.
 */
function validateMetaEvent(event) {
  const out = [];

  // ── Required top-level fields ───────────────────────────────────────────
  if (!event.event_name) {
    out.push(err('event_name missing', 'Required. e.g. "Purchase", "AddToCart", "Lead".'));
  } else {
    out.push(ok(`event_name present (${event.event_name})`));
  }

  // event_time: must be Unix SECONDS, within the last 7 days and not in the future.
  if (event.event_time == null) {
    out.push(err('event_time missing', 'Required. Unix timestamp in SECONDS (UTC).'));
  } else if (typeof event.event_time !== 'number') {
    out.push(err('event_time is not a number', 'Must be an integer Unix timestamp in seconds, not a string or ISO date.'));
  } else if (String(event.event_time).length === 13) {
    out.push(err('event_time looks like milliseconds', 'Meta expects SECONDS (10 digits), not milliseconds (13). Divide by 1000.'));
  } else {
    const now = Math.floor(Date.now() / 1000);
    const ageSec = now - event.event_time;
    if (ageSec > 7 * 24 * 3600) {
      out.push(err('event_time is older than 7 days', 'Meta rejects events older than 7 days. This event will be dropped silently.'));
    } else if (ageSec < -3600) {
      out.push(err('event_time is in the future', 'Events more than ~1h in the future are rejected. Check server timezone / ms-vs-s.'));
    } else {
      out.push(ok('event_time valid (Unix seconds, within window)'));
    }
  }

  // action_source: required for web events.
  if (!event.action_source) {
    out.push(warn('action_source missing', 'Recommended. Use "website" for web purchases, "system_generated" for offline.'));
  } else {
    out.push(ok(`action_source present (${event.action_source})`));
  }

  // event_id: required for Pixel<->CAPI deduplication.
  if (!event.event_id) {
    out.push(err('event_id missing', 'Required for deduplication. Must match the browser Pixel event_id, or Meta double-counts.'));
  } else {
    out.push(ok('event_id present (enables Pixel deduplication)'));
  }

  // ── user_data ───────────────────────────────────────────────────────────
  const u = event.user_data || {};
  const hashedFields = ['em', 'ph', 'fn', 'ln', 'ct', 'st', 'zp', 'country', 'external_id'];
  const rawFields = ['client_ip_address', 'client_user_agent', 'fbc', 'fbp'];

  // At least one strong identifier required.
  const hasIdentifier = Boolean(u.em || u.ph || u.fbc || u.external_id);
  if (!hasIdentifier) {
    out.push(err('no customer identifier in user_data',
      'At least one of em (email), ph (phone), fbc, or external_id is required for matching.'));
  } else {
    out.push(ok('user_data has at least one customer identifier'));
  }

  // PII fields that MUST be hashed.
  for (const f of hashedFields) {
    if (u[f] == null) continue;
    const vals = Array.isArray(u[f]) ? u[f] : [u[f]];
    for (const v of vals) {
      if (looksHashed(v)) {
        out.push(ok(`user_data.${f} is SHA-256 hashed`));
      } else if (typeof v === 'string' && v.includes('@')) {
        out.push(err(`user_data.${f} is RAW email (contains "@")`,
          'PII must be SHA-256 hashed. Lowercase + trim, THEN hash. Raw values fail matching silently.'));
      } else {
        out.push(err(`user_data.${f} is not SHA-256 hashed`,
          `Expected a 64-char hex digest. Got "${truncate(String(v))}". Hash it with SHA-256 before sending.`));
      }
    }
  }

  // Fields that must NOT be hashed.
  for (const f of rawFields) {
    if (u[f] == null) continue;
    if (looksHashed(u[f])) {
      out.push(err(`user_data.${f} appears to be hashed`,
        `${f} must be sent RAW. Hashing it breaks matching. Send the plain value.`));
    } else {
      out.push(ok(`user_data.${f} sent raw (correct)`));
    }
  }

  // fbc / fbp format check.
  for (const f of ['fbc', 'fbp']) {
    if (typeof u[f] === 'string' && !FBP_FBC_RE.test(u[f])) {
      out.push(warn(`user_data.${f} has unexpected format`,
        'Should start with "fb.1." followed by a 13-digit timestamp, e.g. fb.1.1700000000000.AbCd.'));
    }
  }

  // ── custom_data (Purchase needs value + currency) ───────────────────────
  const c = event.custom_data || {};
  if (event.event_name === 'Purchase') {
    if (c.value == null) {
      out.push(err('custom_data.value missing for Purchase', 'Purchase events require a numeric value.'));
    } else if (typeof c.value !== 'number') {
      out.push(warn('custom_data.value is not a number', `Got "${truncate(String(c.value))}". Send a numeric value, not a string.`));
    } else {
      out.push(ok(`custom_data.value present (${c.value})`));
    }
    if (!c.currency) {
      out.push(err('custom_data.currency missing for Purchase', 'Required. ISO 4217, e.g. "USD", "GBP". Meta rejects Purchase without currency.'));
    } else if (!/^[A-Za-z]{3}$/.test(c.currency)) {
      out.push(warn('custom_data.currency not ISO 4217', `Got "${c.currency}". Use a 3-letter code like USD or GBP.`));
    } else {
      out.push(ok(`custom_data.currency present (${c.currency})`));
    }
  }

  return out;
}

/**
 * Validate a single TikTok Events API event.
 */
function validateTikTokEvent(event) {
  const out = [];

  if (!event.event) {
    out.push(err('event missing', 'Required. e.g. "CompletePayment", "AddToCart".'));
  } else {
    out.push(ok(`event present (${event.event})`));
  }

  if (event.event_time == null) {
    out.push(err('event_time missing', 'Required. Unix timestamp in seconds.'));
  } else if (String(event.event_time).length === 13) {
    out.push(err('event_time looks like milliseconds', 'TikTok expects seconds (10 digits), not milliseconds.'));
  } else {
    out.push(ok('event_time present'));
  }

  if (!event.event_id) {
    out.push(warn('event_id missing', 'Recommended for Pixel deduplication; match the browser Pixel event_id.'));
  } else {
    out.push(ok('event_id present (enables deduplication)'));
  }

  const u = event.user || {};
  const hasId = Boolean(u.email || u.phone || u.ttclid || u.external_id);
  if (!hasId) {
    out.push(err('no identifier in user', 'At least one of email, phone, ttclid, or external_id required.'));
  } else {
    out.push(ok('user has at least one identifier'));
  }

  // TikTok also requires SHA-256 on email/phone/external_id.
  for (const f of ['email', 'phone', 'external_id']) {
    if (u[f] == null) continue;
    if (looksHashed(u[f])) {
      out.push(ok(`user.${f} is SHA-256 hashed`));
    } else if (typeof u[f] === 'string' && u[f].includes('@')) {
      out.push(err(`user.${f} is RAW email`, 'TikTok requires SHA-256 hashed PII. Lowercase + trim, then hash.'));
    } else {
      out.push(err(`user.${f} is not SHA-256 hashed`, `Expected 64-char hex digest. Got "${truncate(String(u[f]))}".`));
    }
  }

  // IP / user agent must be raw.
  for (const f of ['ip', 'user_agent']) {
    if (u[f] != null && looksHashed(u[f])) {
      out.push(err(`user.${f} appears hashed`, `${f} must be sent raw; TikTok hashes server-side.`));
    }
  }

  const p = event.properties || {};
  if (event.event === 'CompletePayment') {
    if (p.value == null) out.push(err('properties.value missing for CompletePayment', 'Required numeric value.'));
    else out.push(ok(`properties.value present (${p.value})`));
    if (!p.currency) out.push(err('properties.currency missing', 'Required. ISO 4217, e.g. USD.'));
    else out.push(ok(`properties.currency present (${p.currency})`));
  }

  return out;
}

function truncate(s, n = 24) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/**
 * Top-level: detect platform + shape, run the right validator across all events.
 * @param {object} payload  parsed JSON
 * @param {object} opts     { platform: 'meta' | 'tiktok' | 'auto' }
 * @returns {{ platform: string, events: Array<{ findings: object[] }> }}
 */
function validatePayload(payload, opts = {}) {
  let platform = opts.platform || 'auto';

  // Auto-detect.
  if (platform === 'auto') {
    const probe = Array.isArray(payload?.data) ? payload.data[0]
      : Array.isArray(payload) ? payload[0] : payload;
    if (probe && (probe.user_data || probe.event_name)) platform = 'meta';
    else if (probe && (probe.user || probe.event)) platform = 'tiktok';
    else platform = 'meta'; // default
  }

  // Normalize to an array of events.
  let events;
  if (Array.isArray(payload?.data)) events = payload.data;        // Meta: { data: [...] }
  else if (Array.isArray(payload?.events)) events = payload.events; // some wrappers
  else if (Array.isArray(payload)) events = payload;
  else events = [payload];

  const runner = platform === 'tiktok' ? validateTikTokEvent : validateMetaEvent;
  return {
    platform,
    events: events.map((e) => ({ findings: runner(e) })),
  };
}

module.exports = { validatePayload, validateMetaEvent, validateTikTokEvent, looksHashed, SHA256_RE };
