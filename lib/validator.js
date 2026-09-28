'use strict';

/**
 * Validation rules for Meta Conversions API and TikTok Events API payloads.
 *
 * Meta rules follow Meta's Conversions API parameter documentation (server
 * event, customer information and custom data parameters), checked
 * 28 September 2026. TikTok rules have not yet been re-checked against
 * TikTok's current Events API documentation. The most common
 * silent failure these platforms have is that they DO NOT warn you when PII
 * is sent unhashed: the event is simply never matched. This validator exists
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
      out.push(err('event_time is older than 7 days',
        'Meta returns an error for the whole request and processes none of its events if any event_time is more than 7 days old.'));
    } else if (ageSec < -3600) {
      out.push(warn('event_time is in the future',
        'Meta\'s docs set no rule for future times, but a future timestamp usually means a timezone or milliseconds bug.'));
    } else {
      out.push(ok('event_time valid (Unix seconds, within window)'));
    }
  }

  // action_source: required by Meta on every event.
  if (!event.action_source) {
    out.push(err('action_source missing', 'Required by Meta. Use "website" for purchases on your site.'));
  } else {
    out.push(ok(`action_source present (${event.action_source})`));
  }

  // event_id: optional per Meta, but recommended for deduplication.
  if (!event.event_id) {
    out.push(warn('event_id missing',
      'Meta marks it optional but recommends it for deduplicating browser Pixel and server events. Send the same event_id from both.'));
  } else {
    out.push(ok('event_id present (enables Pixel deduplication)'));
  }

  const website = event.action_source === 'website';

  // event_source_url: required for website events.
  if (website && !event.event_source_url) {
    out.push(err('event_source_url missing', 'Required by Meta for website events: the URL of the page where the event happened.'));
  } else if (website) {
    out.push(ok('event_source_url present'));
  }

  // ── user_data ───────────────────────────────────────────────────────────
  if (event.user_data == null) {
    out.push(err('user_data missing', 'Required by Meta on every event: the customer information used for matching.'));
  }
  const u = event.user_data || {};
  const hashedFields = ['em', 'ph', 'fn', 'ln', 'ct', 'st', 'zp', 'country'];
  const rawFields = ['client_ip_address', 'client_user_agent', 'fbc', 'fbp'];

  // Meta: "You must provide at least one of the following user_data parameters".
  const hasCustomerInfo = hashedFields.some((f) => u[f] != null);
  if (!hasCustomerInfo) {
    out.push(warn('no customer information parameter in user_data',
      'Meta requires at least one correctly formatted customer information parameter, such as em (email) or ph (phone).'));
  } else {
    out.push(ok('user_data has at least one customer information parameter'));
  }

  // client_user_agent: required for website events.
  if (website && !u.client_user_agent) {
    out.push(err('user_data.client_user_agent missing', 'Required by Meta for website events. Send the browser user agent, unhashed.'));
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

  // external_id: Meta recommends hashing it but does not require it.
  if (u.external_id != null) {
    const vals = Array.isArray(u.external_id) ? u.external_id : [u.external_id];
    if (vals.every(looksHashed)) out.push(ok('user_data.external_id is SHA-256 hashed'));
    else out.push(warn('user_data.external_id is not hashed', 'Meta recommends hashing external_id with SHA-256. It is not required.'));
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

/**
 * Normalise a value the way Meta asks before hashing (customer information
 * parameters). Hash the result with SHA-256 yourself.
 *   normalizeForMeta('em', '  Buyer@Example.com ') -> 'buyer@example.com'
 *   normalizeForMeta('ph', '+1 (650) 555-1212')    -> '16505551212'
 * Phone: Meta asks you to remove symbols, letters and leading zeros and to
 * include the country code. This cannot add a missing country code, or drop
 * a national trunk zero written after it, as in "+44 (0)7700...": fix those first.
 * Zip: Meta asks for only the first 5 digits of US zip codes; this does not
 * know the country, so trim US zips yourself.
 */
function normalizeForMeta(field, value) {
  let v = String(value).trim();
  switch (field) {
    case 'em': return v.toLowerCase();
    case 'ph': return v.replace(/[^0-9]/g, '').replace(/^0+/, '');
    case 'fn':
    case 'ln': return v.toLowerCase().replace(/[\p{P}]/gu, '');
    case 'ct': return v.toLowerCase().replace(/[\p{P}\p{S}\s]/gu, '');
    case 'st': return v.toLowerCase().replace(/[\p{P}\p{S}\s]/gu, '');
    case 'zp': return v.toLowerCase().replace(/[\s-]/g, '');
    case 'country': return v.toLowerCase();
    default: throw new Error(`No Meta normalisation rule for "${field}"`);
  }
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

module.exports = { validatePayload, validateMetaEvent, validateTikTokEvent, looksHashed, normalizeForMeta, SHA256_RE };
