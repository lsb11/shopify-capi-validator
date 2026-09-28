# shopify-capi-validator

[![Shopify iOS Attribution Gap](https://stackarchitect.xyz/api/gap-badge)](https://stackarchitect.xyz/shopify-ios-attribution-gap-benchmark/)
[![npm version](https://img.shields.io/npm/v/shopify-capi-validator)](https://www.npmjs.com/package/shopify-capi-validator)
[![license](https://img.shields.io/npm/l/shopify-capi-validator)](#license)

Validate **Meta Conversions API (CAPI)** and **TikTok Events API** payloads locally, before you go live.

Meta and TikTok have one infuriating behaviour in common: **they do not tell you when a payload is wrong.** Send a raw (un-hashed) email, a millisecond timestamp, or a `Purchase` with no currency, and the event is simply *never matched*. No error, no warning, just silently missing conversions and a tanking Event Match Quality score. You find out hours later in Events Manager, if at all.

This is a zero-dependency CLI that catches those failures in one command.

```bash
npx shopify-capi-validator --payload ./webhook.json
```

```
  Platform: META   Events: 1
  ✓ event_name present (Purchase)
  ✗ event_time looks like milliseconds
      → Meta expects SECONDS (10 digits), not milliseconds (13). Divide by 1000.
  ✓ event_id present (enables Pixel deduplication)
  ✗ user_data.em is RAW email (contains "@")
      → PII must be SHA-256 hashed. Lowercase + trim, THEN hash. Raw values fail matching silently.
  ✓ user_data.client_ip_address sent raw (correct)
  ✗ custom_data.currency missing for Purchase
      → Required. ISO 4217, e.g. "USD", "GBP". Meta rejects Purchase without currency.

  Summary  3 passed  1 warnings  3 failed
```

Exit code is `1` when any check fails, so it drops straight into CI.

## Install

No install needed: run it with `npx`. Or add it to a project:

```bash
npm install --save-dev shopify-capi-validator
```

## Usage

```bash
# from a file
npx shopify-capi-validator --payload ./event.json

# pipe from anywhere (curl, jq, a log line)
cat event.json | npx shopify-capi-validator

# force a platform instead of auto-detecting
npx shopify-capi-validator -p event.json --platform tiktok

# machine-readable output for scripts / CI
npx shopify-capi-validator -p event.json --json
```

| Flag | Description |
|------|-------------|
| `-p`, `--payload <file>` | Path to a JSON payload (or pipe via stdin) |
| `--platform <name>` | `meta` \| `tiktok` \| `auto` (default: auto-detect) |
| `--json` | Output machine-readable JSON |
| `--quiet` | Only show failures + summary |
| `-h`, `--help` | Help |

## What it checks

**Meta Conversions API** (rules checked against Meta's [Conversions API parameter docs](https://developers.facebook.com/documentation/ads-commerce/conversions-api/parameters) on 28 September 2026)

Fails, because Meta requires them:

- `event_name`, `event_time`, `action_source` and `user_data` present on every event
- `event_time` is Unix **seconds** (catches the classic milliseconds mistake) and no more than 7 days old. One old event makes Meta reject the whole request.
- Website events (`action_source: "website"`) include `event_source_url` and `user_data.client_user_agent`
- `em`, `ph`, `fn`, `ln`, `ct`, `st`, `zp` and `country` are **SHA-256 hashed** (64-char hex), not raw
- Fields that must stay raw (`client_ip_address`, `client_user_agent`, `fbc`, `fbp`) are **not** accidentally hashed
- `Purchase` events include `value` and `currency`

Warns, because Meta recommends them or they point to a bug:

- `event_id` missing. Meta marks it optional but recommends it for deduplicating browser Pixel and server events.
- No customer information parameter such as `em` or `ph`
- `external_id` not hashed (Meta recommends hashing it)
- `fbc` / `fbp` not in the `fb.1.<timestamp>.<value>` format, a future `event_time`, a non-numeric `value` or a non-ISO `currency`

It also exports `normalizeForMeta(field, value)`, which applies Meta's formatting rules (lowercase email, digits-only phone, and so on) so you can hash the result.

**TikTok Events API**

- `event`, `event_time`, `event_id` present
- `user` has at least one identifier (`email`, `phone`, `ttclid`, `external_id`)
- PII SHA-256 hashed; `ip` / `user_agent` left raw
- `CompletePayment` includes `value` + `currency`

The TikTok rules have not yet been re-checked against TikTok's current Events API documentation. Treat them as a first pass.

## Use it as a library

```js
const { validatePayload } = require('shopify-capi-validator');

const result = validatePayload(myPayload, { platform: 'meta' });
// → { platform, events: [{ findings: [{ level, msg, hint }] }] }
```

## Why hashing is the #1 issue

A SHA-256 digest is always 64 hexadecimal characters. If a field that Meta
expects hashed doesn't look like that, this tool flags it. Meta's own guidance
is explicit: PII must be lowercased, trimmed, then SHA-256 hashed, and the
platform will *not* warn you if you skip it.

## How much are silent failures costing you?

Payloads that fail matching don't error, they just stop attributing. Stack Architect's iOS attribution gap benchmark tracks what that costs Shopify stores, with sources.

[![Shopify iOS Attribution Gap](https://stackarchitect.xyz/api/gap-badge)](https://stackarchitect.xyz/shopify-ios-attribution-gap-benchmark/)

## Related: free Shopify tracking resources

- **[Shopify server-side tracking setup](https://stackarchitect.xyz/blog/shopify-server-side-tracking-complete-setup-guide/)**: send Shopify orders to Meta, Google and TikTok from the server.
- **[CAPI Shield](https://stackarchitect.xyz/capi-shield/)**: free field-by-field Make.com setup for Meta CAPI, Google Enhanced Conversions & TikTok Events API, no code
- **[iOS Attribution Gap benchmark](https://stackarchitect.xyz/shopify-ios-attribution-gap-benchmark/)**: a sourced benchmark of the Shopify iOS attribution gap
- **[Meta EMQ Score Estimator](https://stackarchitect.xyz/meta-emq-score-estimator/)**: estimate your Event Match Quality before you ship

## License

MIT © [Stack Architect](https://stackarchitect.xyz/)
