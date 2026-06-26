# shopify-capi-validator

Validate **Meta Conversions API (CAPI)** and **TikTok Events API** payloads locally — before you go live.

Meta and TikTok have one infuriating behaviour in common: **they do not tell you when a payload is wrong.** Send a raw (un-hashed) email, a millisecond timestamp, or a `Purchase` with no currency, and the event is simply *never matched* — no error, no warning, just silently missing conversions and a tanking Event Match Quality score. You find out hours later in Events Manager, if at all.

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

No install needed — run it with `npx`. Or add it to a project:

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

**Meta Conversions API**

- `event_name`, `event_time`, `event_id`, `action_source` present
- `event_time` is Unix **seconds** (catches the classic milliseconds mistake) and inside the 7-day window
- `event_id` present — required so the Pixel and CAPI events **deduplicate** instead of double-counting
- `user_data` has at least one strong identifier (`em`, `ph`, `fbc`, or `external_id`)
- PII fields (`em`, `ph`, `fn`, `ln`, `ct`, `st`, `zp`, `country`, `external_id`) are **SHA-256 hashed** (64-char hex) — not raw
- Fields that must stay raw (`client_ip_address`, `client_user_agent`, `fbc`, `fbp`) are **not** accidentally hashed
- `fbc` / `fbp` use the `fb.1.<timestamp>.<value>` format
- `Purchase` events include a numeric `value` and ISO-4217 `currency`

**TikTok Events API**

- `event`, `event_time`, `event_id` present
- `user` has at least one identifier (`email`, `phone`, `ttclid`, `external_id`)
- PII SHA-256 hashed; `ip` / `user_agent` left raw
- `CompletePayment` includes `value` + `currency`

## Use it as a library

```js
const { validatePayload } = require('shopify-capi-validator');

const result = validatePayload(myPayload, { platform: 'meta' });
// → { platform, events: [{ findings: [{ level, msg, hint }] }] }
```

## Why hashing is the #1 issue

A SHA-256 digest is always 64 hexadecimal characters. If a field that Meta
expects hashed doesn't look like that, this tool flags it. Meta's own guidance
is explicit: PII must be lowercased, trimmed, then SHA-256 hashed — and the
platform will *not* warn you if you skip it.

If you're setting up server-side tracking on Shopify and want the full
field-by-field mapping and a free Make.com implementation, there's a complete
walkthrough here: **[Free Shopify server-side tracking (CAPI Shield)](https://stackarchitect.xyz/capi-shield/)**.

## License

MIT © [Stack Architect](https://stackarchitect.xyz/)
